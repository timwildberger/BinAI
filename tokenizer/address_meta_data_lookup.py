import angr
from intervaltree import Interval, IntervalTree

class AddressMetaDataLookup:
    def __init__(self, project, cfg, auto_load_libs=False):
        self.project = project
        self.cfg = cfg
        self.exact_lookup = {}
        self.range_lookup = IntervalTree()
        self._build_indices()

    def _get_section_type(self, section):
        name = section.name or ""
        if name in {'.init', '.fini', '.plt'}:
            return 'code'
        elif name == ".bss":
            return 'bss'
        elif section.is_executable:
            return 'code'
        elif section.is_writable:
            return 'data'
        else:
            return 'rodata'

    def _build_indices(self):
        loader = self.project.loader
        main_obj = loader.main_object

        # -- Sections (if present)
        try:
            for section in main_obj.sections:
                if section.memsize == 0:
                    continue # skip empty sections
                meta = {
                    'name': section.name,
                    'type': self._get_section_type(section),
                    'binary': section.binary,
                    'permissions': {
                        'r': section.is_readable,
                        'w': section.is_writable,
                        'x': section.is_executable,
                    },
                    'size': section.memsize,
                    'source': 'section'
                }
                self.range_lookup[section.vaddr:section.vaddr + section.memsize] = meta
        except Exception:
            # some stripped binaries might not expose sections cleanly
            pass

        # -- Symbols (exact)
        try:
            for sym in self.project.kb.symbols:
                if sym.rebased_addr is None:
                    continue
                self.exact_lookup[sym.rebased_addr] = {
                    'name': sym.name,
                    'type': 'symbol',
                    'binding': sym.binding,
                    'size': sym.size,
                    'source': 'symbol'
                }
        except Exception:
            pass # stripped binary fallback

        # -- Functions (range)
        try:
            for func in self.cfg.kb.functions.values():
                if func.size == 0:
                    continue
                self.range_lookup[func.addr:func.addr + func.size] = {
                    'name': func.name,
                    'type': 'function',
                    'size': func.size,
                    'source': 'function'
                }
        except Exception:
            pass

            
        # -- bass in stripped binaries
        try:
            for seg in self.project.loader.main_object.segments:
                if seg.memsize > seg.filesize: # bass usually has memsize > filesize
                    bss_vaddr = seg.vaddr + seg.filesize
                    bss_size = seg.memsize - seg.filesize
                    meta = {
                        'name': '.bss',
                        'type': 'bss',
                        'size': bss_size,
                        'source': 'segment-inferred'
                    }
                self.range_lookup[bss_vaddr:bss_vaddr + bss_size] = meta
        except Exception:
            pass    
    
    def lookup(self, addr) -> tuple[dict | None, str]:
        """
        Returns a tuple: (metadata_dict, source-type)
        source_type is one of 'exact', 'range', 'miss'
        """
        if addr in self.exact_lookup:
            return self.exact_lookup[addr], 'exact'
        
        matches = self.range_lookup[addr]
        if matches:
            interval = list(matches)[0]
            meta = interval.data.copy()
            meta['start_addr'] = interval.begin
            meta['end_addr'] = interval.end  # Optional, but useful
            return meta, 'range'

        return None, 'miss'