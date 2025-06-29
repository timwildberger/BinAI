import angr
from intervaltree import Interval, IntervalTree

class AddressMetaDataLookup:
    def __init__(self, path):
        self.project = angr.Project(path, auto_load_libs=True)
        # Define code-related sections to include in CFG
        self._code_regions = []
        for section in self.project.loader.main_object.sections:
            if section.name in (".text", ".plt", ".init", ".fini", ".plt.sec"):
                self._code_regions.append((section.vaddr, section.vaddr + section.memsize))
        self.cfg = self.project.analyses.CFGFast(normalize=True, regions=self._code_regions)

        self.exact_lookup = {}
        self.range_lookup = IntervalTree()
        self.library_ranges = self._build_library_ranges()
        self._build_indices()

    def _build_library_ranges(self):
        """
        Builds a list of tuples: (start_addr, end_addr, library_name)
        for all loaded binaries (main executable + libraries).
        """
        lib_ranges = []
        for binary in self.project.loader.all_objects:
            start = binary.min_addr
            end = binary.max_addr + 1  # exclusive end
            lib_name = getattr(binary, "provides", None)
            if lib_name is None:
                # fallback to filename or unknown
                lib_name = getattr(binary, "filename", None) or "unknown"
            lib_ranges.append((start, end, lib_name))
        return lib_ranges

    def _find_library_for_addr(self, addr):
        for start, end, lib_name in self.library_ranges:
            if start <= addr < end:
                return lib_name
        return "unknown"

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
                    continue  # skip empty sections
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
            pass  # stripped binary fallback

        # -- Functions (range) with local vs library classification
        try:
            for func in self.cfg.kb.functions.values():
                if func.size == 0:
                    continue

                library = self._find_library_for_addr(func.addr)

                if func.binary == main_obj:
                    func_type = 'local_function'
                    source = 'function'
                elif func.is_simprocedure or func.is_plt:
                    func_type = 'library_function'
                    source = 'library'
                else:
                    func_type = 'local_function'
                    source = 'function'

                meta = {
                    'name': func.name,
                    'type': func_type,
                    'size': func.size,
                    'source': source,
                    'library': library
                }

                self.range_lookup[func.addr:func.addr + func.size] = meta
        except Exception:
            pass

        # -- bss in stripped binaries
        try:
            for seg in self.project.loader.main_object.segments:
                if seg.memsize > seg.filesize:  # bss usually has memsize > filesize
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
