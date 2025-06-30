import lief
from collections import defaultdict

class BinaryParser:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.binary = lief.parse(binary_path)
        self.address_map = defaultdict(list)
        self.parse_binary()
    
    def parse_binary(self):
        """
        Parse the binary to gather all section data.
        """
        # Parse each section of the binary
        for section in self.binary.sections:
            if section.name == ".text":
                self._parse_text_section(section)
            elif section.name == ".data":
                self._parse_data_section(section)
            elif section.name == ".rodata":
                self._parse_rodata_section(section)
            elif section.name == ".plt":
                self._parse_plt_section(section)
            else:
                self._parse_other_section(section)
    
    def _parse_text_section(self, section):
        """
        Parse .text section to map function and block addresses.
        """
        print(f"Parsing .text section: {section.name}")
        
        # Loop over the content of the .text section (functions and blocks)
        for i in range(0, len(section.content), 16):  # assuming 16 bytes per block for simplicity
            block = section.content[i:i + 16]
            start_address = section.virtual_address + i
            
            # Store the block address
            self.address_map[start_address].append({
                "type": "block",
                "section": ".text",
                "content": block
            })
        
        # Store functions in the .text section (e.g., use function entries, if available)
        for func in self.binary.functions:
            if section.virtual_address <= func.address < (section.virtual_address + len(section.content)):
                self.address_map[func.address].append({
                    "type": "function",
                    "section": ".text",
                    "name": func.name
                })
    
    def _parse_data_section(self, section):
        """
        Parse .data section to map data entries.
        """
        print(f"Parsing .data section: {section.name}")
        
        # Loop through the section content and treat it as raw data
        for i in range(0, len(section.content), 4):  # Assuming 4 bytes per data entry (adjust if needed)
            data = section.content[i:i + 4]
            start_address = section.virtual_address + i
            
            # Store the data entry with its address
            self.address_map[start_address].append({
                "type": "data",
                "section": ".data",
                "content": data
            })
    
    def _parse_rodata_section(self, section):
        """
        Parse .rodata section to map read-only data.
        """
        print(f"Parsing .rodata section: {section.name}")
        
        # Treat the read-only data as raw content
        for i in range(0, len(section.content), 8):  # Assuming 8 bytes per entry
            entry = section.content[i:i + 8]
            start_address = section.virtual_address + i
            
            # Store read-only data entry with its address
            self.address_map[start_address].append({
                "type": "rodata",
                "section": ".rodata",
                "content": entry
            })
    
    def _parse_plt_section(self, section):
        """
        Parse .plt section to map PLT entries (function pointers).
        """
        print(f"Parsing .plt section: {section.name}")
        
        # PLT entries are typically a fixed-size (4 or 8 bytes depending on architecture)
        plt_entry_size = 4  # Assume 32-bit; use 8 bytes for 64-bit architectures.
        
        # Iterate through each entry in the .plt section
        for i in range(0, len(section.content), plt_entry_size):
            entry = section.content[i:i + plt_entry_size]
            start_address = section.virtual_address + i
            
            # Add the entry to the address map
            self.address_map[start_address].append({
                "type": "plt",
                "section": ".plt",
                "entry": entry,
                "resolved_address": int.from_bytes(entry, "little")  # Assuming little-endian format
            })
    
    def _parse_other_section(self, section):
        """
        Parse any other section and store it.
        """
        print(f"Parsing unknown section: {section.name}")
        
        # Loop through the section content and store all addresses
        for i in range(0, len(section.content), 8):  # Adjust the size for other sections
            entry = section.content[i:i + 8]
            start_address = section.virtual_address + i
            
            # Add the entry to the address map
            self.address_map[start_address].append({
                "type": "unknown",
                "section": section.name,
                "content": entry
            })
    
    def get_metadata(self, address):
        """
        Retrieve metadata for a given address.
        """
        return self.address_map.get(address, None)

def main(binary_path, address):
    parser = BinaryParser(binary_path)
    metadata = parser.get_metadata(address)
    if metadata:
        print(f"Metadata for address {hex(address)}: {metadata}")
    else:
        print(f"No metadata found for address {hex(address)}.")

# Example usage:
if __name__ == "__main__":
    #binary_path = "src/curl/x86-clang-3.5-O0_curl"
    #parser = BinaryParser(binary_path)
    
    # Look up a given address in the binary
    #address_to_lookup = 0x08048400  # Example address
    #metadata = parser.get_metadata(address_to_lookup)
    
    if metadata:
        print(f"Metadata for address {hex(address_to_lookup)}: {metadata}")
    else:
        print(f"No metadata found for address {hex(address_to_lookup)}.")
