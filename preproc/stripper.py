import os, sys
import lief

def strip_debug(binary):
    """Remove debug sections."""
    to_remove = [".debug_info", ".debug_line", ".debug_str", ".debug_abbrev", ".debug_frame"]
    for section in to_remove:
        sec = binary.get_section(section)
        if sec:
            binary.remove_section(sec.name)
    return binary

def strip_symbols(binary):
    """Remove symbol and string tables."""
    to_remove = [".symtab", ".strtab", ".shstrtab"]
    for section in to_remove:
        sec = binary.get_section(section)
        if sec:
            binary.remove_section(sec.name)
    return binary

def strip_metadata(binary):
    """Remove comment and metadata sections."""
    to_remove = [".comment", ".note", ".interp", ".hash", ".gnu.hash"]
    for section in to_remove:
        sec = binary.get_section(section)
        if sec:
            binary.remove_section(sec.name)
    return binary

def process_binaries(file_list):
    """Process a list of binaries and generate various stripped versions."""
    for binary_path in file_list:
        # Load the binary using lief
        binary = lief.parse(binary_path)
        
        # Create different versions by stripping sections progressively
        base_filename = os.path.basename(binary_path)
        file_dir = os.path.dirname(binary_path)

        # Stage 1: Original Binary (No changes)
        print(f"[INFO] Processing {base_filename}...")
        binary.write(os.path.join(file_dir, base_filename))  # Unmodified
        
        # Stage 2: Remove Debug Sections (nodebug)
        binary_nodebug = lief.parse(binary_path)
        binary_nodebug = strip_debug(binary_nodebug)
        binary_nodebug.write(os.path.join(file_dir, f"{base_filename}_nodebug"))
        
        # Stage 3: Remove Symbol Tables (nosym)
        binary_nosym = lief.parse(binary_path)
        binary_nosym = strip_symbols(binary_nosym)
        binary_nosym.write(os.path.join(file_dir, f"{base_filename}_nosym"))
        
        # Stage 4: Remove Metadata Sections (nometa)
        binary_nometa = lief.parse(binary_path)
        binary_nometa = strip_metadata(binary_nometa)
        binary_nometa.write(os.path.join(file_dir, f"{base_filename}_nometa"))
        
        # Stage 5: Remove Debug + Symbol Tables (nodebug_nosym)
        binary_nodebug_nosym = lief.parse(binary_path)
        binary_nodebug_nosym = strip_debug(binary_nodebug_nosym)
        binary_nodebug_nosym = strip_symbols(binary_nodebug_nosym)
        binary_nodebug_nosym.write(os.path.join(file_dir, f"{base_filename}_nodebug_nosym"))
        
        # Stage 6: Remove Debug + Metadata (nodebug_nometa)
        binary_nodebug_nometa = lief.parse(binary_path)
        binary_nodebug_nometa = strip_debug(binary_nodebug_nometa)
        binary_nodebug_nometa = strip_metadata(binary_nodebug_nometa)
        binary_nodebug_nometa.write(os.path.join(file_dir, f"{base_filename}_nodebug_nometa"))
        
        # Stage 7: Remove Symbols + Metadata (nosym_nometa)
        binary_nosym_nometa = lief.parse(binary_path)
        binary_nosym_nometa = strip_symbols(binary_nosym_nometa)
        binary_nosym_nometa = strip_metadata(binary_nosym_nometa)
        binary_nosym_nometa.write(os.path.join(file_dir, f"{base_filename}_nosym_nometa"))
        
        # Stage 8: Fully Stripped Binary (nodebug_nosym_nometa)
        binary_nodebug_nosym_nometa = lief.parse(binary_path)
        binary_nodebug_nosym_nometa = strip_debug(binary_nodebug_nosym_nometa)
        binary_nodebug_nosym_nometa = strip_symbols(binary_nodebug_nosym_nometa)
        binary_nodebug_nosym_nometa = strip_metadata(binary_nodebug_nosym_nometa)
        binary_nodebug_nosym_nometa.write(os.path.join(file_dir, f"{base_filename}_nodebug_nosym_nometa"))

        print(f"[INFO] Finished processing {base_filename}. Output files saved.")

if __name__ == "__main__":
    # Directory containing queue files
    queue_dir = sys.argv[1]  # The first command line argument should be the queue directory path

    # List of ELF binaries to process
    binary_files = []

    # Check if the directory exists
    if not os.path.isdir(queue_dir):
        print(f"[Error] The directory {queue_dir} does not exist.")
        sys.exit(1)

    # Iterate over all files in the queue directory
    for file_name in os.listdir(queue_dir):
        file_path = os.path.join(queue_dir, file_name)
        
        # Only process text files (queue files)
        if os.path.isfile(file_path) and file_name.endswith(".txt"):
            try:
                with open(file_path, "r") as file:
                    # Read the file and strip leading/trailing whitespace from each line
                    string_list = [line.strip() for line in file.readlines() if line.strip()]
                    binary_files.extend(string_list)  # Add to the list of binaries to process
            except FileNotFoundError:
                print(f"[Error] The file {file_path} was not found.")
            except Exception as e:
                print(f"[Error] An unexpected error occurred while processing {file_path}: {e}")

    # Check if we found any binaries to process
    if not binary_files:
        print("[Error] No binaries to process.")
        sys.exit(1)

    # Process the binaries
    process_binaries(binary_files)