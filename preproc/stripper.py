import os
import sys
import lief

def strip_debug(binary):
    to_remove = [".debug_info", ".debug_line", ".debug_str", ".debug_abbrev", ".debug_frame"]
    for section in to_remove:
        sec = binary.get_section(section)
        if sec:
            binary.remove_section(sec.name)
    return binary

def strip_symbols(binary):
    to_remove = [".symtab", ".strtab"]
    for section in to_remove:
        sec = binary.get_section(section)
        if sec:
            binary.remove_section(sec.name)
    return binary

def strip_metadata(binary):
    to_remove = [".comment", ".note", ".hash", ".gnu.hash"]
    for section in to_remove:
        sec = binary.get_section(section)
        if sec:
            binary.remove_section(sec.name)
    return binary

def process_binaries(binary_map):
    """Process and strip binaries, returning a dict mapping queue files to newly created binaries."""
    queue_updates = {}

    for binary_path, source_queue_file in binary_map:
        if not os.path.isfile(binary_path):
            print(f"[WARN] Skipping non-existent file: {binary_path}")
            continue

        try:
            binary = lief.parse(binary_path)
        except Exception as e:
            print(f"[ERROR] Failed to parse {binary_path}: {e}")
            continue

        base_filename = os.path.basename(binary_path)
        file_dir = os.path.dirname(binary_path)

        # Track created variants
        created_variants = []

        print(f"[INFO] Processing {base_filename}...")

        variants = {
            "_nodebug": lambda b: strip_debug(b),
            "_nosym": lambda b: strip_symbols(b),
            "_nometa": lambda b: strip_metadata(b),
            "_nodebug_nosym": lambda b: strip_symbols(strip_debug(b)),
            "_nodebug_nometa": lambda b: strip_metadata(strip_debug(b)),
            "_nosym_nometa": lambda b: strip_metadata(strip_symbols(b)),
            "_nodebug_nosym_nometa": lambda b: strip_metadata(strip_symbols(strip_debug(b)))
        }

        for suffix, transform in variants.items():
            try:
                modified_binary = transform(lief.parse(binary_path))
                new_path = os.path.join(file_dir, f"{base_filename}{suffix}")
                modified_binary.write(new_path)
                created_variants.append(new_path)
            except Exception as e:
                print(f"[ERROR] Failed to create {suffix} for {binary_path}: {e}")

        # Register the updates for the queue file
        if source_queue_file not in queue_updates:
            queue_updates[source_queue_file] = []
        queue_updates[source_queue_file].extend(created_variants)

        print(f"[INFO] Finished processing {base_filename}. {len(created_variants)} variants created.")

    return queue_updates

def update_queue_files(queue_updates):
    """Append new binaries to their respective queue files."""
    for queue_file, new_binaries in queue_updates.items():
        try:
            with open(queue_file, "a") as f:
                for binary_path in new_binaries:
                    f.write(binary_path + "\n")
            print(f"[INFO] Updated queue file: {queue_file} with {len(new_binaries)} new binaries.")
        except Exception as e:
            print(f"[ERROR] Could not update {queue_file}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[Usage] python script.py <queue_directory>")
        sys.exit(1)

    queue_dir = sys.argv[1]

    if not os.path.isdir(queue_dir):
        print(f"[Error] The directory {queue_dir} does not exist.")
        sys.exit(1)

    binary_map = []  # List of tuples (binary_path, source_queue_file)

    for file_name in os.listdir(queue_dir):
        if not file_name.endswith(".txt"):
            continue

        file_path = os.path.join(queue_dir, file_name)
        try:
            with open(file_path, "r") as f:
                for line in f:
                    binary_path = line.strip()
                    if binary_path:
                        binary_map.append((binary_path, file_path))
        except Exception as e:
            print(f"[ERROR] Could not read {file_path}: {e}")

    if not binary_map:
        print("[Error] No binaries found to process.")
        sys.exit(1)

    # Process binaries and get update map
    queue_updates = process_binaries(binary_map)

    # Append new paths to queue files
    update_queue_files(queue_updates)
