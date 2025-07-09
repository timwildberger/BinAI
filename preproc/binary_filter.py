import os
from pathlib import Path
import argparse

class BinaryFilter:
    def __init__(self, root_dir="src"):
        self.root_dir = root_dir
        self.binaries = self._find_binaries()
        self.fields = ["arch", "compiler", "version", "opt", "program"]

    def _find_binaries(self):
        binaries = []
        for root, _, files in os.walk(self.root_dir):
            for file in files:
                filepath = os.path.join(root, file)
                data = self._parse_filename(file)
                if data:
                    binaries.append({
                        "path": filepath,
                        "name": file,
                        **data
                    })
        return binaries

    def _parse_filename(self, filename):
        name = os.path.splitext(filename)[0]
        if "-" not in name or "_" not in name:
            return None
        try:
            prefix, program = name.split("_", 1)
            parts = prefix.split("-")
            if len(parts) != 4:
                return None
            return {
                "arch": parts[0],
                "compiler": parts[1],
                "version": parts[2],
                "opt": parts[3],
                "program": program
            }
        except ValueError:
            return None

    def show_filter_options(self):
        options = {field: set() for field in self.fields}
        for binary in self.binaries:
            for field in self.fields:
                options[field].add(binary[field])
        for field in self.fields:
            print(f"{field}: {sorted(options[field])}")

    def filter(self, **criteria):
        results = []
        for binary in self.binaries:
            match = True
            for key, value in criteria.items():
                if isinstance(value, list):
                    if binary.get(key) not in value:
                        match = False
                        break
                else:
                    if binary.get(key) != value:
                        match = False
                        break
            if match:
                results.append(binary)
        return results

def sort_files_by_size(paths):
    """
    Takes a list of file paths (as strings), returns a list of (path, size_in_bytes),
    sorted by size descendingly.
    """
    file_sizes = []
    for path in paths:
        if os.path.isfile(path):
            size = os.path.getsize(path)
            file_sizes.append((path, size))
        else:
            print(f"Warning: '{path}' is not a valid file or doesn't exist.")

    sorted_files = sorted(file_sizes, key=lambda x: x[1], reverse=False)

    # Print with formatting
    for path, size in sorted_files:
        size_kb = size / 1024
        size_mb = size / (1024 * 1024)
        #print(f"{path}:\n"
        #      f"  {size} bytes\n"
        #      f"  {size_kb:.2f} KB\n"
        #      f"  {size_mb:.2f} MB\n")

    return [path for path, _ in sorted_files]


def split_paths_interleaved(paths, output_dir, num_lists: int, prefix="queue"):
    """
    Splits a list of file paths into num_lists interleaved lists and writes each to a text file.

    Args:
        paths (list of str): The list of file paths.
        output_dir (str or Path): Directory to store output files.
        prefix (str): Prefix for the output text files.

    Creates:
        queue_0.txt, queue_1.txt, queue_2.txt, queue_3.txt in output_dir
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create 4 interleaved buckets
    buckets: list[list[Path]] = [[] for _ in range(num_lists)]
    for i, path in enumerate(paths):
        buckets[i % num_lists].append(path)

    # Write each bucket to its own text file
    for i, bucket in enumerate(buckets):
        file_path = output_dir / f"{prefix}_{i}.txt"
        with open(file_path, "w") as f:
            for line in bucket:
                f.write(f"{line}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--splits", type=int, default=4, help="Number of output queue files to generate.")
    parser.add_argument("--output-dir", type=str, default="./queue", help="Directory to store queue files.")
    args = parser.parse_args()

    bf = BinaryFilter("./src")
    matches = bf.filter(arch=["x86", "x64", "arm32", "arm64"], compiler=["gcc", "clang"], version="9", opt=["O0", "O3"])
    paths = [match["path"] for match in matches]
    print(f"Found {len(paths)} matching binaries.")

    queue = sort_files_by_size(paths)
    split_paths_interleaved(queue, args.output_dir, args.splits)

if __name__ == "__main__":
    main()
