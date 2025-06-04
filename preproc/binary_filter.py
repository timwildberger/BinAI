import os

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
        """
        Filters: arch, compiler, version, opt, program"""
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


def main():
    bf = BinaryFilter()

    # Show filter options
    bf.show_filter_options()

    # Filter for arch in ["x86", "arm64"] and opt = "O0"
    matches = bf.filter(arch=["x86", "arm64", "arm32", "x64"], compiler=["gcc", "clang"], opt=["O0", "O2"], version=["9"])

    for match in matches:
        print(match["path"])

    print(len(matches))

if __name__ == "__main__":
    main()