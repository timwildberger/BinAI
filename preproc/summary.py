import os
import sys
import subprocess
import re
import pandas as pd

def summarize_binaries(folder_path):
    summary = []

    for filename in os.listdir(folder_path):
        filepath = os.path.join(folder_path, filename)
        if not os.path.isfile(filepath):
            continue

        try:
            # Detect architecture
            file_output = subprocess.check_output(['file', filepath], text=True)

            arch = "Unknown"
            if "x86-64" in file_output:
                arch = "x86_64"
            elif "ARM" in file_output:
                arch = "ARM"
            elif "aarch64" in file_output:
                arch = "ARM64"

            # Detect compiler using strings
            strings_output = subprocess.check_output(['strings', filepath], text=True)
            compiler = "Unknown"
            if "GCC:" in strings_output:
                compiler = "GCC"
            elif "clang" in strings_output:
                compiler = "Clang"
            elif "Microsoft" in strings_output:
                compiler = "MSVC"

            # Heuristic optimization level
            opt_level = "Unknown"
            opt_match = re.search(r'-O[0123s]', strings_output)
            if opt_match:
                opt_level = opt_match.group(0)

            summary.append({
                "Filename": filename,
                "Architecture": arch,
                "Compiler": compiler,
                "Optimization": opt_level
            })

        except subprocess.CalledProcessError:
            continue

    df = pd.DataFrame(summary)
    return df

def main():
    if len(sys.argv) != 2:
        print("Usage: python summarize_binaries.py /path/to/binaries")
        sys.exit(1)

    folder_path = sys.argv[1]
    if not os.path.isdir(folder_path):
        print(f"Error: '{folder_path}' is not a valid directory.")
        sys.exit(1)

    df = summarize_binaries(folder_path)
    if df.empty:
        print("No binaries found or could not extract metadata.")
    else:
        print(df.to_string(index=False))

if __name__ == "__main__":
    main()
