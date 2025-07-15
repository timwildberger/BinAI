import os

def collect_csv_files(directory):
    """
    Collect all .csv files from a nested directory and store them in a dictionary.
    The key is the file path, and the value is the file's content.
    """
    csv_files = {}
    
    # Walk through the directory to find all .csv files
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".csv"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    csv_files[file_path] = f.read()  # Store the file's content
                
    return csv_files

def check_paths_in_dict(txt_file_path, csv_dict):
    """
    Check if the paths from the .txt file are in the given dictionary.
    Returns the percentage of found paths.
    """
    found_count = 0
    total_count = 0
    
    # Read the paths from the .txt file
    with open(txt_file_path, 'r') as f:
        paths = f.readlines()
    
    total_count = len(paths)  # Total number of paths to check
    
    # Check each path and see if it's in the dictionary
    for path in paths:
        path = path.strip()  # Remove any extra spaces or newline characters
        if path in csv_dict:
            found_count += 1
    
    # Calculate the percentage of found paths
    if total_count > 0:
        percentage = (found_count / total_count) * 100
    else:
        percentage = 0.0
    
    return percentage, found_count, total_count

def main():
    # Directories and files (you can adjust these paths as needed)
    csv_directory = "out"  # Directory where .csv files are located
    txt_file = "queue/queue_complete.txt"       # .txt file with paths to check

    # Collect all .csv files in the dictionary
    csv_dict = collect_csv_files(csv_directory)

    # Check paths in the .txt file against the dictionary
    percentage, found, total = check_paths_in_dict(txt_file, csv_dict)

    # Print the result
    print(f"Found {found} out of {total} paths.")
    print(f"Percentage of paths found: {percentage:.2f}%")

if __name__ == "__main__":
    main()
