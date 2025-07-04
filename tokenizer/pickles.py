import csv
import os
import pickle

import numpy as np


def load_all_pickles(*file_paths):
    all_data = {}

    for file_path in file_paths:
        with open(file_path, "rb") as f:
            data = pickle.load(f)

        key = os.path.splitext(os.path.basename(file_path))[0]
        all_data[key] = data

        if key == "insn_runlength_dict":
            print("Data for insn_runlength_dict loaded:")
            # print(data)
            print(f"Type of data: {type(data)}")
            print(f"Number of items: {len(data) if hasattr(data, '__len__') else 'N/A'}")

        new_filename = f"output_meta/{key}.csv"
        print(f"Writing to: {new_filename}")

        try:
            with open(new_filename, "w", newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                if isinstance(data, dict):
                    for k, v in data.items():
                        writer.writerow([k, v])

                elif isinstance(data, list):
                    if key == "insn_runlength_dict":
                        print(data)
                    for item in data:
                        writer.writerow([item])

                elif isinstance(data, np.ndarray):
                    np.savetxt(csvfile, data, delimiter=",", fmt="%s")

                else:
                    writer.writerow([str(data)])
        except Exception as e:
            print(f"❌ Failed to write {new_filename}: {e}")

    return all_data


def save_pickles(
        func_names, token_dict, block_runlength_dict, insn_runlength_dict, opaque_meta_dict, vocab,
        duplicate_func_names, tokenized_instructions, block_run_lengths, insn_run_lengths, meta_result
):
    filenames = [
        "func_names.pkl", "token_dict.pkl", "block_runlength_dict.pkl", "insn_runlength_dict.pkl",
        "opaque_meta_dict.pkl", "vocab.pkl", "duplicate_func_names.pkl",
        "tokenized_instructions.pkl", "block_run_lengths.pkl", "insn_run_lengths.pkl", "meta_result.pkl"
    ]

    variables = [
        func_names, token_dict, block_runlength_dict, insn_runlength_dict, opaque_meta_dict, vocab,
        duplicate_func_names, tokenized_instructions, block_run_lengths, insn_run_lengths, meta_result
    ]

    for filename, variable in zip(filenames, variables):
        with open(filename, "wb") as f:
            pickle.dump(variable, f)
