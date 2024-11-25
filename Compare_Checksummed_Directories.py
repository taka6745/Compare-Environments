import os
import csv
import argparse
import tkinter as tk
from tkinter import filedialog, messagebox

# Load checksums and versions from a checksums.csv file
def load_checksums(csv_file):
    print(f"Loading checksums from: {csv_file}")
    checksums = {}
    if os.path.exists(csv_file):
        with open(csv_file, mode='r') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            for row in reader:
                filename = row[0]
                checksum = row[1]
                version = row[2] if len(row) > 2 else 'N/A'
                checksums[filename] = (checksum, version)
    else:
        print(f"File not found: {csv_file}")
    return checksums

# Compare checksums.csv files in both folders and generate missing and different reports
def compare_checksum_csvs(file1, file2, output_folder):
    print(f"Comparing files: {file1} <-> {file2}")
    checksums1 = load_checksums(file1)
    checksums2 = load_checksums(file2)

    missing = []
    different = []

    # Compare files in first folder with second folder
    for filename, (checksum1, version1) in checksums1.items():
        if filename not in checksums2:
            missing.append([filename, os.path.basename(file2)])
            print(f"Missing in {os.path.basename(file2)}: {filename}")
        else:
            checksum2, version2 = checksums2[filename]
            if checksum1 != checksum2 or version1 != version2:
                different.append([filename, checksum1, checksum2, version1, version2])
                print(f"Different file: {filename}")

    # Compare files in second folder with first folder
    for filename in checksums2:
        if filename not in checksums1:
            missing.append([filename, os.path.basename(file1)])
            print(f"Missing in {os.path.basename(file1)}: {filename}")

    # Write missing.csv
    if missing:
        missing_csv = os.path.join(output_folder, 'missing.csv')
        print(f"Writing missing files to: {missing_csv}")
        with open(missing_csv, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Filename', 'Missing_From'])
            writer.writerows(missing)

    # Write different.csv
    if different:
        different_csv = os.path.join(output_folder, 'different.csv')
        print(f"Writing differing files to: {different_csv}")
        with open(different_csv, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Filename', 'Checksum_1', 'Checksum_2', 'Version_1', 'Version_2'])
            writer.writerows(different)

# Traverse directories and compare checksums.csv files
def compare_folders(input_folder1, input_folder2, output_folder):
    print(f"Comparing folders: {input_folder1} <-> {input_folder2}")
    for root1, _, files1 in os.walk(input_folder1):
        rel_path = os.path.relpath(root1, input_folder1)
        folder2 = os.path.join(input_folder2, rel_path)
        output_subfolder = os.path.join(output_folder, rel_path)
        os.makedirs(output_subfolder, exist_ok=True)

        if os.path.exists(folder2):
            if 'checksums.csv' in files1 and os.path.exists(os.path.join(folder2, 'checksums.csv')):
                compare_checksum_csvs(os.path.join(root1, 'checksums.csv'), os.path.join(folder2, 'checksums.csv'), output_subfolder)
        else:
            print(f"Folder missing in {os.path.basename(input_folder2)}: {rel_path}")
            missing_csv = os.path.join(output_subfolder, 'missing.csv')
            with open(missing_csv, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Folder', 'Missing_From'])
                writer.writerow([rel_path, os.path.basename(input_folder2)])

    for root2, _, _ in os.walk(input_folder2):
        rel_path = os.path.relpath(root2, input_folder2)
        folder1 = os.path.join(input_folder1, rel_path)

        if not os.path.exists(folder1):
            print(f"Folder missing in {os.path.basename(input_folder1)}: {rel_path}")
            output_subfolder = os.path.join(output_folder, rel_path)
            os.makedirs(output_subfolder, exist_ok=True)
            missing_csv = os.path.join(output_subfolder, 'missing.csv')
            with open(missing_csv, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Folder', 'Missing_From'])
                writer.writerow([rel_path, os.path.basename(input_folder1)])

# GUI functions
def browse_directory(entry_field):
    path = filedialog.askdirectory()
    if path:
        entry_field.delete(0, tk.END)
        entry_field.insert(0, path)

def start_comparison():
    input_folder1 = folder1_entry.get()
    input_folder2 = folder2_entry.get()

    if not input_folder1 or not input_folder2:
        messagebox.showerror("Error", "Please select both input folders.")
        return

    output_folder_name = f"comparison_{os.path.basename(input_folder1)}_{os.path.basename(input_folder2)}"
    output_folder = os.path.join(os.getcwd(), output_folder_name)
    os.makedirs(output_folder, exist_ok=True)

    print(f"Output folder: {output_folder}")
    compare_folders(input_folder1, input_folder2, output_folder)
    messagebox.showinfo("Success", "Comparison completed successfully.")

def launch_gui():
    global folder1_entry, folder2_entry

    app = tk.Tk()
    app.title("Checksum Folder Comparator")

    # Input Folder 1
    tk.Label(app, text="Select Folder 1:").grid(row=0, column=0, padx=10, pady=5)
    folder1_entry = tk.Entry(app, width=50)
    folder1_entry.grid(row=0, column=1, padx=10, pady=5)
    tk.Button(app, text="Browse", command=lambda: browse_directory(folder1_entry)).grid(row=0, column=2, padx=10, pady=5)

    # Input Folder 2
    tk.Label(app, text="Select Folder 2:").grid(row=1, column=0, padx=10, pady=5)
    folder2_entry = tk.Entry(app, width=50)
    folder2_entry.grid(row=1, column=1, padx=10, pady=5)
    tk.Button(app, text="Browse", command=lambda: browse_directory(folder2_entry)).grid(row=1, column=2, padx=10, pady=5)

    # Start Button
    tk.Button(app, text="Start", command=start_comparison).grid(row=2, column=0, columnspan=3, pady=10)

    app.mainloop()

# Main function
def main():
    parser = argparse.ArgumentParser(description="Compare two folders recursively and generate missing/different file reports.")
    parser.add_argument('input_folder1', nargs='?', help="First folder to compare")
    parser.add_argument('input_folder2', nargs='?', help="Second folder to compare")
    parser.add_argument('--gui', action='store_true', help="Launch GUI application.")

    args = parser.parse_args()

    if args.gui:
        launch_gui()
    else:
        if not args.input_folder1 or not args.input_folder2:
            print("Error: Please provide both input folders in CLI mode.")
            return

        input_folder1 = os.path.abspath(args.input_folder1)
        input_folder2 = os.path.abspath(args.input_folder2)

        output_folder_name = f"comparison_{os.path.basename(input_folder1)}_{os.path.basename(input_folder2)}"
        output_folder = os.path.join(os.getcwd(), output_folder_name)
        os.makedirs(output_folder, exist_ok=True)

        print(f"Output folder: {output_folder}")
        compare_folders(input_folder1, input_folder2, output_folder)
        print("Comparison completed.")

if __name__ == '__main__':
    main()
