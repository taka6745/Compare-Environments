import os
import hashlib
import csv
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import win32api
import tkinter as tk
from tkinter import filedialog, messagebox

# Function to calculate checksum of a file and get the file version
def checksum_file(filepath, algo='sha256'):
    hash_func = hashlib.new(algo)
    file_version = "N/A"
    try:
        # Get file version if available
        try:
            info = win32api.GetFileVersionInfo(filepath, '\\')
            ms = info['FileVersionMS']
            ls = info['FileVersionLS']
            file_version = f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
        except Exception as e:
            print(f"No file version info for {filepath}: {e}")

        # Calculate file checksum
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest(), file_version

    except PermissionError:
        print(f"Permission denied: {filepath}. Skipping.")
        return None, file_version
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return None, file_version

# Function to process a single directory and generate a checksum CSV
def process_single_directory(directory, output_folder, algo='sha256'):
    print(f"Processing directory: {directory}")
    output_subfolder = os.path.join(output_folder, os.path.relpath(directory, root_dir))
    os.makedirs(output_subfolder, exist_ok=True)

    csv_file = os.path.join(output_subfolder, 'checksums.csv')
    with open(csv_file, mode='w', newline='') as csvf:
        csv_writer = csv.writer(csvf)
        csv_writer.writerow(['Filename', 'Checksum', 'File Version'])

        for file in os.listdir(directory):
            file_path = os.path.join(directory, file)
            if os.path.isfile(file_path):
                print(f"Processing file: {file_path}")
                checksum, file_version = checksum_file(file_path, algo)
                if checksum:
                    csv_writer.writerow([file, checksum, file_version])

# Function to process all directories concurrently
def process_all_directories(directory, output_folder, algo='sha256', max_workers=4):
    directories = [root for root, _, _ in os.walk(directory)]
    print(f"Directories to process: {directories}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for dir_path in directories:
            futures.append(executor.submit(process_single_directory, dir_path, output_folder, algo))

        for future in as_completed(futures):
            future.result()

# GUI functions
def browse_directory(entry_field):
    path = filedialog.askdirectory()
    if path:
        entry_field.delete(0, tk.END)
        entry_field.insert(0, path)

def start_processing():
    global root_dir
    directory = directory_entry.get()
    output_folder = output_folder_entry.get()
    algo = algo_var.get()
    workers = int(workers_var.get())

    if not directory or not output_folder:
        messagebox.showerror("Error", "Please select both the directory and output folder.")
        return

    try:
        root_dir = os.path.abspath(directory)
        output_folder = os.path.abspath(output_folder)
        os.makedirs(output_folder, exist_ok=True)

        process_all_directories(root_dir, output_folder, algo, workers)
        messagebox.showinfo("Success", "Checksum generation completed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def launch_gui():
    global directory_entry, output_folder_entry, algo_var, workers_var

    app = tk.Tk()
    app.title("Checksum Generator")

    # Directory selection
    tk.Label(app, text="Select Directory:").grid(row=0, column=0, padx=10, pady=5)
    directory_entry = tk.Entry(app, width=50)
    directory_entry.grid(row=0, column=1, padx=10, pady=5)
    tk.Button(app, text="Browse", command=lambda: browse_directory(directory_entry)).grid(row=0, column=2, padx=10, pady=5)

    # Output folder selection
    tk.Label(app, text="Select Output Folder:").grid(row=1, column=0, padx=10, pady=5)
    output_folder_entry = tk.Entry(app, width=50)
    output_folder_entry.grid(row=1, column=1, padx=10, pady=5)
    tk.Button(app, text="Browse", command=lambda: browse_directory(output_folder_entry)).grid(row=1, column=2, padx=10, pady=5)

    # Algorithm selection
    tk.Label(app, text="Checksum Algorithm:").grid(row=2, column=0, padx=10, pady=5)
    algo_var = tk.StringVar(value="sha256")
    tk.Entry(app, textvariable=algo_var).grid(row=2, column=1, padx=10, pady=5)

    # Workers
    tk.Label(app, text="Number of Workers:").grid(row=3, column=0, padx=10, pady=5)
    workers_var = tk.StringVar(value="4")
    tk.Entry(app, textvariable=workers_var).grid(row=3, column=1, padx=10, pady=5)

    # Start button
    tk.Button(app, text="Start", command=start_processing).grid(row=4, column=0, columnspan=3, pady=10)

    app.mainloop()

# Main function
def main():
    parser = argparse.ArgumentParser(description="Generate checksums for files in a directory.")
    parser.add_argument('directory', nargs='?', help="The root directory to process recursively.")
    parser.add_argument('output_folder', nargs='?', help="The output folder for checksum CSVs.")
    parser.add_argument('--algo', default='sha256', help="Checksum algorithm to use (default: sha256).")
    parser.add_argument('--workers', default=4, type=int, help="Number of threads to use (default: 4).")
    parser.add_argument('--gui', action='store_true', help="Launch GUI application.")

    args = parser.parse_args()

    if args.gui:
        launch_gui()
    else:
        if not args.directory or not args.output_folder:
            print("Error: Please provide both directory and output folder in CLI mode.")
            return

        global root_dir
        root_dir = os.path.abspath(args.directory)
        output_folder = os.path.abspath(args.output_folder)
        os.makedirs(output_folder, exist_ok=True)

        print(f"Starting checksum generation...")
        print(f"Root directory: {root_dir}")
        print(f"Output directory: {output_folder}")
        process_all_directories(root_dir, output_folder, args.algo, args.workers)
        print("Checksum generation completed.")

if __name__ == '__main__':
    main()
