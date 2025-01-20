import os
import csv
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import win32api  # Requires: pip install pywin32
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, StringVar, BooleanVar

##############################################################################
#                           FILE VERSION & CHECKSUM
##############################################################################
def get_file_version(filepath):
    """
    Return Windows file version string or 'N/A' if not available.
    """
    try:
        info = win32api.GetFileVersionInfo(filepath, '\\')
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except:
        return "N/A"


class ProgressManager:
    """
    Thread-safe class for aggregating the total number of bytes processed.
    We'll poll this from the main thread to update the progress bar.
    """
    def __init__(self):
        self.total_bytes_processed = 0
        self.lock = threading.Lock()

    def add_bytes(self, count: int):
        with self.lock:
            self.total_bytes_processed += count

    def get_bytes(self) -> int:
        with self.lock:
            return self.total_bytes_processed


def checksum_file_with_progress(filepath, algo, progress_mgr, chunk_size=65536):
    """
    Calculate the checksum of 'filepath' with the specified hash 'algo' (e.g. 'sha256'),
    incrementing 'progress_mgr' as bytes are read.

    Returns: (checksum_hex, file_version) or (None, "N/A") if error.
    """
    try:
        hash_func = hashlib.new(algo)
        version = get_file_version(filepath)
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_func.update(chunk)
                progress_mgr.add_bytes(len(chunk))
        return hash_func.hexdigest(), version
    except Exception as e:
        print(f"Could not process file '{filepath}': {e}")
        return None, "N/A"


##############################################################################
#                    LIST ROOT FILES (SKIP .CSV) - NO SUBFOLDERS
##############################################################################
def list_root_files(folder_path):
    """
    Return list of (filename, fullpath, filesize).
    Skip directories and .csv files.
    """
    results = []
    if os.path.isdir(folder_path):
        for fname in os.listdir(folder_path):
            fullp = os.path.join(folder_path, fname)
            if os.path.isfile(fullp) and not fname.lower().endswith('.csv'):
                try:
                    size = os.path.getsize(fullp)
                except:
                    size = 0
                results.append((fname, fullp, size))
    return results


##############################################################################
#                             COMPARISON LOGIC
##############################################################################
def compare_file_data(data1, data2, label1="Folder1", label2="Folder2"):
    """
    data1, data2 = dict { filename: (checksum, version) }.

    Returns (missing_rows, different_rows):
      missing_rows => [ [Filename, FoundIn, FileVersion, FileChecksum, MissingIn], ... ]
      different_rows => [ [Filename,
                           Folder1Version, Folder1Checksum,
                           Folder2Version, Folder2Checksum], ... ]
    """
    missing_rows = []
    different_rows = []

    # Check from data1 -> data2
    for fname, (cs1, ver1) in data1.items():
        if fname not in data2:
            missing_rows.append([fname, label1, ver1, cs1, label2])
        else:
            # present in both => check difference
            cs2, ver2 = data2[fname]
            if cs1 != cs2 or ver1 != ver2:
                different_rows.append([fname, ver1, cs1, ver2, cs2])

    # Check from data2 -> data1
    for fname, (cs2, ver2) in data2.items():
        if fname not in data1:
            missing_rows.append([fname, label2, ver2, cs2, label1])

    return missing_rows, different_rows


##############################################################################
#                                GUI APP
##############################################################################
class RootFolderCompareApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Root-Folder Checksum & Compare (Partial Progress)")

        # Use ttk for style
        self.style = ttk.Style(self.master)
        self.style.theme_use("clam")

        # Variables
        self.folder1_var = StringVar()
        self.folder2_var = StringVar()
        self.output_var = StringVar()
        self.algo_var = StringVar(value="sha256")
        self.save_var = BooleanVar(value=False)
        self.workers_var = StringVar(value="4")

        # For progress
        self.progress_var = tk.IntVar(value=0)  # 0 -> 100
        self.total_size = 0
        self.folder1_data = {}
        self.folder2_data = {}

        # Layout
        main_frame = ttk.Frame(master, padding="10 10 10 10")
        main_frame.grid(row=0, column=0, sticky="nsew")

        # Folder 1
        ttk.Label(main_frame, text="Folder 1:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        ttk.Entry(main_frame, textvariable=self.folder1_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_folder1).grid(row=0, column=2, padx=5, pady=5)

        # Folder 2
        ttk.Label(main_frame, text="Folder 2:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        ttk.Entry(main_frame, textvariable=self.folder2_var, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_folder2).grid(row=1, column=2, padx=5, pady=5)

        # Output
        ttk.Label(main_frame, text="Output Folder:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        ttk.Entry(main_frame, textvariable=self.output_var, width=50).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=2, column=2, padx=5, pady=5)

        # Default output to Desktop if possible
        try:
            from pathlib import Path
            desktop = str(Path.home() / "Desktop")
            self.output_var.set(desktop)
        except:
            pass

        # Hash algo
        ttk.Label(main_frame, text="Hash Algorithm:").grid(row=3, column=0, sticky="e", padx=5, pady=5)
        ttk.Entry(main_frame, textvariable=self.algo_var, width=15).grid(row=3, column=1, sticky="w", padx=5, pady=5)

        # Workers
        ttk.Label(main_frame, text="Threads:").grid(row=4, column=0, sticky="e", padx=5, pady=5)
        ttk.Entry(main_frame, textvariable=self.workers_var, width=5).grid(row=4, column=1, sticky="w", padx=5, pady=5)

        # Save checksums
        ttk.Checkbutton(main_frame, text="Save Root Checksums to Output Folder",
                        variable=self.save_var).grid(row=5, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        # Progress bar
        ttk.Label(main_frame, text="Progress:").grid(row=6, column=0, sticky="e", padx=5, pady=5)
        self.progress_bar = ttk.Progressbar(main_frame, orient="horizontal",
                                            length=400, mode="determinate",
                                            maximum=100, variable=self.progress_var)
        self.progress_bar.grid(row=6, column=1, padx=5, pady=5, sticky="we")

        # Start button
        ttk.Button(main_frame, text="Start", command=self.start_process).grid(row=7, column=0, columnspan=3, pady=15)

        # Expand
        main_frame.columnconfigure(1, weight=1)
        self.master.columnconfigure(0, weight=1)

        # For concurrency
        self.progress_mgr = None
        self.futures = []
        self.future_map = {}

    def browse_folder1(self):
        path = filedialog.askdirectory()
        if path:
            self.folder1_var.set(path)

    def browse_folder2(self):
        path = filedialog.askdirectory()
        if path:
            self.folder2_var.set(path)

    def browse_output(self):
        path = filedialog.askdirectory()
        if path:
            self.output_var.set(path)

    def start_process(self):
        folder1 = self.folder1_var.get().strip()
        folder2 = self.folder2_var.get().strip()
        out_dir = self.output_var.get().strip()

        # Validate
        if not folder1 or not os.path.isdir(folder1):
            messagebox.showerror("Error", "Folder 1 is not a valid directory.")
            return
        if not folder2 or not os.path.isdir(folder2):
            messagebox.showerror("Error", "Folder 2 is not a valid directory.")
            return
        if not out_dir or not os.path.isdir(out_dir):
            messagebox.showerror("Error", "Output folder is not a valid directory.")
            return

        # Reset progress
        self.progress_var.set(0)
        self.folder1_data = {}
        self.folder2_data = {}
        self.progress_mgr = ProgressManager()

        # Gather root files
        files1 = list_root_files(folder1)
        files2 = list_root_files(folder2)

        # Sum total size
        self.total_size = sum(f[2] for f in files1) + sum(f[2] for f in files2)
        if self.total_size == 0:
            messagebox.showinfo("Info", "No non-CSV files found in either folder's root.")
            return

        self.folder1_files = files1
        self.folder2_files = files2
        self.algo = self.algo_var.get().strip()
        self.save_csvs = self.save_var.get()
        self.out_dir = out_dir
        try:
            self.num_workers = int(self.workers_var.get().strip())
        except ValueError:
            self.num_workers = 4

        # Start background threading
        threading.Thread(target=self.compute_checksums_bg, daemon=True).start()
        # Poll progress
        self.master.after(200, self.poll_progress)

    def compute_checksums_bg(self):
        """
        Schedules hashing tasks in a ThreadPoolExecutor so the UI is not blocked.
        """
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            future_map_local = {}

            # Submit tasks for Folder1
            for fname, fullp, _sz in self.folder1_files:
                fut = executor.submit(checksum_file_with_progress, fullp, self.algo, self.progress_mgr)
                future_map_local[fut] = ("folder1", fname)

            # Submit tasks for Folder2
            for fname, fullp, _sz in self.folder2_files:
                fut = executor.submit(checksum_file_with_progress, fullp, self.algo, self.progress_mgr)
                future_map_local[fut] = ("folder2", fname)

            self.futures = list(future_map_local.keys())
            self.future_map = future_map_local

        # Once the executor context exits, all tasks have completed
        self.master.after(200, self.on_all_checksums_done)

    def poll_progress(self):
        """
        Update the progress bar ~5 times per second based on partial bytes read.
        """
        if self.progress_mgr is not None and self.total_size > 0:
            current_bytes = self.progress_mgr.get_bytes()
            pct = int(100 * current_bytes / self.total_size)
            if pct > 100:
                pct = 100
            self.progress_var.set(pct)

        # If we still have pending futures or we haven't done final finishing,
        # keep polling
        if any(fut for fut in self.futures if not fut.done()):
            self.master.after(200, self.poll_progress)
        else:
            # All tasks might be done, but let's do one more check in case
            if self.progress_mgr is not None and self.total_size > 0:
                pct = int(100 * self.progress_mgr.get_bytes() / self.total_size)
                if pct > 100:
                    pct = 100
                self.progress_var.set(pct)

    def on_all_checksums_done(self):
        """
        Called after the thread pool is done. Gather results from futures.
        """
        for fut in self.futures:
            location, fname = self.future_map[fut]
            try:
                csum, ver = fut.result()
                if csum:
                    if location == "folder1":
                        self.folder1_data[fname] = (csum, ver)
                    else:
                        self.folder2_data[fname] = (csum, ver)
            except Exception as e:
                print(f"Future error: {e}")

        self.futures.clear()
        self.future_map.clear()

        # Now that we have folder1_data and folder2_data, do final steps
        self.compare_and_finish()

    def compare_and_finish(self):
        """
        Writes optional root checksums CSV, then compares and writes missing/different CSVs.
        """
        # 1) Save checksums if requested
        if self.save_csvs:
            c1_path = os.path.join(self.out_dir, "checksums_input1.csv")
            c2_path = os.path.join(self.out_dir, "checksums_input2.csv")
            self.write_checksums_csv(c1_path, self.folder1_data, "Folder1", self.algo)
            self.write_checksums_csv(c2_path, self.folder2_data, "Folder2", self.algo)

        # 2) Compare
        missing_rows, different_rows = compare_file_data(self.folder1_data, self.folder2_data,
                                                         label1="Folder1", label2="Folder2")

        # 3) Write missing.csv / different.csv if needed
        msg = []
        if missing_rows:
            missing_csv = os.path.join(self.out_dir, "missing.csv")
            with open(missing_csv, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["Filename", "Found In", "FileVersion", "FileChecksum", "Missing In"])
                w.writerows(missing_rows)
            msg.append(f"missing.csv => {missing_csv}")

        if different_rows:
            diff_csv = os.path.join(self.out_dir, "different.csv")
            with open(diff_csv, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["Filename",
                            "Folder1Version", "Folder1Checksum",
                            "Folder2Version", "Folder2Checksum"])
                w.writerows(different_rows)
            msg.append(f"different.csv => {diff_csv}")

        if not missing_rows and not different_rows:
            msg.append("No files missing or different!")

        final_msg = "Checksum & Compare Complete!\n\n" + "\n".join(msg)
        messagebox.showinfo("Done", final_msg)

    def write_checksums_csv(self, csv_path, data_dict, label, algo):
        """
        Write a CSV of file checksums & versions to the output folder:
          Filename, Checksum, FileVersion, Folder, HashAlgo
        """
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(["Filename", "Checksum", "FileVersion", "Folder", "HashAlgo"])
            for fname, (csum, ver) in data_dict.items():
                w.writerow([fname, csum, ver, label, algo])


def main():
    root = tk.Tk()
    app = RootFolderCompareApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
