import os
import csv
import hashlib
import threading

# colorssssss
BLUE   ="\033[1;34m"
VIOLET ="\033[1;35m"
RCOLOR ="\033[0m"

# Initialize a list to store the hash and file name pairs
hash_list = []

# File to save file hashes and file name in csv format
# hashFile  = "fileHashes.csv"
directory = "data"

def scan_file(file_path, file_name):

    try:
        # Generate SHA-256 hash for the file
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while True:
                data = file.read()
                if not data: break
                sha256.update(data)

        payload_hash = format(sha256.hexdigest())

        # Append the hash and file name to the list
        hash_list.append((file_name, payload_hash))
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}\n")


def generate_file_hashes(directory_path):

    try:
        # Check if the given path is a directory
        if os.path.isdir(directory_path):

            # Get a list of all files in the directory
            dirContent = os.listdir(directory_path)

            # Filter out only files (exclude subdirectories)
            files = [content for content in dirContent if os.path.isfile(os.path.join(directory_path, content))]

            # Print the list of files and generate hashes
            if files:

                print(f"\nScanning files in {VIOLET}{directory_path}{RCOLOR} directory")

                threads = []
                for file_name in files:
                    file_path = os.path.join(directory_path, file_name)

                    # Create a thread to scan each file
                    thread = threading.Thread(target=scan_file, args=(file_path, file_name))
                    threads.append(thread)
                    thread.start()

                # Wait for all threads to finish
                for thread in threads: thread.join()

                # Ensure the "data" directory exists or create it if it doesn't
                if not os.path.exists(directory):
                    os.makedirs(directory)

                # Define the full path to the CSV file within the "data" directory
                csv_file_path = os.path.join(directory, "fileHashes.csv")

                # Write the hash list to a CSV file within the "data" directory
                with open(csv_file_path, 'w', newline='') as csv_file:
                    csv_writer = csv.writer(csv_file)
                    csv_writer.writerow(["File Name", "SHA-256 Hash"])
                    csv_writer.writerows(hash_list)

                print(f"Hashes saved to {BLUE}{csv_file_path}{RCOLOR} file"); return csv_file_path
            
            else: print(f"\nNo files found in {directory_path}.\n")
        else: print(f"\n'{directory_path}' is not a valid directory.\n")
    except Exception as e: print(f"\nAn error occurred: {str(e)}\n")
