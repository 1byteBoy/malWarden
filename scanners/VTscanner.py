import os
import csv
import json
import requests
import concurrent.futures
from assets.headers import vtheader

# colorssssss
RED    = '\033[1;31m'
BLUE   ="\033[1;34m" 
RCOLOR = '\033[0m'

# Define the URL for the search request
SEARCH_URL = "https://www.virustotal.com/ui/search"
# Define headers to match the intercepted request
headers = vtheader

popular_threat_category = []
popular_threat_name     = []
detected_engines        = []

isMalacious = 0

# Define a function to save threat information to a log file
def save_threat_info(file_name, file_hash, threat_category, threat_name, engines):
    log_directory = "data"  # Adjust this directory as needed
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    log_file_path = os.path.join(log_directory, f"{file_name}_log.txt")

    with open(log_file_path, 'w') as log_file:  # Use 'a' (append) mode to add data to the file
        log_file.write(f"File name: {file_name}\n")
        log_file.write(f"File hash: {file_hash}\n")
        log_file.write("Popular Threat Category:\n")
        log_file.write(", ".join(threat_category) + "\n")  # Write categories separated by a comma
        log_file.write("Popular Threat Name:\n")
        log_file.write(", ".join(threat_name) + "\n")  # Write names separated by a comma
        log_file.write("Detected Engines:\n")
        log_file.write(", ".join(engines) + "\n")  # Write engines separated by a comma

def analysis_stats (data) :
    analysis_results = data.get("data", [])[0].get("attributes", {}).get("last_analysis_stats", []).get("malicious")
    return analysis_results


def threat_category (data) :
    data_analysis_results_threat = data.get("data", [])[0].get("attributes", {}).get("popular_threat_classification", {}).get("popular_threat_category", [])
    for entry in data_analysis_results_threat:
      if isinstance(entry, dict) and "value" in entry:
          value = entry["value"]
          popular_threat_category.append(value)
    return popular_threat_category


def threat_name (data) :
    data_analysis_threat_name = data.get("data", [])[0].get("attributes", {}).get("popular_threat_classification", {}).get("popular_threat_name", [])
    for entry in data_analysis_threat_name:
        if isinstance(entry, dict) and "value" in entry:
            value = entry["value"]
            popular_threat_name.append(value)
    return popular_threat_name


# last_analysis_stats
def engines (data) :
    data_analysis_results = data.get("data", [])[0].get("attributes", {}).get("last_analysis_results", [])
    malicious_engine_names = [name for name, engine in data_analysis_results.items() if engine.get("category") == "malicious"]
    # Print the list of malicious engine names
    if malicious_engine_names:
        for name in malicious_engine_names:
            detected_engines.append(name)
    return detected_engines

def process_response(file_name, query, response):
    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        try:
            # Attempt to parse the JSON response
            data = response.json()

            # check if the file is malicious at the first point
            stat = analysis_stats(data)

            # only if malicious number is greater than 0
            if stat > 0:
                global isMalacious
                isMalacious = 1
                print(f"{RED}[Malicious]{RCOLOR} {file_name}")

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future_category = executor.submit(threat_category, data)
                    future_name = executor.submit(threat_name, data)
                    future_engines = executor.submit(engines, data)

                popular_threat_category = future_category.result()
                popular_threat_name = future_name.result()
                popular_threat_engines = future_engines.result()

                # Save the threat information to a log file
                save_threat_info(file_name, query, popular_threat_category, popular_threat_name, popular_threat_engines)

        except json.JSONDecodeError:
            print("Response is not valid JSON")
    else:
        print(f"Error: {response.status_code} - {response.text}")


# this somewhat bypasses the api restriction somewhat maybe
def virusTotalWeb(file_name, query):
    # Define the parameters for the search query
    params = {
        "limit": 20,
        "relationships[comment]": "author,item",
        "query": query,
    }

    try:
        # Make a GET request to the search URL with headers and parameters
        response = requests.get(SEARCH_URL, headers=headers, params=params)
        
        # Process the response asynchronously
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            executor.submit(process_response, file_name, query, response)

    except Exception as e: pass
        # print(f"An error occurred: {str(e)}")
 

def VirusTotal(input_csv):

    try:
        # Read the CSV file containing the hashes
        with open(input_csv, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            next(csv_reader)  # Skip the header row

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                for row in csv_reader:
                    file_name, payload_hash = row
                    try:
                        executor.submit(virusTotalWeb, file_name, payload_hash)
                    except KeyboardInterrupt:
                        print("\nGood Bye\n")
                        exit(0)
                print(" ")

        if isMalacious == 0 : print("No malicious files found\n")
        else : print(f"\nLog files saved in {BLUE}data{RCOLOR} folder\n") # sorry for hardcoding it
    except Exception as e: pass
        # print(f"\nAn error occurred: {str(e)}\n")


