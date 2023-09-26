import os
import csv
import json
import requests 
import virustotal_python
from dotenv import load_dotenv

# BUF_SIZE = 65536 # Read the file in 64k chunks

# colorssssss
RED    = '\033[1;31m'
GREEN  = '\033[1;32m'
BLUE   = '\033[1;34m'
VIOLET = '\033[1;35m'
RCOLOR = '\033[0m'

# Virus Total API key token
envPath = '../secret/.env'
load_dotenv(dotenv_path=envPath)
TOKEN = os.getenv('VIRUSTOTAL_TOKEN')
# Define the URL where you want to send the payload
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"
# for url based api request 
headers = {
    "x-apikey": TOKEN
}


# data not parsed for this function
def virusTotalAPIWeb(payload_hash):
    try:
        # Create the URL for the specific file report
        url = f"{VIRUSTOTAL_API_URL}{payload_hash}"

        # Make a GET request to the URL with headers
        response = requests.get(url, headers=headers)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            try:
                # Attempt to parse the JSON response
                json_data = response.json()

                # Print the JSON data or process it as needed
                print("JSON Response:")
                print(json_data)
            except json.JSONDecodeError:
                print("Response is not valid JSON")
        else:
            print(f"Error: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")


def virusTotalAPI(file_path, file_name, file_ID):

    files = {"file": (os.path.basename(file_path), open(os.path.abspath(file_path), "rb"))}

    with virustotal_python.Virustotal(TOKEN) as vtotal:

        resp = vtotal.request("files", files=files, method="POST")

        # Query the scan results
        resp = vtotal.request(f"files/{file_ID}")

        # Extract and print a concise summary of scan results
        scan_results = resp.data.get("attributes", {}).get("last_analysis_stats", {})

        # Print other information, if needed
        print(f"{VIOLET}File Name : {RCOLOR}", file_name)
        print(f"{VIOLET}File Hash : {RCOLOR}", file_ID)

        # Print the summary of scan results
        for key, value in scan_results.items():
            print(f"{VIOLET}{key} : {RCOLOR}{value}")

        # Determine if the file is malicious based on the 'malicious' count
        is_malicious = scan_results.get("malicious", 0) > 0
        if is_malicious:
            print(f"{RED}This file is considered malicious\033[0m\n\n")
        else:
            print(f"{GREEN}This file is not considered malicious\033[0m\n\n")


def VirusTotal(input_csv):

    try:
        # Read the CSV file containing the hashes
        with open(input_csv, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            next(csv_reader)  # Skip the header row

            for row in csv_reader:
                file_name, payload_hash = row
                try:
                    virusTotalAPI(file_name, payload_hash)
                except KeyboardInterrupt:
                    print("\nGood Bye\n")
                    exit(0)
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}\n")