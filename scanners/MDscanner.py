import csv
import json
import requests

# colorssssss
RED    = '\033[1;31m'
GREEN  = '\033[1;32m'
VIOLET = '\033[0;35m'
YELLOW = '\033[1;33m'
RCOLOR = '\033[0m'

# Metadefender API key token
# for 1 day it can scan 1000 hashes
headers = { "apikey": "0af2845d347266ee9c8f3cba01896a6b" }

def metaDefender (file_sha256):

    MetaUrl = f"https://api.metadefender.com/v4/hash/{file_sha256}"
    response = requests.get(MetaUrl, headers=headers)

    if response.status_code == 200:
        
        # dumps the data into json and then convert it into dictionary
        data_dict = json.loads(response.text)
        # print(json.dumps(data_dict, indent=4))

        # Access and print scan results
        scan_results = data_dict['scan_results']

        # Iterate through each scan result
        for scanner, details in scan_results['scan_details'].items():
            threat_found = details['threat_found']
            print(f"{YELLOW}Scanner        {RCOLOR}: {scanner}")
            print(f"{YELLOW}Threat Found   {RCOLOR}: {threat_found}")

        # Access and print malware types
        malware_types = data_dict['malware_type']

        # Iterate through each malware type
        print(f"{YELLOW}Malware Type   {RCOLOR}: ",end='')
        for malware_type in malware_types:
            print(f"{malware_type},",end=' ')

        malware_family = data_dict['malware_family']
        threat_name = data_dict['threat_name']
        print(f"\n{YELLOW}Malware Family {RCOLOR}: {malware_family}")
        print(f"{YELLOW}Threat Name    {RCOLOR}: {threat_name}")

    else:
        error_message = json.loads(response.text)['error']['messages'][0]
        print(f"{RED}[{response.status_code}]{RCOLOR}\t       :  {error_message}")

def MetaDefender(input_csv):

    try:
        # Read the CSV file containing the hashes
        with open(input_csv, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            next(csv_reader)  # Skip the header row

            for row in csv_reader:
                file_name, payload_hash = row
                try:
                    print(f"\n{YELLOW}File Name      : {RED}{file_name}{RCOLOR}")
                    metaDefender(payload_hash)      
                except KeyboardInterrupt:
                    print("\nGood Bye\n")
                    exit(0)
            print(" ")

    except Exception as e:
        print(f"\nAn error occurred: {str(e)}\n")