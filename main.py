import sys

from shaaaash.fileHasher import *
from scanners.VTscanner import VirusTotal
# from scanners.MDscanner import MetaDefender

VIOLET ="\033[1;35m"
RCOLOR ="\033[0m"

# leaving the help function at top for others to get help =)
def help () :

    # Note : argument parser can be implimented later
    print(f"\nUsage : python3 {sys.argv[0]} <option> [<mode>]")
    print("\nExamples:")
    print(f"python3 {sys.argv[0]} -v <path/to/directory>")
    print(f"python3 {sys.argv[0]} -p <mode>")
    print("\nOptions:")
    print("-v\tScan directory using VirusTotal")
    print("-m\tScan directory using MetaDefender")
    print("-p\tScan the running system application")
    print("-h\tPrint the help menu")
    print("\nModes:")
    print("-v\tVirusTotal Scan")
    print("-m\tMetadefender Scan\n")
    exit()
    # i know the mode is still confusing deal with it for now


def send_ME_home (flag, justArgument) :

    if flag == '-v' or flag == '-m' : 
        hash_file = generate_file_hashes(justArgument)
        if flag == '-v': VirusTotal(hash_file)
        # elif flag == '-m': MetaDefender(hash_file) 


def choice () :

    # this argument handling is messy but works, so deal with it for now
    try: user_flag = sys.argv[1]
    except IndexError: help()

    user_flag = user_flag.lower()
    if user_flag == '-v' or user_flag == '-m':       
        try: 
            if user_flag == '-m' : print("\n[!] sorry need to fix some bugs\n"); exit()
            directry_path = sys.argv[2]
            if os.path.isdir(directry_path): send_ME_home(user_flag, directry_path)
            else: print(f"\n{directry_path} is not a valid directory.\n"); exit()
        except IndexError: 
            print(f"\n[!]{VIOLET} Please enter a valid directory path {RCOLOR}"); help()
    elif user_flag == '-p' : 
        try: 
            print("\n[!] Process scanning not ready yet\n")
            # scanMethod = sys.argv[2]
            # send_ME_home(user_flag, scanMethod)
        except IndexError: 
            print(f"\n[!]{VIOLET} Please Specify the scan mode{RCOLOR}"); help()
    elif user_flag == '-h': help()
    else:
        print(f"\n[!]{VIOLET} Please specify a valid option{RCOLOR}") 
        help()


if __name__ == "__main__": choice()