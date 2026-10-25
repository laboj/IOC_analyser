#==============================================================================================================================
#author@laboj
#date@23-10-2026
#lesson: File Hash Analysis
#description: read file, reusable function, Ioc hash, error control
#==============================================================================================================================

#libraries
import hashlib
from pathlib import Path

#function
def calculate_sha256(filename):
    try:
        with open (filename, "rb") as file:
            data = file.read()

            return hashlib.sha256(data).hexdigest()
    except OSError as error:
        print(f"Error handling {filename}: {error}")
        return None

#iocs
known_ioc = {
    "b4653cac0adf789a5c180c1e5e8aefa0c1262bbd1baf44d1bcb385e536602127",
    "843cf12c8e68da40f9d2b755e3d76fe86250b8b941f3cd48525296f71605b4b2"
}

#counters
error = 0
files_scanned = 0
ioc_matched = 0


samples = Path("samples")

#rules_&_analysis
print("========== COMPLETE SCAN ANALYSIS ==========\n")
if samples.is_dir():
    for item in samples.iterdir():
        
        #process regular files only
        if not item.is_file():
            continue
            
        hash_value = calculate_sha256(item)

        #handle failed hashing
        if hash_value is None:
            error += 1
            print(f"Status: unable to analyze {item.name}\n")
            continue

        #hash calculated successfully
        files_scanned += 1

        print(f"FileName: {item.name}")
        print(f"SHA-256: {hash_value}")

        #check for ioc match
        if hash_value in known_ioc:
            ioc_matched += 1
            print(f"Status: IOC matched!\n")
        else:
            print(f"Status: IOC_not_matched\n")
       
else:
    print("ERROR: Sample directory not found")
            
#summary
print("========== SCAN SUMMARY ==========\n")
print(f"Files successfully scanned: {files_scanned}")
print(f"IOC matched: {ioc_matched}")
print(f"Files that could not be analysed: {error}")
        
