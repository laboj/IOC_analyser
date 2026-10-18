#===========================================================================
#author@laboj
#date@17-10-2026
#lesson: hashlib
#description: import hashlib, multiple IOCs, file hash match detection
#===========================================================================

#libraries
import hashlib
from pathlib import Path

#IOCs
known_iocs = {
    "a0e5558ee799fdae87722e7e8214b63041304ffdeb1b8e6dc3bdb7a1a779878a",
    "5039ba2524a81bfa362c007dd854bf9fce2bbfa0ca61fbc5740638ab20a7c319"
}

#function
def calculate_sha256(filename):
    with open (filename, "rb") as file:
        data = file.read()

        hash_object = hashlib.sha256(data)
        hash_value = hash_object.hexdigest()
        return hash_value

#analysis report
samples = Path("samples")
print("========== FILE IOC ANALYSIS ==========\n")
if samples.is_dir():
    for item in samples.iterdir():
        if item.is_file():
            hash_figure = calculate_sha256(item)
            print(f"File: {item.name}")
            print(f"Size: {item.stat().st_size} bytes")
            print(f"SHA-256: {hash_figure}")
        if hash_figure in known_iocs:
            print("Status: WARNING, IOC matched\n")
        else:
            print("Status: No IOC matched\n")


