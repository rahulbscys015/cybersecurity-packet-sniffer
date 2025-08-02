import tarfile

with tarfile.open("GeoLite2-City.tar.gz", "r:gz") as tar:
    tar.extractall()
    print("[*] Extracted all files")

# Now find the .mmdb file and print path
import os
for root, dirs, files in os.walk("."):
    for name in files:
        if name.endswith(".mmdb"):
            full_path = os.path.join(root, name)
            print("[+] Found DB:", full_path)
