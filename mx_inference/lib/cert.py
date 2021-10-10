""" This file manages root and intermediate certificates.

More information: https://wiki.mozilla.org/CA

Intermedia CA PEM retrieved from:
    https://ccadb-public.secure.force.com/mozilla/PublicAllIntermediateCertsWithPEMCSV
    

Root CA PEM retrieved from:
    https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMCSV?TrustBitsInclude=Websites
"""

import urllib.request
import os
import csv

from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import X509Store, X509StoreContext

# Read pem from CSV file
def extract_pem_from_csv(input_f, output_f):
    ls = []
    with open(input_f) as f:
        reader = csv.reader(f, delimiter=',', quotechar='"')
        for row in reader:
            ls.append(row)

    with open(output_f,"w") as f:
        for row in ls:
            f.write(row[-1].strip("'")+"\n")

# If cert data doesn't exist, download cert data
def update_cert_data():
    try:
        cert_dir = os.path.dirname(os.path.abspath(__file__)) + "/certs"

        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir) 
        
        print("Updating Root CA Data")
        urllib.request.urlretrieve('https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMCSV?TrustBitsInclude=Websites', '{}/Root_CA_PEM.csv'.format(cert_dir))
        extract_pem_from_csv("{}/Root_CA_PEM.csv".format(cert_dir), "{}/Root_CA.pem".format(cert_dir))
        
        print("Updating Intermedia CA Data")
        urllib.request.urlretrieve('https://ccadb-public.secure.force.com/mozilla/PublicAllIntermediateCertsWithPEMCSV', '{}/Intermediate_CA_PEM.csv'.format(cert_dir))
        extract_pem_from_csv("{}/Intermediate_CA_PEM.csv".format(cert_dir), "{}/Intermediate_CA.pem".format(cert_dir))
    except:
        print("Updating CA Data Error!")

