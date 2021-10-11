"""
This file contains network functions

scan_domain: Scan a domain and save all the information
scan_mx: Scan a given MX record
scan_ip: Scan an IP

verify_certificate_chain: verify if a cert is browser trusted (by Mozilla/Firefox)

"""

import dns.resolver
import subprocess
import socket
import ssl
import OpenSSL
import smtplib
import os 
from subprocess import Popen, PIPE
from os import listdir
from os.path import isfile, join
from datetime import datetime

from mx_inference.lib.cert import update_cert_data
from mx_inference.lib.ds import CertData, SMTPData, IPData, MXData, DomainData
from mx_inference.lib.extract_domain import extract_valid_fqdns_from_cert

my_resolver = dns.resolver.Resolver(configure=False)
my_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

def scan_domain(domain_name):
    """Scan a domain and save all the information

    Parameters
    ----------
    domain_name : str
        The domain to scan
    """

    domain_data = DomainData(domain_name)
    
    # check for MX records
    raw_mx_records = query_dns(domain_name, 'MX')

    if len(raw_mx_records) == 0:
        return domain_data

    # sort MX by prefrence
    raw_mx_records = sorted(raw_mx_records, key=lambda x: int(x.preference))
    
    for raw_mx_record in raw_mx_records:
        # Read MX and Preference
        mx_address = raw_mx_record.exchange.to_text().strip().strip(".")
        mx_preference = int(raw_mx_record.preference)
        mx_data = scan_mx(mx_address, mx_preference)
        domain_data.add_parsed_mx(mx_data)
    
    return domain_data

def scan_mx(mx_address, mx_preference = 0):
    """Scan a given MX record

    Parameters
    ----------
    mx_address : str
        The MX to scan
    mx_preference : int, optional
        The preference of this MX
    """

    # Create a wrapper
    mx_data = MXData(mx_address, mx_preference)

    # Resolve MX
    raw_ip4_addresses = query_dns(mx_address, 'A')

    # Not resolvable
    if len(raw_ip4_addresses) == 0:
        return mx_data
    
    # Probe each IP
    for raw_ip4_address in raw_ip4_addresses:
        ip_data = scan_ip(raw_ip4_address.address)
        mx_data.add_parsed_ip(ip_data)
    
    return mx_data

def scan_ip(ipv4_address):
    """Scan an IP

    Parameters
    ----------
    ipv4_address : str
        The ip address to scan. Only tested on ipv4 addresses
    """

    # Create wrapper
    ip_data = IPData(ipv4_address, as_number = as_number_of_ip(ipv4_address))
    
    # try retrieve banner/ehlo, create a table if the IP still exists
    banner, ehlo, x509, debug_message = _smtp_port_scan(ipv4_address)
    
    ip_data.set_debug_message(debug_message)
    if banner == None and ehlo == None:
        return ip_data
                    
    # ehlo and banner in two iters
    smtp_data = SMTPData()
    ip_data.add_parsed_smtp_data(smtp_data)

    for raw, key in zip([banner, ehlo], ('banner','ehlo')):
        if raw == None:
            continue

        if key == 'ehlo':
            smtp_data.add_ehlo_message(raw)
        else:
            smtp_data.add_banner_message(raw)
    
    # Try scan smtp
    x509_debug_msg = "no_x509"
    if x509 != None:
        # create wrapper
        cert_data = CertData(raw_cert = x509)
        ip_data.add_parsed_cert_data(cert_data)

        # Set is_browser_trusted
        is_browser_trusted, x509_debug_msg = verify_certificate_chain(x509)
        cert_data.set_browser_trusted(is_browser_trusted)
        cert_data.set_debug_message(x509_debug_msg.replace('"',"").replace('"',""))

        # Extract all domain names
        valid_fqdns = extract_valid_fqdns_from_cert(x509)
        cert_data.set_valid_fqdns(valid_fqdns)
    
    return ip_data


## openssl verify -CAfile certs/Root_CA.pem -untrusted certs/Intermediate_CA.pem  unverified_cert.pem ##
def verify_certificate_chain(cert_to_verify):
    """ Verify if a cert is browser trusted (by Mozilla)

    We use the external command: 
        openssl verify -CAfile certs/Root_CA.pem -untrusted certs/Intermediate_CA.pem  pem_to_verify.pem
    """

    cert_dir = os.path.dirname(os.path.abspath(__file__)) + "/certs"
    if (not os.path.exists("{}/Root_CA.pem".format(cert_dir))) or (not os.path.exists("{}/Intermediate_CA.pem".format(cert_dir))):
        print("CA Pem file missing, Downloading!")
        update_cert_data()

    tmp_pem_path = "{}/pem_to_verify.pem".format(cert_dir)
    browser_trusted = False
    debug_msg = ""

    # Return true/false + msg
    try:
        with open(tmp_pem_path, "w") as f:
            f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_to_verify).decode("ascii"))

        process = Popen("openssl verify -CAfile {0}/Root_CA.pem -untrusted {0}/Intermediate_CA.pem {0}/pem_to_verify.pem".format(cert_dir), shell = True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        stdout = stdout.decode()
        stderr = stderr.decode()
        output = stdout + stderr
        
        if "{}: OK".format(tmp_pem_path) in output:
            browser_trusted = True
            debug_msg = "OK"
        else:
            browser_trusted = False
            debug_msg = output.split("\n")[-3].replace("\t"," ")

    except subprocess.CalledProcessError as e:
        browser_trusted = False
        debug_msg = e.output.decode("ascii").split("\n")[-3].replace("\t"," ")
    
    finally:
        if os.path.exists(tmp_pem_path):
            os.remove(tmp_pem_path)
    
    return browser_trusted, debug_msg

# Scan an IP and try extracting information
def _smtp_port_scan(ip, port=25, local_server_name = 'seldusaer.dev', timeout=30):
    connection = None
    banner = None
    ehlo = None


    x509 = None
    message = None
    try:
        connection = smtplib.SMTP(ip, timeout = timeout)
        banner_raw = connection.connect(ip, port)
        banner = " ".join([str(banner_raw[0]), banner_raw[1].decode('ascii')])
        banner = banner.replace("\t"," ").replace('"',"").replace("'","")

        ehlo_raw = connection.ehlo(name=local_server_name)
        ehlo = " ".join([str(ehlo_raw[0]), ehlo_raw[1].decode('ascii')])
        ehlo = ehlo.replace("\t"," ").replace('"',"").replace("'","")

        connection.starttls()
        cert = ssl.DER_cert_to_PEM_cert(connection.sock.getpeercert(binary_form=True))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).to_cryptography()
        message = "OK"
    
    # Timeout, return nothing
    except socket.timeout:
        banner = None
        ehlo = None
        message = "Connection Timeout"

    except Exception as e:
        message = repr(e).replace("\t"," ").replace('"',"").replace("'","")
    
    finally:
        try:
            connection.quit()
        except:
            pass
        
        return banner, ehlo, x509, message.replace("\t"," ").replace('"',"").replace("'","")

def query_dns(query_name, query_type):
    # Send a dns query
    try:
        results = my_resolver.query(query_name, query_type)
        return list(results)
    except:
        return []

def as_number_of_ip(ip):
    # Try resolving the AS number of an IP
    asns_top = query_dns("{}.origin.asn.cymru.com".format(".".join(reversed(ip.split('.')))),"TXT")
    if len(asns_top) > 0:
        asns = asns_top[0].to_text().strip('"').split("|")[0]
        if " " not in asns:
            asns_top = int(asns.strip())
        else:
            asns_top = int(asns.split(" ")[0].strip())

    else:
        asns_top = None
    
    return asns_top

if __name__ == "__main__":
    print(scan_domain('ucsd.edu'))
