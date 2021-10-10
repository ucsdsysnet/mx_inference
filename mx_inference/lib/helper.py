""" This file contains a list of helper functions for IO"""
import csv 
import cryptography

from collections import defaultdict
from cryptography.hazmat.backends import default_backend
from mx_inference.lib.ds import CertData, SMTPData, IPData, MXData, DomainData

def truncate_string(string, width = 1000):
    if len(string) > width:
        string = string[:width-3] + '...'
    return string

# Write a list of records to csv    
def dump_list_of_records_to_csv(records, output_file, headers = ["domain_name","mx","mx_pref","ip_of_mx","asn_of_ip","dict_scanning_data"], delimiter = '\t'):
    with open('{}'.format(output_file), 'w') as f:
        # using csv.writer method from CSV package
        write = csv.writer(f,delimiter=delimiter)
        write.writerow(headers)
        write.writerows(records)


def convert_domain_object_to_list_of_records_format_censys(domain_data):
    """ This func dumps information in a DomainData object to a list of records, and each record itself is a list.

    Items in each record:
        Domain name : str
        MX : str or None
        MX Preference : int or None
        IPv4 of MX : str or None
        ASN of IPv4 : int or None
        ip_info_p25 : dict or None
    """

    result_list = []

    domain_name = domain_data.domain_name

    has_mx = False
    for mx_record in domain_data.mx_records:
        has_mx = True

        current_mx = mx_record.mx_record
        current_mx_pref = mx_record.pref

        has_ip = False
        for ip in mx_record.ips:
            has_ip = True

            current_ip = ip.ipv4_address
            current_ip_asn = int(ip.as_number) if ip.as_number != None else None
            current_cert = ip.cert_data
            current_smtp = ip.smtp_data
            
            # Construct port 25 data
            p_25_dict = None
            if current_smtp != None or current_cert != None:
                p_25_dict = {}
                p_25_dict['smtp'] = {}
                p_25_dict['smtp']['starttls'] = {}

                if current_smtp != None and current_smtp.has_banner_message():
                    p_25_dict['smtp']['starttls']['banner'] = current_smtp.get_banner_message()
                
                if current_smtp != None and current_smtp.has_ehlo_message():
                    p_25_dict['smtp']['starttls']['ehlo'] = current_smtp.get_ehlo_message()
                
                if current_cert != None:
                    p_25_dict['smtp']['starttls']['tls'] = {}
                    p_25_dict['smtp']['starttls']['tls']["certificate"] = {}
                    p_25_dict['smtp']['starttls']['tls']["certificate"]['raw'] = current_cert.raw_cert_dump_str()
                    p_25_dict['smtp']['starttls']['tls']["certificate"]["parsed"] = {}
                    p_25_dict['smtp']['starttls']['tls']["certificate"]["parsed"]["names"] = current_cert.valid_fqdns
                    p_25_dict['smtp']['starttls']['tls']["validation"] = {}
                    p_25_dict['smtp']['starttls']['tls']["validation"]["browser_trusted"] = current_cert.browser_trusted
                    p_25_dict['smtp']['x509_msg'] = current_cert.debug_message
                
                p_25_dict['smtp']['port_scan_msg'] = ip.port_scan_debug_message
            
            result_list.append((domain_name, current_mx, current_mx_pref, current_ip, current_ip_asn, p_25_dict))

        # No IP for an MX
        if has_ip == False:
            result_list.append((domain_name, current_mx, current_mx_pref, None, None, None))

    # No MX at all
    if has_mx == False:
        result_list.append((domain_name, None, None, None, None, None))
    
    return result_list




# Dump data to csv in censys format
def dump_domain_data_to_csv_format_censys(domains, output_file, headers = ["domain_name","mx","mx_pref","ip_of_mx","asn_of_ip","dict_scanning_data"], delimiter = '\t'):
    records = []
    for domain_data in domains:
        records += convert_domain_object_to_list_of_records_format_censys(domain_data)
    dump_list_of_records_to_csv(records, output_file, headers, delimiter)


def _read_records_of_one_domain(filepath, has_header = True, delimiter = '\t'):
    current_domain = None
    current_records = []
    with open(filepath, newline='') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=delimiter)
        if has_header == True:
            next(csvreader)
        for record in csvreader:
            domain_name, mx, mx_pref, ip_of_mx, asn_of_ip, dict_scanning_data = record
            if current_domain == None:
                current_domain = domain_name
                current_records.append(record)
                continue
            elif current_domain != None and current_domain == domain_name:
                current_records.append(record)
                continue
            else:
                yield current_domain, current_records
                current_domain = domain_name
                current_records = []
                current_records.append(record)
    
    if len(current_records) != 0:
        yield current_domain, current_records
            
def _parse_dict_scanning_data(raw):
    
    smtp_data, cert_data = None, None
    if raw == None:
        return smtp_data, cert_data

    raw = eval(raw)
    
    if 'banner' in raw['smtp']['starttls'] or 'ehlo' in raw['smtp']['starttls']:
        smtp_data = SMTPData()
        if 'banner' in raw['smtp']['starttls']:
            banner_message = raw['smtp']['starttls']['banner']
            smtp_data.add_banner_message(banner_message)
        if 'ehlo' in raw['smtp']['starttls']:
            ehlo_message = raw['smtp']['starttls']['ehlo']
            smtp_data.add_ehlo_message(ehlo_message)       

    if 'tls' in raw['smtp']['starttls']:
        x509 = cryptography.x509.load_pem_x509_certificate(raw['smtp']['starttls']['tls']["certificate"]['raw'].encode(), default_backend())
        cert_data = CertData(raw_cert = x509)
        cert_data.set_debug_message(raw['smtp']['x509_msg'])
        cert_data.set_valid_fqdns(raw['smtp']['starttls']['tls']['certificate']['parsed']['names'])
        browser_trusted = raw['smtp']['starttls']['tls']["validation"]["browser_trusted"]
        cert_data.set_browser_trusted(bool(browser_trusted))

    return smtp_data, cert_data

# Load data from path in censys format
def load_domain_data_from_path_format_censys(filepath, has_header = True, delimiter = '\t'):
    domain_objs = []
    for domain_name, records in _read_records_of_one_domain(filepath, has_header, delimiter):
        mx_records_to_data = defaultdict(lambda: {})
        

        if domain_name != None:
            domain_data = DomainData(domain_name)

        for record in records:
            domain_name, mx, mx_pref, ip_of_mx, asn_of_ip, dict_scanning_data = record
            if mx == "":
                mx = None
            # This should not be none
            if mx_pref == "":
                mx_pref = None
            else:
                mx_pref = int(mx_pref)

            if ip_of_mx == "":
                ip_of_mx = None
            if asn_of_ip == "":
                asn_of_ip = None
            if dict_scanning_data == "":
                dict_scanning_data = None
                
            a = mx_records_to_data[(mx, mx_pref)]
            mx_records_to_data[(mx, mx_pref)][ip_of_mx] = (asn_of_ip, dict_scanning_data)
        
        for mx, mx_pref in mx_records_to_data.keys():
            if mx == None:
                continue
            
            mx_data = MXData(mx, mx_pref)
            domain_data.add_parsed_mx(mx_data)
            
            for ipv4_address in mx_records_to_data[(mx, mx_pref)].keys():
                if ipv4_address == None:
                    continue
                asn, dict_scanning_data = mx_records_to_data[(mx, mx_pref)][ipv4_address]

                # Further process
                if asn != None:
                    asn = int(asn)
                ip_data = IPData(ipv4_address, asn)
                mx_data.add_parsed_ip(ip_data)

                smtp_data, cert_data = _parse_dict_scanning_data(dict_scanning_data)

                if smtp_data != None:
                    ip_data.add_parsed_smtp_data(smtp_data)
                
                if cert_data != None:
                    ip_data.add_parsed_cert_data(cert_data)
                

        domain_objs.append(domain_data)
    
    return domain_objs