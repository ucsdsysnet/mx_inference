""" This file contains data structure used in this project
"""

from mx_inference.lib.extract_domain import extract_domain_from_banner_or_ehlo_text
from mx_inference.config.config import CONFIG

from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL import crypto

# Wraps results for Heuristics
class HeuristicData():
    def __init__(self):
        self.new_provider_id = None
        self.corrected = 0 # 0 means not corrected, -1 means not the provider id, 1 means the provider id might be new_provider_id
        self.msg = ""
    
    def is_corrected(self):
        return self.corrected != 0

# Wraps information associated with provider id
class ProviderID():
    # provider_id,provider_id_type,source,msg are strings
    # score is int
    def __init__(self,provider_id,provider_id_type,source,msg,score):
        self.provider_id = provider_id
        self.provider_id_type = provider_id_type
        self.source = source
        self.msg = msg
        self.score = score
        self.heuristics_obj = HeuristicData() # Place holder for heuristics_obj 
        self.company_id = None # Place holder for inferred company data
    
    def __str__(self):
        string = ""
        if self.heuristics_obj.is_corrected():
            if CONFIG['DEBUG_LEVEL'] == 0:
                string += "ID:{}, Type:{}, Source:{}, Conf_Score:{}\n".format(self.provider_id, self.provider_id_type, self.source, self.score)
            elif CONFIG['DEBUG_LEVEL'] == 1:
                string += "ID:{}, Type:{}, Source:{}, Conf_Score:{}\n".format(self.provider_id, self.provider_id_type, self.source, self.score)
            else:
                string += "ID:{}, Type:{}, Source:{}, Conf_Score:{}, Debug MSG:{}\n".format(self.provider_id, self.provider_id_type, self.source, self.score, self.msg)
            
            # provider_id misleading, should use the new one
            if self.heuristics_obj.corrected == 1:
                string += "\tHeuristics suggests new provider id: {}, reason: {}\n".format(self.heuristics_obj.new_provider_id, self.heuristics_obj.msg)
                if self.company_id != None:
                    string += "\tSuggested company: {}\n".format(self.company_id)
            
            # provider_id misleading, vps
            elif self.heuristics_obj.corrected == -1:
                string += "\tHeuristics suggests that this provider id might NOT be accurate, reason: {}\n".format(self.heuristics_obj.msg)

            else:
                raise Exception("Unhandled")
            
            string += "\n"
        else:
            string += "ID:{}, Type:{}, Source:{}, Debug MSG:{}, Conf_Score:{}\n".format(self.provider_id, self.provider_id_type, self.source, self.msg, self.score)
            if self.company_id != None:
                string += "\tSuggested Company: {}\n".format(self.company_id)
        
            string += "\n"
            
        return string
    
    def get_provider_id_str(self):
        if "OK" in self.provider_id_type:
            return self.provider_id
        return None

    def add_heuristics_obj(self, o):
        self.heuristics_obj = o

    def set_heuristics(self, corrected, new_provider_id = None, msg = None):
        self.heuristics_obj.corrected = corrected
        if new_provider_id != None:
            self.heuristics_obj.new_provider_id = new_provider_id
        if msg != None:
            self.heuristics_obj.msg = msg

    def set_company_id(self, company_id):
        self.company_id = company_id

# Wraps information related to TLS cert
class CertData:
    # Raw cert is the parsed x509 file
    # valid_fqdns are the fqdns contained in the cert, if the cert is valid
    def __init__(self, raw_cert = None, valid_fqdns = [], browser_trusted = False):
        self.raw_cert = raw_cert
        self.valid_fqdns = valid_fqdns
        self.browser_trusted = browser_trusted
        self.debug_message = "no_debug_msg"
    
    def set_browser_trusted(self,browser_trusted):
        self.browser_trusted = browser_trusted
    
    def set_debug_message(self,debug_message):
        self.debug_message = debug_message
    
    def set_valid_fqdns(self, fqdns):
        self.valid_fqdns = fqdns

    def is_browser_trusted(self):
        return self.browser_trusted == True

    def raw_cert_dump_str(self):
        return crypto.dump_certificate(FILETYPE_PEM, self.raw_cert).decode('utf-8')

    def __repr__(self):
        string = ""
        if CONFIG['DEBUG_LEVEL'] == 0:
            string += "Browser Trusted: {}\n".format(self.browser_trusted)
        elif CONFIG['DEBUG_LEVEL'] == 1:
            string += "Browser Trusted: {}, Cert debug message: {}\n".format(self.browser_trusted, self.debug_message)            
        else:
            string += "Browser Trusted: {}, Cert debug message: {}, Raw Cert: {}\n".format(self.browser_trusted, self.debug_message, repr(self.raw_cert))
        return string

# Wraps information related to Banner/EHLO messages
class SMTPData:
    # Save raw banner/ehlo messages as well as extraced banner and ehlo domains
    def __init__(self):
        self.data = {}
    
    def add_banner_message(self, banner_message):
        self.data['banner_message'] = banner_message

        # Further parsing the data
        banner_fqdn, banner_rd, banner_rd_type = extract_domain_from_banner_or_ehlo_text(banner_message)

        self.data['banner_fqdn'] = banner_fqdn
        self.data['banner_rd'] = banner_rd
        self.data['banner_rd_type'] = banner_rd_type
    
    def add_ehlo_message(self, ehlo_message):
        self.data['ehlo_message'] = ehlo_message

        # Further parsing the data
        ehlo_fqdn, ehlo_rd, ehlo_rd_type = extract_domain_from_banner_or_ehlo_text(ehlo_message)

        self.data['ehlo_fqdn'] = ehlo_fqdn
        self.data['ehlo_rd'] = ehlo_rd
        self.data['ehlo_rd_type'] = ehlo_rd_type

    def has_valid_banner_rd(self):
        if 'OK' in self.data['banner_rd_type'] and self.data['banner_rd'] != None:
            return True
        return False

    def get_valid_banner_rd(self):
        if self.has_valid_banner_rd():
            return self.data['banner_rd']
        return None

    def get_valid_banner_fqdn(self):
        if self.has_valid_banner_rd():
            return self.data['banner_fqdn']
        return None



    def has_valid_ehlo_rd(self):
        if 'OK' in self.data['ehlo_rd_type'] and self.data['ehlo_rd'] != None:
            return True
        return False

    def get_valid_ehlo_rd(self):
        if self.has_valid_ehlo_rd():
            return self.data['ehlo_rd']
        return None

    def get_valid_ehlo_fqdn(self):
        if self.has_valid_ehlo_rd():
            return self.data['ehlo_fqdn']
        return None
        

    def has_ehlo_message(self):
        return 'ehlo_message' in self.data


    def get_ehlo_message(self):
        if 'ehlo_message' not in self.data:
            raise Exception('Get EHLO error')
        return self.data['ehlo_message']
    
    def has_banner_message(self):
        return 'banner_message' in self.data
    

    def get_banner_message(self):
        if 'banner_message' not in self.data:
            raise Exception('Get Banner error')
        return self.data['banner_message']
    
    def __repr__(self):
        string = ""
        if CONFIG['DEBUG_LEVEL'] == 0:
            string += "Banner RD: {}\n".format(self.data['banner_rd'])
            string += "EHLO RD: {}\n".format(self.data['ehlo_rd'])
        elif CONFIG['DEBUG_LEVEL'] == 1:
            string += "Banner RD: {} Banner RD Type: {}\n".format(self.data['banner_rd'],self.data['banner_rd_type'])
            string += "EHLO RD: {} EHLO RD Type:{}\n".format(self.data['ehlo_rd'],self.data['ehlo_rd_type'])
        else:
            string += "Banner RD: {} Banner RD Type: {} Banner Message: {}\n".format(self.data['banner_rd'],self.data['banner_rd_type'],repr(self.data['banner_message']) if 'banner_message' in self.data else "None")
            string += "EHLO RD: {} EHLO RD Type:{} EHLO Message: {}\n".format(self.data['ehlo_rd'],self.data['ehlo_rd_type'],repr(self.data['ehlo_message']) if 'ehlo_message' in self.data else "None")

        return string
        

# Wraps information associated with an IP
class IPData:
    # ipv4_address is a string
    def __init__(self, ipv4_address, as_number = None, smtp_data = None, cert_data = None, port_scan_debug_msg = "no_debug_message"):
        self.ipv4_address = ipv4_address
        self.as_number = as_number
        self.cert_data = cert_data
        self.smtp_data = smtp_data
        self.port_scan_debug_msg = port_scan_debug_msg
    
    def add_parsed_smtp_data(self, smtp_data):
        self.smtp_data = smtp_data
    
    def add_parsed_cert_data(self, cert_data):
        self.cert_data = cert_data

    def set_debug_message(self, debug_message):
        self.port_scan_debug_message = debug_message

    def __repr__(self):
        string = ""
        string += "IPv4: {}, ASN: {}\n".format(self.ipv4_address, self.as_number)
        if self.smtp_data != None:
            string += ''.join(['\t' + i for i in str(self.smtp_data).splitlines(True)])
        if self.cert_data != None:
            string += ''.join(['\t' + i for i in str(self.cert_data).splitlines(True)])
        return string

    def has_smtp(self):
        if self.smtp_data != None or self.cert_data != None:
            return True
        return False

    def get_ip_str(self):
        return self.ipv4_address

    # Return valid cert fqdns
    def get_valid_cert_fqdns(self):
        if self.cert_data != None:
            if self.cert_data.is_browser_trusted():
                return self.cert_data.valid_fqdns
        
        return []

    def has_valid_ehlo_rd(self):
        if self.smtp_data != None and self.smtp_data.has_valid_ehlo_rd():
            return True
        
        return False
    
    def has_valid_banner_rd(self):
        if self.smtp_data != None and self.smtp_data.has_valid_banner_rd():
            return True
        
        return False 

    # Return banner fqdn
    def get_valid_banner_rd(self):
        return self.smtp_data.get_valid_banner_rd()

    def get_valid_banner_fqdn(self):
        return self.smtp_data.get_valid_banner_fqdn()

        
    # Return ehlo rd
    def get_valid_ehlo_rd(self):
        return self.smtp_data.get_valid_ehlo_rd()

    def get_valid_ehlo_fqdn(self):
        return self.smtp_data.get_valid_ehlo_fqdn()

# Wraps information associated with an MX
class MXData:
    # mx_record is a string
    def __init__(self, mx_record, pref = 0, ips = []):
        self.mx_record = mx_record
        self.pref = pref
        self.ips = []
        self.pid = None # Each MX will have a provider ID. 
    
    def add_parsed_ip(self, ip_data):
        self.ips.append(ip_data)

    def __repr__(self):
        string = ""
        string += "MX: {}, Pref:{}\n".format(self.mx_record, self.pref)
        for ip in self.ips:
            string += ''.join(['\t' + i for i in str(ip).splitlines(True)])
        return string

    def has_smtp(self):
        for ip in self.ips:
            if ip.has_smtp():
                return True
        return False

    # Remove IPs that don't have smtp data (dead)
    def get_cleaned_mx(self):
        filter_mx = MXData(self.mx_record, self.pref)
        for ip in self.ips:
            if ip.has_smtp():
                filter_mx.add_parsed_ip(ip)
        return filter_mx

    def get_mx_str(self):
        return self.mx_record

    def get_pref(self):
        return self.pref

    def get_ips(self):
        return self.ips

    
# Wraps information associated with a domain
class DomainData:
    # domain_name is a string
    def __init__(self, domain_name, mx_records = []):
        self.domain_name = domain_name
        self.mx_records = []
        self.pids = None # Place holder for inferred provider ids (each MX has one id, each domain can have multiple pids)
        self.primary_mx_records_with_smtp = None

    def add_parsed_mx(self, mx_record):
        self.mx_records.append(mx_record)

    # Compute a list of most preferred MX records that have SMTP, 
        # Return [] if no such MX exists
    def compute_primary_mx_records_with_smtp(self):
        if self.primary_mx_records_with_smtp != None:
            return 
        
        self.primary_mx_records_with_smtp = []
        prioirty_of_most_preferred_mx_with_smtp = float('inf')
        
        for mx_record in self.mx_records:
            if mx_record.has_smtp():
                if mx_record.get_pref() < prioirty_of_most_preferred_mx_with_smtp:
                    prioirty_of_most_preferred_mx_with_smtp = mx_record.get_pref()
        
        if prioirty_of_most_preferred_mx_with_smtp == float('inf'):
            return []


        
        # Use a clean set of MX records that are filtered
        for mx_record in self.mx_records:
            if mx_record.get_pref() == prioirty_of_most_preferred_mx_with_smtp:
                self.primary_mx_records_with_smtp.append(mx_record.get_cleaned_mx())
        
    # Return a list of most preferred MX records that have SMTP, 
        # Return [] if no such MX exists
    def get_most_preferred_mx_records_with_smtp(self):
        if self.primary_mx_records_with_smtp == None:
            self.compute_primary_mx_records_with_smtp()
        return self.primary_mx_records_with_smtp

    def add_pid(self, pid):
        if self.pids == None:
            self.pids = []
        self.pids.append(pid)

    def __repr__(self):
        string = ""
        string += "Domain: {}\n".format(self.domain_name)

        # Print any pid data if available
        if self.pids == None or len(self.pids) == 0:
            string += "\tInfered Provider ID: N/A\n\n"
        else:
            for self.pid in self.pids:
                string += ''.join(['\t' + i for i in str(self.pid).splitlines(True)])

        if CONFIG['DEBUG_LEVEL'] == 0:
            output_mx = self.get_most_preferred_mx_records_with_smtp()
        else:
            output_mx = self.mx_records

        for mx_record in output_mx:
            string += ''.join(['\t' + i for i in str(mx_record).splitlines(True)])

        return string
