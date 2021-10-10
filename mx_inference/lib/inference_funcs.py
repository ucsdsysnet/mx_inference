""" This file contains static methods to infer the provider ID of a domain
"""
from mx_inference.lib.extract_domain import registered_domain_of_fqdn
from mx_inference.lib.ds import ProviderID

class IDFromData():
    # One domain could have multiple MX records that belong to different providers
    # While we are not sure how this works, we treat all providers as valid.
    # Infer one MX at a time
    @staticmethod
    def infer(mx, stats = None):
        pass
    
    
class IDFromMX(IDFromData):
    @staticmethod
    def infer(mx, stats = None):
        # confidence score
        confidence_score = 1
        # inferred id from cert
        provider_id = registered_domain_of_fqdn(mx.get_mx_str())
        if provider_id == "":
            ProviderID(None, "CANNOT_EXTRACT_RD_FROM_MX", "None", "Cannot extract rd of MX", None)
        else:
            return ProviderID(provider_id, "OK", "MX", "MX RD Ok", confidence_score)
        
        if provider_id == None:
            return ProviderID(None, "NO_MX_WITH_SMTP", "None", "Cannot find an MX record with smtp servers", None)
            

class IDFromBanner(IDFromData):
    @staticmethod
    def infer(mx, stats = None):
        # Other optional stats
        cnt_ip = None if 'cnt_ip' not in stats else stats['cnt_ip']
        cnt_mx = None if 'cnt_mx' not in stats else stats['cnt_mx']

        # confidence score
        confidence_score = 1
        # inferred id from cert
        provider_id = None
        for ip in mx.get_ips():
            banner_rd = ip.get_valid_banner_rd()
            if banner_rd != None:
                if provider_id == None:
                    provider_id = banner_rd

                if provider_id != banner_rd:
                    return ProviderID(None, "ID_DONT_AGREE", "NONE", "ID Don't Agree: {} (pre) {} (cur)".format(provider_id,banner_rd), None)
                else:
                    if cnt_ip != None:
                        confidence_score = max(confidence_score, cnt_ip[ip.get_ip_str()])
                    if cnt_mx != None:
                        confidence_score = max(confidence_score, cnt_mx[mx.get_mx_str()])
            
            ehlo_rd = ip.get_valid_ehlo_rd()
            if ehlo_rd != None:
                if provider_id == None:
                    provider_id = ehlo_rd
                
                if provider_id != ehlo_rd:
                    return ProviderID(None, "ID_DONT_AGREE", "NONE", "ID Don't Agree: {} (pre) {} (cur)".format(provider_id,ehlo_rd), None)
                else:
                    if cnt_ip != None:
                        confidence_score = max(confidence_score, cnt_ip[ip.get_ip_str()])
                    if cnt_mx != None:
                        confidence_score = max(confidence_score, cnt_mx[mx.get_mx_str()])

        if provider_id == None:
            return ProviderID(None, "NO_VALID_BANNER_OR_EHLO", "NONE", "Can't find valid domains in banner/ehlo messages", None)
        else:
            return ProviderID(provider_id, "OK", "Banner/EHLO", "Banner/EHLO ID Ok", confidence_score)

class IDFromTLS(IDFromData):
    @staticmethod
    def infer(mx, stats = None):
        if stats == None or 'cert_fqdn_to_group_name' not in stats:
            raise Exception("No Cert Group Info")

        cert_fqdn_to_group_name = stats['cert_fqdn_to_group_name']

        # Other optional stats
        cnt_ip = None if 'cnt_ip' not in stats else stats['cnt_ip']
        cnt_cert_rd = None if 'cnt_cert_rd' not in stats else stats['cnt_cert_rd']

        # confidence score
        confidence_score = 1
        # inferred id from cert
        cert_id = None
        for ip in mx.get_ips():
            for fqdn in ip.get_valid_cert_fqdns():
                fqdn_id = cert_fqdn_to_group_name[fqdn]
                if cert_id == None:
                    cert_id = fqdn_id
                else:
                    if cert_id != fqdn_id:
                        return ProviderID(None, "ID_DONT_AGREE", "NONE", "ID Don't Agree: {} (pre) {} (cur)".format(cert_id,fqdn), None)
                    if cnt_ip != None:
                        confidence_score = max(confidence_score, cnt_ip[ip.get_ip_str()])
                    if cnt_cert_rd != None:
                        confidence_score = max(confidence_score, cnt_cert_rd[fqdn_id])

        if cert_id == None:
            return ProviderID(None, "NO_VALID_FQDN_IN_CERT", "NONE", "Can't find valid cert or fqdn", None)
        else:
            return ProviderID(cert_id, "OK", "TLS", "Cert ID Ok", confidence_score) 

        