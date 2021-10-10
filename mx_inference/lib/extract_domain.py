""" This file contains functions used to extract domains from a string """
from mx_inference.config.config import CONFIG

import re
import tldextract
import cryptography



extract = tldextract.TLDExtract(include_psl_private_domains=True)
extract.update()

registered_domain_pattern = re.compile("^([a-zA-Z0-9\-_]([a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9\-_])?\.)+[a-zA-Z]{2,}$")
strip_symbols = ":,;!."

# If we extract these domains, very likely we are wrong.
common_misleading_domains = [".spamhaus.org",".abuseat.org",".trustedsource.org","eecs.umich.edu"]

def extract_domain_from_banner_or_ehlo_text(text):
    """ ehlo string, a dict """
    domain, domain_rd, domain_type = None, None, "NONE"


    # Bug fix text == "". Nothing can be extracted
    if text == "" or text == None or type(text) != str:
        return None, None, "NONE"

    # Best scenario
    texts = [i.strip() for i in text.split("\n") if i.strip().strip(strip_symbols).strip() != ""]
    # Nothing can be extracted
    if len(texts) == 0:
        return None, None, "NONE"

    domain, domain_rd, domain_type = try_extract_domain_from_the_beginning(texts[0])
    if domain != None:
        return domain.lower(), domain_rd.lower(), domain_type

    # Handle corner cases...
    domain, domain_rd, domain_type = try_extract_domain_from_the_end(texts[0])
    if domain != None:
        return domain.lower(), domain_rd.lower(), domain_type
    
    return None, None, "NONE"

def try_extract_domain_from_the_beginning(initial_msg):

    # too short
    if len(initial_msg) < 3:
        return None, None, "NONE"

    if initial_msg[0].isdigit() == True and initial_msg[1].isdigit() == True and initial_msg[2].isdigit() == True:
        code = initial_msg[:3]
        if code == initial_msg:
            # Not enough information
            domain = None
            return None, None, "NONE"

        # Best scenario 1
        if initial_msg[3] == "-":
            # strip : for corner case
            domain = initial_msg.split(" ")[0][4:].strip(strip_symbols)
            
            # Add special case for eigbox.net
            if "bosimpinc" in domain:
                domain = "eigbox.net"
                return domain, domain, "OK_EIG_SPECIAL"
                
            # Potentially a domain, three expressions reduce false positives
            if registered_domain_pattern.match(domain) != None:
                # corner cases
                for misleading_domain in common_misleading_domains:
                    if misleading_domain in domain:
                        return None, None, "NONE"

                # real domain
                if extract(domain).registered_domain != "":
                    return domain, extract(domain).registered_domain, "OK"
                # private tld only like test.ru
                elif extract(domain).suffix != "":
                    return domain, domain, "PRIVATE_TLD"
                # not necessarily a real domain
                else:
                    return domain, domain, "PSEUDO"
            else:
                # print("Not A Domain:{}\t{}".format(domain, initial_msg))
                return None, None, "NONE"

        # Best scenario 2
        elif initial_msg[3] == " ":
            domain = initial_msg.split(" ")[1].strip(strip_symbols)
            
            # Add special case for eigbox.net
            if "bosimpinc" in domain:
                domain = "eigbox.net"
                return domain, domain, "OK_EIG_SPECIAL"

            # Potentially a domain, three expressions reduce false positives
            if registered_domain_pattern.match(domain) != None:
                # corner cases
                for misleading_domain in common_misleading_domains:
                    if misleading_domain in domain:
                        return None, None, "NONE"

                # real domain
                if extract(domain).registered_domain != "":
                    return domain, extract(domain).registered_domain, "OK"
                # private tld only like test.ru
                elif extract(domain).suffix != "":
                    return domain, domain, "PRIVATE_TLD"
                # not necessarily a real domain
                else:
                    return domain, domain, "PSEUDO"
            else:
                #print("Not A Domain:{}\t{}".format(domain, initial_msg))
                return None, None, "NONE"
        
        # not conforming to the protocol
        else:
            return None, None, "NONE"
    
    return None, None, "NONE"

def try_extract_domain_from_the_end(last_message):
    if " " in last_message:
        segments = [i.strip().strip(strip_symbols).strip() for i in last_message.split(" ") if i.strip().strip(strip_symbols).strip() != ""]
        domain = segments[-1]
    else:
        domain = last_message
    # Potentially a domain, three expressions reduce false positives
    if registered_domain_pattern.match(domain) != None:
        # corner cases
        for misleading_domain in common_misleading_domains:
            if misleading_domain in domain:
                return None, None, "NONE"
        

        # real domain
        if extract(domain).registered_domain != "":
            return domain, extract(domain).registered_domain, "OK"
        # private tld only like test.ru
        elif extract(domain).suffix != "":
            return domain, domain, "PRIVATE_TLD"
        # not necessarily a real domain
        else:
            return domain, domain, "PSEUDO"

    return None, None, "NONE"


# Extract all valid fqdns from a cert
def extract_valid_fqdns_from_cert(cert):
    all_names = []
    cn = None
    try:
        cn = cert.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)[0].value
        if "." not in cn:
            cn = None
    except Exception as e:
        cn = None
    
    # get san
    sans = []
    try:
        san = cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName)
        sans = san.value.get_values_for_type(cryptography.x509.DNSName)
    except Exception as e:
        #print(e)
        sans = []
    
    if cn != None:
        all_names.append(cn)
    if len(sans) != 0:
        for sa in sans:
            if sa not in all_names:
                all_names.append(sa)

    valid_fqdns = set()
    for name in all_names:
        rd = registered_domain_of_fqdn(name)
        if rd != "":
            valid_fqdns.add(name)
    valid_fqdns = sorted(list(valid_fqdns))

    return valid_fqdns

def registered_domain_of_fqdn(fqdn):
    return extract(fqdn).registered_domain

# ref: https://leetcode.com/problems/wildcard-matching/discuss/17810/Linear-runtime-and-constant-space-solution
def regex_match(text, pattern):
    s = 0
    p = 0
    match = 0
    starIdx = -1
    while (s < len(text)):
        if p < len(pattern) and text[s] == pattern[p]:
            s += 1
            p += 1
        elif p < len(pattern) and pattern[p] == "*":
            starIdx = p
            match = s
            p += 1
        elif starIdx != -1:
            p = starIdx + 1
            match += 1
            s = match
        else:
            return False
    
    while p < len(pattern) and pattern[p] == '*':
        p += 1
    
    return p == len(pattern)