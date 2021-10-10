"""
This file contains various heuristics used to 
    quickly identify false positives (e.g., VPS servers) 
    in inferring the mail provider.

Use the heuristics with a grain of salt.
"""
from mx_inference.lib.extract_domain import regex_match
from mx_inference.config.config import CONFIG
from mx_inference.lib.ds import HeuristicData

# Contains AS in which we observe legitimate mail servers
company_to_as = {
    "AppRiver":(15395, 27357, 33070, 53780, 59519,),
    "Aruba":(31034,),
    "Barracuda":(13009, 15324, 16509, 53292, 56301,),
    "Beget":(198610,),
    "Cisco":(16417, 30215, 30238,),
    "EIG":(19905, 20013, 26337, 29873, 32475, 36024, 36351, 46606, 62729, 394695,), # False positive 40676
    "Fastmail":(11403,201628),
    "FireEye":(8987, 14618, 16509, 17330, 393423),
    "ForcePoint":(7598, 35788, 44444),
    "Gandi":(29169,),
    "GoDaddy":(8972, 20738, 20773, 26496, 34011, 35329, 61157, 65050, 65055, 398101,), #398101 used for VPS
    "Google":(15169,), # 
    "GreenviewData":(13380, 13768, 20473, 32244, 32613, 36351, 63018,),
    "IntermediaCloud":(3561, 16406, 50152, 135160),
    "Mail.Ru":(47764, 197695), # FP: 49981, collision. 9331601.mail.ru
    "Mailgun":(14618, 16509,),
    "MessageLabs":(14618, 16509, 21345, 26282), 
    "Microsoft":(8075, 58593, 200517), #FPs: 4788, 1680. Potentially malicious
    "Mimecast":(203, 1290, 3561, 13173, 14135, 17477, 17819, 30031, 33538, 37235, 39588, 42427, 60492, 136792),
    "NameCheap":(22612,), # 
    "OVH":(16276,),
    "ProofPoint":(13916, 15830, 22843, 26211, 52129,),
    "Rackspace":(19994, 27357, 33070, 33724),
    "SakuraInternet":(7684, 9370, 9371),
    "SiteGround": (15169, 16509, 19527, 32475, 36351, 396982), # siteground.us: 16509 FPs:
    "Solarwinds":(174, 7203, 8972, 12876, 16633, 24940, 28753, 30083, 30633, 49544, 59253, 60781, 205544,),
    "Sophos": (2856, 3209, 6453, 14618, 16509, 21755, 46887, 393497,), # All commontouch ASNs
    "Spamhero":(13354,13951),
    "Strato": (6724,), # FPs: 24940 (Heztner) --> unable to verify (limited data, legit pattern). h1779670/1.stratoserver.net --> same pattern, only 2017, no TLS, also some in 6724 don't have TLS
    "Tencent":(816, 6939, 17623, 132203, 132591,),  #FPs: 37963 --> unable to verify (limited data, legit pattern)
    "TrendMicro":(14618, 16509, 16880, 36421), # Likely FPs: 4808, 4812,
    "Tucows":(15348, 32491),
    "Ukraine.ua": (200000, 200525,), # 
    "UnitedInternet":(8560,), # FPs: 7992, 43443, 12876, 50673 
    "Web.com":(13335, 19871, 55002,),
    "Yahoo": (10229, 24506, 26101, 34010, 36646, 36647, 56173), # FP: 34971
    "Yandex":(13238,),
    "Zoho":(2639, 13237, 15830, 41913),
}

# Contains provider IDs associated with each company identified in our dataset
company_to_provider_ids = {
    "AppRiver":("appriver.com",),
    "Aruba":("aruba.it","arubabusiness.it","arubabiz.net",),
    "Barracuda":("barracudanetworks.com","barracuda.com","cuda-inc.com",), #"barracudamoto.co.uk",
    "Beget": ("beget.ru","beget.tech"),
    "Cisco": ("iphmx.com",),
    "EIG":("bluehost.com","eigbox.com","eigbox.net","hostgator.com","webhostbox.net","yourhostingaccount.com","arvixe.com","mailhostbox.com"),
    "Fastmail":("messagingengine.com","pobox.com",),
    "FireEye":("fireeyecloud.com","fireeyegov.com"),
    "ForcePoint":("mailcontrol.com",),
    "Gandi":("gandi.net",),
    "GoDaddy": ("secureserver.net","mailcore.me","hosteurope.de","extendcp.co.uk","ispgateway.de","123-reg.co.uk"),
    "Google": ("google.com","gmail.com"),
    "GreenviewData":("spamh.com",),
    "IntermediaCloud":("serverdata.net",),
    "Mail.Ru": ("mail.ru",),
    "Mailgun": ("mailgun.org",),
    "MessageLabs": ("messagelabs.com",),
    "Microsoft": ("outlook.com","office365.us","hotmail.com","outlook.cn","outlook.de"), # "azure.com"
    "Mimecast": ("mimecast.com","mimecast.co.za","mimecast-offshore.com"),
    "NameCheap": ("privateemail.com","namecheap.tech","registrar-servers.com","web-hosting.com","jellyfish.systems",),#
    "OVH": ("ovh.net","ovh.ca"),
    "ProofPoint": ("pphosted.com","ppe-hosted.com","ppops.net","gpphosted.com"),
    "Rackspace":("emailsrvr.com","rack-host.net"),
    "SakuraInternet":("180r.com","sakura.ne.jp",),
    "SiteGround": ("mailspamprotection.com","siteground.*","sgded.com","siteground*.com","sgcpanel.com"), # tricky
    "Solarwinds":("antispamcloud.com","spamexperts.eu",),
    "Sophos": ("sophos.com","reflexion.net"),
    "Spamhero":("mxthunder.net","mxthunder.com"),
    "Strato": ("rzone.de","stratoserver.net"),
    "Tencent": ("qq.com",),
    "TrendMicro":("trendmicro.com","trendmicro.co.jp","trendmicro.eu",),
    "Tucows":("hostedemail.com","tucows.com"),
    "Ukraine.ua": ("default-host.net","ukraine.com.ua"), # ,"vps-ukraine.com.ua","vps-default-host.net",
    "UnitedInternet":("web.de","gmx.net","mail.com","livemail.co.uk","kundenserver.de","perfora.net","1and1.com"),
    "Web.com":("registeredsite.com","myregisteredsite.com","register.com","netsolmail.net"),
    "Yandex": ("yandex.net","yandex.ru","yandex-team.ru"),
    "Yahoo":("yahoo.com","yahoodns.net",),
    "Zoho": ("zoho.com","zoho.eu"),
}

provider_id_to_comany_static = {v:k for k,vs in company_to_provider_ids.items() for v in vs if "*" not in v}

provider_id_to_comany_patterns = {v:k for k,vs in company_to_provider_ids.items() for v in vs if "*" in v}

def has_company_info_for_provider_id(provider_id):
    if provider_id in provider_id_to_comany_static:
        return True
    
    else:
        for pattern in provider_id_to_comany_patterns.keys():
            if regex_match(provider_id, pattern):
                return True
    return False


def func_provider_id_to_comany(provider_id):
    if provider_id in provider_id_to_comany_static:
        return provider_id_to_comany_static[provider_id]

    else:
        for pattern in provider_id_to_comany_patterns.keys():
            if regex_match(provider_id, pattern):
                return provider_id_to_comany_patterns[pattern]
    raise Exception("Error Matching P id: {}".format(provider_id))


# Heuristic to find VPS servers based on what we have seen in the dataset
# This function returns a tuple: (type, type_int)
# DEDICATED means not VPS
def extract_pattern_of_server_id(text, pattern_from):
    # Assume you've filtered out AS false postives

    # AppRiver
    if "appriver.com" in text:
        return ("DEDICATED", 0)

    # Aruba.it
    elif "aruba.it" in text:
        return ("DEDICATED", 0)
    elif "arubabusiness.it" in text:
        return ("DEDICATED", 0)
    # Some one could rent on top of it
    elif "arubabiz.net" in text:
        return ("VPS", 0)


    # Barracuda
    elif "cuda-inc.com" in text:
        return ("DEDICATED", 0)
    elif "barracudanetworks.com" in text:
        return ("DEDICATED", 0)
    elif "barracuda.com" in text:
        return ("DEDICATED", 0)


    # Beget
    elif "beget.ru" in text:
        return ("DEDICATED", 0)
    # Only 1 server, weird bahavior
    elif "beget.tech" in text:
        return ("VPS", 0)


    # Cisco
    elif "iphmx.com" in text:
        return ("DEDICATED", 0)

    
    # EIG
    elif "mailhostbox.com" in text:
        return ("DEDICATED", 0)
    elif "webhostbox.net" in text:
        if "pp" in text and "wb" in text:
            return ("DEDICATED", 0)
        if "md" in text:
            return ("DEDICATED", 0)
        if "mail" in text:
            return ("DEDICATED", 0)
        if "web" in text:
            return ("DEDICATED", 0)
        if "*.webhostbox.net" in text:
            return ("DEDICATED", 1)
        if "vps" in text:
            return ("VPS", 3)
        if "-" in text:
            try:
                pieces = text.split(".")[0].split("-")
                if len(pieces) == 4 and all(0<=int(p.strip())<256 for p in pieces):
                    return ("VPS", 2)
            # Unknown
            except: 
                pass
    elif "yourhostingaccount.com" in text:
        return ("DEDICATED", 0)
    elif "eigbox.net" in text:
        return ("DEDICATED", 0)
    # Conflict
    elif "bluehost.com" in text:
        return ("DEDICATED", 0)
    elif "hostgator.com" in text:
        return ("DEDICATED", 0)
    elif "eigbox.com" in text:
        return ("DEDICATED", 0)
    elif "arvixe.com" in text:
        return ("DEDICATED", 0)

    # Fastmail
    elif "messagingengine.com" in text:
        return ("DEDICATED", 0)
    elif "pobox.com" in text:
        return ("DEDICATED", 0)

    # Fireeye
    elif "fireeyecloud.com" in text:
        return ("DEDICATED", 0)
    elif "fireeyegov.com" in text:
        return ("DEDICATED", 0)

    # ForcePoint
    elif "mailcontrol.com" in text :
        return ("DEDICATED", 0)
    
    # Gandi
    elif "gandi.net" in text:
        return ("DEDICATED", 0)
    
    # GoDaddy
    elif "secureserver.net" in text:
        if ".prod." in text and "libsmtp" in text:
            return ("DEDICATED", 0)
        if ".prod." in text and "plsmtpout" in text:
            return ("DEDICATED", 1)
        if ".prod." in text and "plsmtpa" in text:
            return ("DEDICATED", 2)
        if ".prod." in text and "plout" in text:
            return ("DEDICATED", 3)
        #  dedrelay.secureserver.net
        if "smtp" in text and "ded" in text:
            return ("DEDICATED", 4)
        if ".prod." in text and "nlsmtp" in text:
            return ("DEDICATED", 5)
        if ".prod." in text and "cpnl" in text:
            return ("DEDICATED", 12)

        if "smtp.secureserver.net" in text:
            return ("DEDICATED", 6)
        if "smtp.europe.secureserver.net" in text:
            return ("DEDICATED", 7)
        if "mailstore1.secureserver.net" in text:
            return ("DEDICATED", 8)
        if "mailstore1.europe.secureserver.net" in text:
            return ("DEDICATED", 9)
        if "smtp.asia.secureserver.net" in text:
            return ("DEDICATED", 10)
        if "mailstore1.asia.secureserver.net" in text:
            return ("DEDICATED", 11)

        
        first_component = text.split(".")[0]
        if first_component.startswith("s") and first_component.count("-") == 3:
            return ("VPS", 12)
        if first_component.startswith("ip-"):
            return ("VPS", 13)
        
        # VPS: CN = mail.cabforum.org, browser_trusted
        if "p3plcabfweb01.prod.phx3.secureserver.net" in text:
            return ("VPS", 14)
        
        return ("RANDOM_STRING_VPS", 15)
    
    elif "hosteurope.de" in text:
        # valid cert: *.webpack.hosteurope.de
        if "webpack.hosteurope.de" in text:
            return ("DEDICATED", 0)
        # valid cert: *.webpack.hosteurope.de
        if "mi" in text and "mc" in text:
            return ("DEDICATED", 1)
        # valid cert: mx0.hosteurope.de
        if text.startswith("mx"):
            return ("DEDICATED", 2)
        # valid cert: mx0.hosteurope.de
        if text.startswith("server"):
            return ("DEDICATED", 3)
        if "*" in text:
            return ("DEDICATED", 9)
        # self signed
        if text.startswith("lvps"):
            return ("VPS", 4)
        # self signed
        if text.startswith("pvcl"):
            return ("VPS", 5)
        # self signed / trusted third party
        if text.startswith("ds"):
            return ("VPS", 6)
        # self signed / trusted third party
        if text.startswith("vs"):
            return ("VPS", 6)
        if "vps" in text:
            return ("VPS", 6)
        # self signed
        if ".rs." in text:
            return ("VPS", 7)
        if "kundenadmin.hosteurope.de" in text:
            return ("VPS", 8)
    
    elif "mailcore.me" in text:
        return ("DEDICATED", 0)
    
    elif "ispgateway.de" in text:
        return ("DEDICATED", 0)
    
    elif "extendcp.co.uk" in text:
        return ("DEDICATED", 0)
    
    elif "123-reg.co.uk" in text:
        return ("DEDICATED", 0)

    
    # Google
    elif "google.com" in text:
        if pattern_from in ("BANNER", "EHLO"):
            if text != "mx.google.com":
                return ('VPS', 1)

        return ("DEDICATED", 0)
    
    elif "gmail.com" in text:
        return ("DEDICATED", 0)

    # GreenviewData
    elif "spamh.com" in text:
        return ("DEDICATED", 0)

    # IntermediaCloud
    elif "serverdata.net" in text:
        return ("DEDICATED", 0)

    # Mail.Ru
    elif "mail.ru" in text:
        return ("DEDICATED", 0)
    
    # Mailgun
    elif "mailgun.org" in text:
        return ("DEDICATED", 0)

    # MessageLabs
    elif "messagelabs.com" in text:
        return ("DEDICATED", 0)
    
    # Microsoft
    elif "outlook.de" in text:
        return ("DEDICATED", 0)
    elif "outlook.cn" in text:
        return ("DEDICATED", 0)
    elif "outlook.com" in text:
        return ("DEDICATED", 0)
    elif "office365.us" in text:
        return ("DEDICATED", 0)
    elif "hotmail.com" in text:
        return ("DEDICATED", 0)

    # Mimecast
    elif "mimecast.com" in text:
        return ("DEDICATED", 0)

    elif "mimecast.co.za" in text:
        return ("DEDICATED", 0)

    elif "mimecast-offshore.com" in text:
        return ("DEDICATED", 1)

    # NameCheap
    elif "jellyfish.system" in text:
        return ("DEDICATED", 0)
    
    elif "namecheap.tech" in text:
        return ("DEDICATED", 0)

    elif "privateemail.com" in text:
        return ("DEDICATED", 0)

    elif "registrar-servers.com" in text:
        return ("DEDICATED", 0)
        
    elif "web-hosting.com" in text:
        if "server" in text:
            return ("DEDICATED", 1)
        
        if "premium" in text:
            return ("DEDICATED", 2)

        return ("VPS", 0)

    # OVH   
    elif "ovh.net" in text:
        # Self-signed
        if "vps" in text:
            return ("VPS", 1)

        if "ns" in text:
            if "ns0." in text:
                return ("DEDICATED", 2)
            return ("VPS", 3)

        if "ssl0." in text:
            return ("DEDICATED", 3)
        
        if "smtp.mail.ovh.net" in text:
            return ("DEDICATED", 4)
        
        if "mail.ovh.net" in text:
            return ("DEDICATED", 5)
        
        if "mx" in text:
            return ("DEDICATED", 6)

        if "parking" in text:
            return ("DEDICATED", 7)
        
        if "redirect" in text:
            return ("DEDICATED", 8)
        
        # Self-signed
        if "reseller." in text and text.startswith('h'):
            return ("VPS", 9)
        
        return ("RANDOM_STRING_VPS", 10)

    elif "ovh.ca" in text:
        # Self-signed
        if "vps" in text:
            return ("VPS", 1)
        
        if "mail.ovh" in text:
            return ("DEDICATED", 4)


    # Proofpoint
    elif "ppe-hosted.com" in text:
        return ("DEDICATED", 0)
    elif "pphosted.com" in text:
        return ("DEDICATED", 1)
    elif "ppops.net" in text:
        return ("DEDICATED", 0)
    elif "gpphosted.com" in text:
        return ("DEDICATED", 0)

    # Rackspace
    elif "emailsrvr.com" in text:
        return ("DEDICATED", 0)
    elif "rack-host.net" in text:
        return ("DEDICATED", 0)

    # SakuraInternet
    elif "180r.com":
        return ("DEDICATED", 0)
    elif "sakura.ne.jp" in text:
        if "*.sakura.ne.jp" == text:
            return ("DEDICATED", 0)
        return ("VPS",0)
    
    # SiteGround
    elif "siteground.us" in text:
        return ("DEDICATED", 0)

    elif "siteground.eu" in text:
        return ("DEDICATED", 0)

    elif "siteground.asia" in text:
        # valid cert: *.sgcpanel.com
        return ("DEDICATED", 0)
    
    elif "siteground.com" in text:
        return ("DEDICATED", 0)

    elif "siteground.biz" in text:
        return ("DEDICATED", 0)
    
    elif "sgded.com" in text:
        if text.startswith("serv") or text.startswith("em") or text.startswith("m") or text.startswith("usm") or text.startswith("esm"):
            return ("VPS", 0)

    elif regex_match(text,"siteground*.com"):
        return ("DEDICATED", 0)
    
    # Popular
    elif "sgcpanel.com" in text:
        return ("DEDICATED", 0)
    # Popular
    elif "mailspamprotection.com" in text:
        return ("DEDICATED", 0)

    
    # Solarwinds
    elif "antispamcloud.com" in text:
        return ("DEDICATED", 0)
    elif "spamexperts.eu" in text:
        return ("DEDICATED", 0)

    # Sophos
    elif "sophos.com" in text:
        return ("DEDICATED", 0)
    elif "reflexion.net" in text:
        return ("DEDICATED", 0)

    # Spamhero
    elif "mxthunder.net" in text:
        return ("DEDICATED", 0)
    elif "mxthunder.com" in text:
        return ("DEDICATED", 0)

    # Strato
    elif "rzone.de" in text:
        return ("DEDICATED", 0)

    elif "stratoserver.net" in text:
        if "h" in text:
            return ("VPS", 0)
        
        return ("RANDOM_STRING_VPS", 1)

    
    # Tencent:
    elif "qq.com" in text:
        return ("DEDICATED", 0)
    

    # TrendMicro:
    elif "trendmicro.eu" in text:
        return ("DEDICATED", 0)
    elif "trendmicro.co.jp" in text:
        return ("DEDICATED", 0)
    elif "trendmicro.com" in text:
        return ("DEDICATED", 0)

    
    # Tucows
    elif "hostedemail.com" in text:
        return ("DEDICATED", 0)
    elif "tucows.com" in text:
        return ("DEDICATED", 0)
    

    # Ukraine.ua
    elif "ukraine.com.ua" in text:
        if text.startswith("relay") or text.startswith("mail"):
            return ("DEDICATED", 0)
        return ("VPS", 1)
    
    elif ".default-host.net" in text:
        if text.startswith("d"):
            return ("VPS", 0)

        if text.startswith("web"):
            return ("VPS", 1)
        
        if "mx" in text:
            return ("DEDICATED", 2)


    # UnitedInternet
    elif "livemail.co.uk" in text:
        return ("DEDICATED", 0)
    elif "web.de" in text:
        return ("DEDICATED", 0)
    elif "gmx.net" in text:
        return ("DEDICATED", 0)
    elif "mail.com" in text:
        return ("DEDICATED", 0)
    elif "perfora.net" in text:
        return ("DEDICATED", 0)
    elif "kundenserver.de" in text:
        return ("DEDICATED", 0)
    elif "1and1.com" in text:
        return ("DEDICATED", 0)


    # Web.com
    elif "registeredsite.com" in text:
        return ("DEDICATED", 0)
    elif "myregisteredsite.com" in text:
        return ("DEDICATED", 0)
    ### register.com and netsolmail.net seem to be MX only
    elif "register.com" in text:
        return ("DEDICATED", 0)
    elif "netsolmail.net" in text:
        return ("DEDICATED", 0)
    

    # Yahoo
    elif "yahoo.com" in text:
        return ("DEDICATED", 0)
    elif "yahoodns.net" in text:
        return ("DEDICATED", 0)


    # Yandex
    elif "yandex.net" in text:
        return ("DEDICATED", 0)
    elif "yandex-team.ru" in text:
        return ("DEDICATED", 0)


    # Zoho
    elif "zoho.eu" in text:
        return ("DEDICATED", 0)
    elif "zoho.com" in text:
        return ("DEDICATED", 0)
    #####################
    
    return ("Pattern Undefined", -1)


class Heuristics():
    @staticmethod
    def run_heuristics(mx):
        if 'USE_HEURISTICS' not in CONFIG:
            return

        # No provider id, return
        if mx.pid == None or mx.pid.get_provider_id_str() == None:
            return
        
        # Run Heuristics only when conf score <= threashold and not mx
        if mx.pid.score < CONFIG['USE_HEURISTICS']['THRESHOLD']:
            Heuristics.heuristics_checks(mx)
        

    @staticmethod
    def heuristics_checks(mx):
        # Get a set of heuristic functions
        heuristic_funcs = [getattr(Heuristics, "{}_heuristics".format(i.lower())) for i in CONFIG['USE_HEURISTICS']['FUNCS']]
        for heuristic_func in heuristic_funcs:
            heuristic_applied = heuristic_func(mx)
            if heuristic_applied == True:
                break

    @staticmethod
    def as_heuristics(mx):
        # Return True if this heuristic is applied

        # Ignore cases where source is MX
        if mx.pid == None or mx.pid.get_provider_id_str() == None or mx.pid.source == 'MX':
            return False
        
        # We also only handle specific cases
        

        ## Case 1: Provider Is Hanlded. IP not in specified AS
        provider_id = mx.pid.get_provider_id_str()
        if has_company_info_for_provider_id(provider_id):
            company = func_provider_id_to_comany(provider_id)
            expected_as = company_to_as[company]
            for ip in mx.ips:
                if ip.as_number != None and ip.as_number not in expected_as:
                    mx.pid.set_heuristics(corrected = -1, msg = "IP in an unseen AS")
                    return True
        
        ## Case 2: IP in Cisco/PP AS
        cisco_as = company_to_as['Cisco']
        if all(ip.as_number in cisco_as for ip in mx.ips if ip.as_number != None and ip.has_smtp()):
            if not has_company_info_for_provider_id(provider_id):
                mx.pid.set_heuristics(corrected = 1, new_provider_id='iphmx.com', msg = "All IPs are in Cisco Ironport's AS")
            return True 

        pp_as = list(company_to_as['ProofPoint'])
        pp_as.remove(15830)
        if all(ip.as_number in pp_as for ip in mx.ips if ip.as_number != None and ip.has_smtp()):
            if not has_company_info_for_provider_id(provider_id):
                mx.pid.set_heuristics(corrected = 1, new_provider_id='pphosted.com', msg = "All IPs are in ProofPoint's AS")
            return True 
        
        return False



    @staticmethod
    def cert_pattern_heuristics(mx):
        # Return True if this heuristic is applied
        # Ignore cases where source is not TLS
        if mx.pid == None or mx.pid.get_provider_id_str() == None or mx.pid.source != 'TLS':
            return False
        
        # If out-of-scope, ignore
        provider_id = mx.pid.get_provider_id_str()
        if has_company_info_for_provider_id(provider_id) == False:
            return

        # Check if the provider id is potentially misleading
        for ip in mx.ips:
            for fqdn in ip.get_valid_cert_fqdns():
                pattern_type, pattern_number = extract_pattern_of_server_id(fqdn, "TLS")
                if "VPS" in pattern_type:
                    mx.pid.set_heuristics(corrected = -1, msg = "FQDN used by Cert Indicates Potentially VPS")
                return True
        
        return False

    @staticmethod
    def banner_pattern_heuristics(mx):
        # Return True if this heuristic is applied
        if mx.pid == None or mx.pid.get_provider_id_str() == None or mx.pid.source != 'Banner/EHLO':
            return False
        
        # If out-of-scope, ignore
        provider_id = mx.pid.get_provider_id_str()
        if has_company_info_for_provider_id(provider_id) == False:
            return

        # Check if the provider id is potentially misleading
        known_vps_pattern = True
        vps_fqdn = None
        for ip in mx.ips:
            if ip.has_valid_ehlo_rd():
                ehlo_fqdn = ip.get_valid_ehlo_fqdn()
                pattern_type, pattern_number = extract_pattern_of_server_id(ehlo_fqdn, "EHLO")
                if "VPS" in pattern_type:
                    known_vps_pattern &= True
                    vps_fqdn = ehlo_fqdn
                else:
                    known_vps_pattern &= False

            if ip.has_valid_banner_rd():
                banner_fqdn = ip.get_valid_banner_fqdn()
                pattern_type, pattern_number = extract_pattern_of_server_id(banner_fqdn, "BANNER")
                if "VPS" in pattern_type:
                    known_vps_pattern &= True
                    vps_fqdn = banner_fqdn
                else:
                    known_vps_pattern &= False
            
            if known_vps_pattern == True:
                mx.pid.set_heuristics(corrected = -1, msg = "FQDN ({}) used by Banner/EHLO Indicates Potentially VPS".format(vps_fqdn))
                return True

        return False

    @staticmethod
    def infer_company_of_mx(mx):
        if mx.pid == None:
            return 

        # Can't find valid provider id
        if mx.pid.get_provider_id_str() == None and mx.pid.heuristics_obj.new_provider_id == None:
            return 
        
        # Correctly
        if mx.pid.heuristics_obj.new_provider_id != None and mx.pid.heuristics_obj.corrected == 1:
            provider_id_str = mx.pid.heuristics_obj.new_provider_id
        else:
            provider_id_str = mx.pid.get_provider_id_str()

        if has_company_info_for_provider_id(provider_id_str) == False:
            return
        
        mx.pid.set_company_id(func_provider_id_to_comany(provider_id_str))

