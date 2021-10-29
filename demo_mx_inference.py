from mx_inference.inference import MXInference
from mx_inference.lib.network_lib import scan_domain
from mx_inference.config.config import CONFIG
from mx_inference.lib.helper import dump_domain_data_to_csv_format_censys, load_domain_data_from_path_format_censys
from datetime import datetime
import argparse
import os
import subprocess

EXAMPLE_DOMAINS = ["ucsd.edu","netflix.com","gsipartners.com","lodi.gov","jeniustoto.net",\
    "sgnetway.net","bbw-chan.nl","utexas.edu","summitorganization.org","arfonts.net"]
    

def setup_config(args):
    if args.disable_tls == True:
        CONFIG['INFERENCE_FUNCTIONS'].remove('IDFromTLS')

    if args.disable_banner == True:
        CONFIG['INFERENCE_FUNCTIONS'].remove('IDFromBanner')

    if args.disable_heuristics == True:
        CONFIG.pop('USE_HEURISTICS')

    if args.disable_heuristics == False and args.disable_heuristics_as == True:
        CONFIG['USE_HEURISTICS']['FUNCS'].remove('AS')
    
    if args.disable_heuristics == False and args.disable_heuristics_banner_pattern == True:
        CONFIG['USE_HEURISTICS']['FUNCS'].remove('BANNER_PATTERN')
    
    if args.disable_heuristics == False and args.disable_heuristics_tls_pattern == True:
        CONFIG['USE_HEURISTICS']['FUNCS'].remove('CERT_PATTERN')

    if args.disable_heuristics == False and type(args.heuristics_threshold) == int:
        CONFIG['USE_HEURISTICS']['THRESHOLD'] = args.heuristics_threshold

    if type(args.map_id_to_company) == bool:
        CONFIG['PROVIDER_ID_TO_COMPANY'] = args.map_id_to_company
    
    if type(args.save_scan_data) == bool:
        CONFIG['SAVE_SCAN_DATA'] = args.save_scan_data

    if type(args.debug) == int:
        CONFIG['DEBUG_LEVEL'] = args.debug


def main():
    # Check if openssl is installed
    try:
        subprocess.call(["openssl", "version"])
    except FileNotFoundError:
        print("Command line util openssl not found. Please install!")
        return

    # Parsing
    parser = argparse.ArgumentParser()
    
    # Specify the domains One Want To Probe
    parser.add_argument("--domains", "-d", nargs='+', default=EXAMPLE_DOMAINS)

    # Load data and run the program
    parser.add_argument("--load_data_from_path", type=str, required=False)

    # Determine what information to use for inference
    parser.add_argument("--disable_tls", default = False, action='store_true', help="Don't use cert information for inference")
    parser.add_argument("--disable_banner", default = False,  action='store_true', help="Don't use banner/ehlo information for inference")

    # Determine what heuristics to use
    parser.add_argument("--disable_heuristics", default = False, action='store_true', help="Do not use heuristics at all")
    # Apply heuristics when confidence score <= threshold
    parser.add_argument("--heuristics_threshold", default = 5, type=int, help="Threshold to apply heuristics; Applied when conf score <= threshold")
    parser.add_argument("--disable_heuristics_as", default = False, action='store_true', help="Don't use heuristics that based on AS information")
    parser.add_argument("--disable_heuristics_tls_pattern", default = False, action='store_true', help="Don't use heuristics that based on TLS Cert FQDN pattern")
    parser.add_argument("--disable_heuristics_banner_pattern", default = False, action='store_true', help="Don't use heuristics that based on banner/ehlo FQDN pattern")

    # Try mapping provider id to company using heuristics
    parser.add_argument("--map_id_to_company", default = True, type=bool, help="Whether to try mapping provider id to company")


    # Sava Data After Probing Each Domain
    parser.add_argument("--save_scan_data", default = True, type=bool, help="Whether to save data after probing domains")

    
    # Debug level
    parser.add_argument("--debug", default = 0, type=int, choices = range(0,3), help="Debug level. 0 = Minimum, 1 = Light, 2 = Verbose; when 0, only prints most preferred MX")


    args = parser.parse_args()
    setup_config(args)

    print('Configuration Used For This Run: {}\n'.format(CONFIG))
    
    if args.load_data_from_path:
        domains_with_data = load_domain_data_from_path_format_censys(args.load_data_from_path)
    else:
        domains_with_data = []
        for domain in args.domains:
            domains_with_data.append(scan_domain(domain))
        if CONFIG['SAVE_SCAN_DATA']:
            path = "mx_inference-data-{}.csv".format(datetime.now().strftime("%Y%m%d%H%M%S"))
            dump_domain_data_to_csv_format_censys(domains_with_data, path)
            print("Scanned Domain Data Saved At: {}\n".format(path))
    
    
    print("Inference Results:")
    for i in MXInference().infer_ids(domains_with_data):
         print(i)

if __name__ == "__main__":
    main()
    