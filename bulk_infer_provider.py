# Script to sequentially infer the mail provider from a list of domains.

# Usage: Change INPUT_FILEPATH, OUTPUT_FILEPATH, FAILURE_FILEPATH as needed

from mx_inference.inference import MXInference
from mx_inference.lib.network_lib import scan_domain
from mx_inference.config.config import CONFIG
from mx_inference.lib.helper import dump_domain_data_to_csv_format_censys, load_domain_data_from_path_format_censys
from datetime import datetime
import argparse
import os
import subprocess

INPUT_FILEPATH = 'all_subdomains.txt'
OUTPUT_FILEPATH = 'subdomains_output.txt'
FAILURE_FILEPATH = 'failed_subdomains.txt'


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
    parser.add_argument("--domains", "-d", nargs='+')

    # Load data and run the program
    parser.add_argument("--load_data_from_path", type=str, required=False)

    # Determine what information to use for inference
    parser.add_argument("--disable_tls", default=False, action='store_true',
                        help="Don't use cert information for inference")
    parser.add_argument("--disable_banner", default=False,  action='store_true',
                        help="Don't use banner/ehlo information for inference")

    # Determine what heuristics to use
    parser.add_argument("--disable_heuristics", default=False,
                        action='store_true', help="Do not use heuristics at all")
    # Apply heuristics when confidence score <= threshold
    parser.add_argument("--heuristics_threshold", default=5, type=int,
                        help="Threshold to apply heuristics; Applied when conf score <= threshold")
    parser.add_argument("--disable_heuristics_as", default=False, action='store_true',
                        help="Don't use heuristics that based on AS information")
    parser.add_argument("--disable_heuristics_tls_pattern", default=False, action='store_true',
                        help="Don't use heuristics that based on TLS Cert FQDN pattern")
    parser.add_argument("--disable_heuristics_banner_pattern", default=False, action='store_true',
                        help="Don't use heuristics that based on banner/ehlo FQDN pattern")

    # Try mapping provider id to company using heuristics
    parser.add_argument("--map_id_to_company", default=True, type=bool,
                        help="Whether to try mapping provider id to company")

    # Sava Data After Probing Each Domain
    parser.add_argument("--save_scan_data", default=True, type=bool,
                        help="Whether to save data after probing domains")

    # Debug level
    parser.add_argument("--debug", default=0, type=int, choices=range(0, 3),
                        help="Debug level. 0 = Minimum, 1 = Light, 2 = Verbose; when 0, only prints most preferred MX")

    args = parser.parse_args()
    setup_config(args)

    with open(INPUT_FILEPATH, 'r') as f:
        all_domains = []
        linelist = f.readlines()
        for line in linelist:
            all_domains.append(line.strip())

    failed_domains = []
    count = 0
    total_count = len(all_domains)
    with open(OUTPUT_FILEPATH, 'a+') as f:
        for domain in all_domains:
            print(domain)
            try:
                domain_with_data = scan_domain(domain)
                i = MXInference().infer_id(domain_with_data)
                f.write(str(i) + '\n')
                count += 1
                print(count)
            except:
                failed_domains.append(domain)
                continue
    print('count: {} / {}'.format(count, total_count))
    with open(FAILURE_FILEPATH, 'a+') as f:
        for domain in failed_domains:
            f.write(domain + '\n')


if __name__ == "__main__":
    main()
