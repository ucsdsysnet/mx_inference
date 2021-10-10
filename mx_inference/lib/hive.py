""" 
This file contains functions for convert lists into hive table. 
    For internal use only.
"""

import csv

# For internal use only
def convert_list_to_hive_compatible_list(result_list):
    dump_list = []
    # Convert to Hive format, used internally
    for (domain_name, mx_address, mx_preference, ip4_address, asns_top, ip_info_p25) in result_list:
        dump_list.append((domain_name.strip(".") if domain_name != None else r"\N",mx_address.strip(".") if mx_address != None else r"\N",ip4_address if ip4_address != None else r"\N",ip_info_p25 if ip_info_p25 != None else r"\N", str(asns_top) if asns_top != None else r"\N", asns_top if asns_top != None else r"\N", r"\N", 'A', r"\N", r"\N", mx_preference if mx_preference != None else "", '2021-09-10'))
    return dump_list

def dump_hive_compatible_list_to_csv(dump_list, output_file):
    with open('{}'.format(output_file), 'a+') as f:
        # using csv.writer method from CSV package
        write = csv.writer(f,delimiter='\t')    
        write.writerows(dump_list)

