import os

import warnings
warnings.simplefilter(action='ignore')

HDFS_BASE_DIR = "/hdfs/user/e7liu/"

def load_hdfs_data(mx_type, date, version, specific_folder):
    hdfs_data_folder_path = HDFS_BASE_DIR + "cr_cr_{}_old_certs_{}_{}/".format(mx_type, date, version) + specific_folder 
    hdfs_summary_path = hdfs_data_folder_path + "/summary"
    if not os.path.exists(hdfs_data_folder_path):
        raise Exception("Input Path Not Exist:{}".format(hdfs_data_folder_path))
    if not os.path.exists(hdfs_summary_path):
        print("Generating Summary File for {}".format(hdfs_summary_path))
        os.system("cd {}; cat * >> summary;".format(hdfs_data_folder_path))

    rows = []

    with open(hdfs_summary_path) as f:
        for row in f:
            row = row.strip()
            row = eval(row)
            rows.append(row)
    
    return rows

from collections import OrderedDict, Counter

def load_data_for_date(mx_type,d,output_version):
    output_file_path = "../src/cr_output_cr_{}_old_certs_{}_{}".format(mx_type, d, output_version)
    company_to_data = OrderedDict()
    record = False
    with open(output_file_path) as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue

            if line.startswith("Companys and Market Share (cleaned)"):
                record = True
            elif record == True:

                line = eval(line)
                r = Row(company_id = line[0], domain_coverage = line[1][1], asns_set = line[1][-1])
                company_to_data[r.company_id] = r
    return company_to_data


def print_table(title, rows):
    ### Print Table Title
    print("{}".format(" {} ".format(title).center(50,'-')))

    ### column left adjusts
    column_left_adjusts = [-1] * len(rows[0])

    for i in range(len(rows)):
        for j in range(len(rows[0])):
            rows[i][j] = str(rows[i][j])
            if len(rows[i][j]) + 2 > column_left_adjusts[j]:
                column_left_adjusts[j] = len(rows[i][j]) + 2
    
    for row in rows:
        print("{}".format(''.join(data.ljust(column_left_adjusts[idx]) for idx,data in enumerate(row))))
    
    print("{}\n\n".format(" End of Table ".center(50,'-')))



def load_alexa_rankings():
    alexa_rankings = {}
    with open("../data/alexa_ranking/alexa-top1m-2021-06-08_0900_UTC.csv") as f:
        for line in f:
            #print(line)
            rank, domain = line.strip().split(",")
            rank = int(rank)
            alexa_rankings[domain] = rank
    
    
    with open("../data/alexa_ranking/alexa-top1m-2021-06-07_0900_UTC.csv") as f:
        for line in f:
            #print(line)
            rank, domain = line.strip().split(",")
            rank = int(rank)
            if domain not in alexa_rankings:
                alexa_rankings[domain] = rank

    return alexa_rankings

    
def load_federal_domains():
    federal = set()
    with open("../data/federal_domains/federal.csv") as f:
        for line in f:
            #print(line)
            domain = line.strip().split(",")[0].lower()
            federal.add(domain)
    
    return federal


def load_alexa_domains():
    domains = []
    with open("../data/domains/alexa_domains_20210608") as f:
        for line in f:
            line = line.strip()
            domain = line
            domains.append(domain)
    return domains

def load_gov_domains():
    domains = []
    with open("../data/domains/gov_domains_20210608") as f:
        for line in f:
            line = line.strip()
            domain = line
            domains.append(domain)
    return domains