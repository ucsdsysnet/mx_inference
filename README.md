# MX Inference
[![Python 3.6](https://img.shields.io/badge/python-3.6-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Python 3.8](https://img.shields.io/badge/python-3.8-blue.svg)](https://www.python.org/downloads/release/python-360/)

MX Inference is a tool that uses DNS data and active port scanning data to infer the mail provider of a domain. This tool makes inference based on the MX records specified by the domain.

## Installation
1. Clone our repository
```bash
git clone https://github.com/ucsdsysnet/mx_inference.git
```
2. Install OpenSSL and associated development libraries ([Reference](https://stackoverflow.com/questions/9001316/how-to-install-openssl-for-python)).
```
# CentOS:
$ yum install openssl-devel libffi-devel

# Ubuntu:
$ apt-get install libssl-dev libffi-dev

# OS X (with Homebrew installed):
$ brew install openssl
```
3. Install python libraries.
```bash

# Optionally: start a virtual environment
python3 -m venv .
source bin/activate

# Mandatory
python3 -m pip install -r requirements.txt
```

### Tested Version
We tested our code with Python 3.6/3.8 and OpenSSL version 1.1.1i/1.0.2g on Ubuntu and Mac respectively.

## Usage
### Default Setup
We have some examples built in. You can simply run the following command (might take a while):
```
python3 demo_mx_inference.py
```
Sample output:
```
...
Domain: ucsd.edu
	ID:pphosted.com, Type:OK, Source:TLS, Debug MSG:Cert ID Ok, Conf_Score:1
		Suggested Company: ProofPoint
	...

Domain: netflix.com
	ID:google.com, Type:OK, Source:TLS, Debug MSG:Cert ID Ok, Conf_Score:2
		Suggested Company: Google
	...

Domain: gsipartners.com
	ID:google.com, Type:OK, Source:TLS, Debug MSG:Cert ID Ok, Conf_Score:2
		Suggested Company: Google
	...

# lodi.gov has two IDs because it has two MX records with same priority
Domain: lodi.gov
	ID:iphmx.com, Type:OK, Source:TLS, Debug MSG:Cert ID Ok, Conf_Score:1
		Suggested Company: Cisco
	
	ID:iphmx.com, Type:OK, Source:TLS, Debug MSG:Cert ID Ok, Conf_Score:1
		Suggested Company: Cisco
	...

Domain: jeniustoto.net
	Infered Provider ID: N/A


Domain: sgnetway.net
	ID:sgnetway.net, Type:OK, Source:Banner/EHLO, Debug MSG:Banner/EHLO ID Ok, Conf_Score:1
	...

Domain: bbw-chan.nl
	ID:bbw-chan.nl, Type:OK, Source:MX, Debug MSG:MX RD Ok, Conf_Score:1
	...

Domain: utexas.edu
	ID:utexas.edu, Type:OK, Source:TLS, Conf_Score:1
		Heuristics suggests new provider id: iphmx.com, reason: All IPs are in Cisco Ironport's AS
		Suggested company: Cisco
	...

Domain: summitorganization.org
	ID:secureserver.net, Type:OK, Source:Banner/EHLO, Conf_Score:1
		Heuristics suggests that this provider id might NOT be accurate, reason: FQDN (s132-148-130-121.secureserver.net) used by Banner/EHLO Indicates Potentially VPS
	...

Domain: arfonts.net
	ID:ovh.net, Type:OK, Source:Banner/EHLO, Conf_Score:1
		Heuristics suggests that this provider id might NOT be accurate, reason: FQDN (vps797297.ovh.net) used by Banner/EHLO Indicates Potentially VPS
	...
```

### Providers of domains
You can probe domains of your choice.
```
python3 demo_mx_inference.py --domains eng.ucsd.edu ucsd.edu
```
Sample output:
```
...
Domain: eng.ucsd.edu
	ID:google.com, Type:OK, Source:TLS, Debug MSG:Cert ID Ok, Conf_Score:1
		Suggested Company: Google
	...

Domain: ucsd.edu
	ID:pphosted.com, Type:OK, Source:TLS, Debug MSG:Cert ID Ok, Conf_Score:1
		Suggested Company: ProofPoint
	...
```

### Load saved data from path
You can load domains saved locally and run the inference program on those domains.
```
python3 demo_mx_inference.py --load_data_from_path=/path/to/saved/data
```

### Other Arguments
```
--disable_tls: do not use TLS certificates for inference
--disable_banner: do not use banner/EHLO information for inference
--disable_heuristics: do not apply any heuristics
--heuristics_threshold: apply heuristics when confidence score <= threshold
--disable_heuristics_as: do not use heuristics that are based on AS information
--disable_heuristics_tls_pattern: do not use heuristics that are based on TLS FQDN pattern
--disable_heuristics_banner_pattern: do not use heuristics that are based on Banner/EHLO FQDN pattern
--map_id_to_company: Try mapping provider id to company. Default: True
--save_scan_data: Save scanned data of domains. Default: True
--debug: Debug information level. 0 = Minimum, 1 = Light, 2 = Verbose. Default: 0.
```

## Project Structure
    mx_inference
    ├── ...
    ├── lib/                       # Libraries
    │   ├── certs/                 # CA/Intermediate Certificates 
    │   ├── cert.py                # Handle certificates
    │   ├── ds.py                  # Data structures
    │   ├── extract_domain.py      # Extract domain from strings
    │   ├── helper.py              # I/O helper functions
    │   ├── heuristics.py          # Heuristics
    │   ├── inference_funcs.py     # Inference functions
    │   ├── network_lib.py         # Network functions
    │   ├── preprocess.py          # Preprocessing certs
    │   └── union_find.py          # Union find algorithm
    ├── config/                     
    │   └── config.py              # Configurations
    └── inference.py               # High-level wrapper for inferring mail providers of a domain


## Note
* This tool is not designed for large-scale analysis. Please use third-party datasets instead (e.g., [OpenINTEL](https://openintel.nl/) and [Censys](censys.io/)). 
* This tool is not tested with IPv6.
* This tool does NOT infer the eventual mail provider used by end users of domain.
* Use our heuristics with a grain of salt.


## Extending This Work
* **How do I import my own data?** If you have some data and want to use our tool, you add your own load data function in `helper.py`. An example function `load_domain_data_from_path_format_censys` can be found in `helper.py`.
* **How do I add other information for inference (e.g., rDNS of an IP)?** If you find the information we use (i.e., MX, Banner/EHLO, TLS) for inference is not satisfying, you can modify the data structures defined in `ds.py` and scanning functions defined in `network_lib.py`.
* **How do I add my own heuristics?** You can find our heuristics in `heuristics.py`


## Cite Our Paper
```
@inproceedings{MxInfer,
  title={Who's Got Your Mail? Characterizing Mail Service Provider Usage},
  author={Liu, Enze and Akiwate, Gautam and Jonker, Mattijs and Mirian, Ariana and Savage, Stefan and Voelker, Geoffrey M.},
  booktitle={ACM Internet Measurement Conference (IMC'21)},
  publisher={ACM},
  year      = {2021},
  address   = {Virtual Event},
  month     = {November}
}
```


## Bugs and Issues
This software is used and maintained for a research project and likely will have many bugs and issues. If you want to report any bugs or issues, please do it through the [Github Issue Page](https://github.com/ucsdsysnet/mx_inference/issues).
