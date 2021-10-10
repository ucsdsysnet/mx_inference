""" 
This file contains configurations. 
You can set configuration in demo_mx_inference.py
"""

CONFIG = {
    # Which functions to use to perform inference, use in that order
    'INFERENCE_FUNCTIONS': ['IDFromTLS','IDFromBanner','IDFromMX'], 

    # Comment out this part if you don't want to use heuristics
    'USE_HEURISTICS': {
        'THRESHOLD': 5, # Run heursitics on domains with confidence score <= THRESHOLD
        # Use AS to identify potential misidentifications
        # Use Banner pattern to identify potential misidentifications
        # Use TLS pattern to idenfity potential misidentifications
        'FUNCS' : ['AS','BANNER_PATTERN','CERT_PATTERN'],
    }, 

    # Try mapping provider id to company
    'PROVIDER_ID_TO_COMPANY' : True,

    'DEBUG_LEVEL': 0, # 0 = Minimum, 1 = Light, 2 = Verbose; when 0, only prints most preferred MX

    'SAVE_SCAN_DATA': True, # Save scanned data about a domain
}

