import csv
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path
import argparse
import re

# Define Argument Parser for script file arguments
parser = argparse.ArgumentParser(description="CSV Network Finder", formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("--ip", help="IP Address to check for")
args = parser.parse_args()

# Define CSV file location
csvpath = "BGP_TABLE_20210212.CSV"

def readcsv(csvpath):
    # Read CSV and convert list of lists to dictionary
    with open(csvpath, "r") as csvfile:
        csvreader = csv.reader(csvfile, delimiter=';')
        bgpdict = { re.sub("[\[\]]","", re.sub("\:", " ", x[1])).lstrip().rstrip(): ip_network(x[0]) for x in csvreader }
    return bgpdict

def inputvalidation(argumentstring):
    # Validate entered IP address
    ip_list = []
    for ip in argumentstring.split(','):
        try:
            ip_list.append(ip_address(ip))
        except:
            print("{ip} Not a valid IP address, ignoring...\n======================".format(ip=ip))
    return ip_list

def networklookup(bgpdict, lookupip):
    output = []
    resultsdict = {}
    # Do the actual crosscheck
    for ip in lookupip:
        resultsdict[ip] = []
        for name, network in bgpdict.items():
            if ip in network:
                resultsdict[ip].append(name)
    
    for key, value in resultsdict.items():
        if len(value) > 0:
            output.append("{ip} is in this VRF:".format(ip=key))
            for entry in value:
                output.append("VRF {vrf}, subnet {nw}".format(vrf=entry, nw=bgpdict[entry]))
            output.append("======================")
        else:
            output.append("{ip} is not in the BGP table".format(ip=ip))
    return output

print('\n'.join(networklookup(readcsv(csvpath),inputvalidation(args.ip))))
