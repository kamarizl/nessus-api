import os, sys
import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

access_key = "f508eefcfa275aa5f76d317b6eb76bfcb8f68cf48bfd6803bdc667db097a209f"
secret_key = "e2a8764f65b5a6ab8996622d211e70413630a601069b1611f058a89249ba41fe"
scanner = "https://192.168.0.211:8834"

headers = {"X-ApiKeys": "accessKey=%s; secretKey=%s;" % (access_key, secret_key)}

script_dirpath = os.path.dirname(os.path.join(os.getcwd(), __file__))
checkpoint_filepath = os.path.join(script_dirpath, "checkpoint_nessus")


def fetch(path):
    path = scanner + path
    r = requests.get(path, headers=headers, verify=False)
    return json.loads(r.text)

def log(f):
    # print("------")
    print(json.dumps(f, indent=2))

# start with checkpoint 0
last_checkpoint = 0

# check latest checkpoint
if os.path.isfile(checkpoint_filepath):
    with open(checkpoint_filepath, "r") as f:
        last_checkpoint = f.readline()

# tmp hack
last_checkpoint = 0

# request scan based on checkpoint last timestamp
scans = fetch("/scans?last_modification_date={}".format(last_checkpoint))

# update the checkpoint for next pull
with open(checkpoint_filepath, "w") as f:
    f.write(str(scans.get("timestamp")))

# if no scans data, exit the script
if not scans.get("scans"):
    sys.exit()

# just take completed scan
completed_scan = [x for x in scans.get("scans") if x.get("status") == "completed"]

base_vuln_placeholder = []

for scan in completed_scan:
    sname = scan.get("name")
    scan_id = scan.get("id")

    # get all the host in particular scan id
    hosts = fetch("/scans/{}".format(scan_id))
    host_ids = [x.get("host_id") for x in hosts.get("hosts")]

    # once we have all the ids, get vuln for that host
    for hostid in host_ids:
        details = fetch("/scans/{}/hosts/{}".format(scan_id, hostid))

        info = details.get("info")

        # enumerate all vuln
        for vuln in details.get("vulnerabilities"):

            # append every vuln with info
            info.update(vuln)
            info["scan-id"] = scan_id
            info["scan-name"] = sname
            vuln.update(info)

            # update into base_vuln_placeholder
            base_vuln_placeholder.append(vuln)

print("done here")
# get detail of the vulnerability
# for vuln in base_vuln_placeholder:

#     full_data = fetch(
#         "/scans/{}/hosts/{}/plugins/{}".format(
#             vuln["scan-id"], vuln["host_id"], vuln["plugin_id"]
#         )
#     )
    
#     # plugin_output = full_data["outputs"][0]['plugin_output']
#     risk_factor = full_data["info"]["plugindescription"]["pluginattributes"]["risk_information"]["risk_factor"]
#     solution = full_data["info"]["plugindescription"]["pluginattributes"]["solution"]
#     synopsis = full_data["info"]["plugindescription"]["pluginattributes"]["synopsis"]
#     description = full_data["info"]["plugindescription"]["pluginattributes"]["description"]
#     plugin_type = full_data["info"]["plugindescription"]["pluginattributes"]["plugin_information"]["plugin_type"]
    
#     for out in full_data["outputs"]:
#         log(out)

#     # log(full_data["info"]["plugindescription"]["pluginattributes"]["plugin_information"]["plugin_type"])
    
#     print("<<<<<<<<<<<<<<<<<<<")
#     break

# print("end")

# def item_generator(json_input, lookup_key):
#     if isinstance(json_input, dict):
#         for k, v in json_input.items():
#             if k == lookup_key:
#                 yield v
#             else:
#                 yield from item_generator(v, lookup_key)
#     elif isinstance(json_input, list):
#         for item in json_input:
#             yield from item_generator(item, lookup_key)


def json_extract(obj, key):
    """Recursively fetch values from nested JSON."""
    arr = []

    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    values = extract(obj, arr, key)
    return values


x = fetch("/scans/11/hosts/62/plugins/51192")
print(json_extract(x, "ports"))

print("end")