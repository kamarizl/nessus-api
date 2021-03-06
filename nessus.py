import json
import os
import sys

import requests
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
    print(json.dumps(f, indent=2))


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


# start with checkpoint 0
last_checkpoint = 0

# check latest checkpoint
if os.path.isfile(checkpoint_filepath):
    with open(checkpoint_filepath, "r") as f:
        last_checkpoint = f.readline()

# tmp hack
# last_checkpoint = 0

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


# get detail of the vulnerability
for vuln in base_vuln_placeholder:

    full_data = fetch(
        "/scans/{}/hosts/{}/plugins/{}".format(
            vuln["scan-id"], vuln["host_id"], vuln["plugin_id"]
        )
    )

    vuln["plugin_output"] = json_extract(full_data, "plugin_output")[0]
    vuln["risk_factor"] = json_extract(full_data, "risk_factor")[0]
    vuln["solution"] = json_extract(full_data, "solution")[0]
    vuln["synopsis"] = json_extract(full_data, "synopsis")[0]
    vuln["description"] = json_extract(full_data, "description")[0]
    vuln["plugin_type"] = json_extract(full_data, "plugin_type")[0]

    if not json_extract(full_data, "cvss3_base_score"):
        vuln["cvss3_base_score"] = "0.0"
    else:
        vuln["cvss3_base_score"] = json_extract(full_data, "cvss3_base_score")[0]

    if not json_extract(full_data, "cvss_base_score"):
        vuln["cvss_base_score"] = "0.0"
    else:
        vuln["cvss_base_score"] = json_extract(full_data, "cvss_base_score")[0]

    if not json_extract(full_data, "cvss3_vector"):
        vuln["cvss3_vector"] = "null"
    else:
        vuln["cvss3_vector"] = json_extract(full_data, "cvss3_vector")[0]

    if not json_extract(full_data, "cvss_vector"):
        vuln["cvss_vector"] = "null"
    else:
        vuln["cvss_vector"] = json_extract(full_data, "cvss_vector")[0]

    # affected port/service
    if full_data["outputs"]:
        for output in full_data["outputs"]:
            vuln["ports"] = [key for key in output["ports"]]

    if full_data["info"]["plugindescription"]["pluginattributes"].get("see_also"):
        vuln["see_also"] = [
            x
            for x in full_data["info"]["plugindescription"]["pluginattributes"][
                "see_also"
            ]
        ]
    else:
        vuln["see_also"] = "null"
    
    # additional info on vulnerability
    plugin_attribute = fetch("/plugins/plugin/{}".format(vuln["plugin_id"]))
    att = plugin_attribute.get("attributes")
    vuln["cve"] = [a.get("attribute_value") for a in att if a.get("attribute_name") == "cve"]
    vuln["exploit_available"] = [a.get("attribute_value") for a in att if a.get("attribute_name") == "exploit_available"]
    vuln["exploitability_ease"] = [a.get("attribute_value") for a in att if a.get("attribute_name") == "exploitability_ease"]
    vuln["xref"] = [a.get("attribute_value") for a in att if a.get("attribute_name") == "xref"]
    vuln["vuln_publication_date"] = [a.get("attribute_value") for a in att if a.get("attribute_name") == "vuln_publication_date"]

    # stream to splunk
    print(json.dumps(vuln))

    # break
