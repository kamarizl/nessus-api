import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

access_key = "f508eefcfa275aa5f76d317b6eb76bfcb8f68cf48bfd6803bdc667db097a209f"
secret_key = "e2a8764f65b5a6ab8996622d211e70413630a601069b1611f058a89249ba41fe"
scanner = "https://192.168.0.211:8834"

headers = {"X-ApiKeys": "accessKey=%s; secretKey=%s;" % (access_key, secret_key)}


def api_path(path):
    return scanner + path


def get(path):
    res = requests.get(api_path(path), headers=headers, verify=False)
    return json.loads(res.text)


def all_scans():
    scans = get("/scans")
    scan_ids = [x["id"] for x in scans.get("scans")]
    scan_name = [x["name"] for x in scans.get("scans")]
    return list(zip(scan_ids, scan_name))


def get_scan_details(id):
    path = "/scans/" + str(id)
    return get(path)


def get_scans():
    data = []
    for scan in all_scans():
        scan_id = scan[0]
        scan_name = scan[1]
        scan_details = get_scan_details(scan_id)
        for x in scan_details.get("hosts"):
            host_id = x["host_id"]
            hostname = x["hostname"]
            data.append([scan_id, scan_name, host_id, hostname])

    return data


def get_host_details():
    data = []
    hosts = get_scans()

    for host in hosts:
        scan_id = host[0]
        scan_name = host[1]
        host_id = host[2]
        hostname = host[3]

        path = "/scans/%d/hosts/%d" % (host[0], host[2])
        details = get(path)
        os = details.get("info").get("operating-system")

        for vuln in details.get("vulnerabilities"):
            plugin_name = vuln.get("plugin_name")
            severity = vuln.get("severity")
            plugin_family = vuln.get("plugin_family")

            vuln_data = {
                "scan_id": scan_id,
                "scan_name": scan_name,
                "host_id": host_id,
                "hostname": hostname,
                "plugin_name": plugin_name,
                "plugin_family": plugin_family,
                "severity": severity,
            }

            data.append(vuln_data)

    return data


def main():
    data = get_host_details()
    print(json.dumps(data, indent=2))


main()
