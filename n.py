import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

access_key = "f508eefcfa275aa5f76d317b6eb76bfcb8f68cf48bfd6803bdc667db097a209f"
secret_key = "e2a8764f65b5a6ab8996622d211e70413630a601069b1611f058a89249ba41fe"
scanner = "https://192.168.0.211:8834"

headers = {
    "X-ApiKeys": "accessKey=%s; secretKey=%s;" % (access_key, secret_key)
}


def api_path(path):
    return (scanner + path)


res = requests.get(api_path("/scans"), headers=headers, verify=False)
data = json.loads(res.text)

print(json.dumps(data, indent=2))
