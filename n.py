import requests

# access key f508eefcfa275aa5f76d317b6eb76bfcb8f68cf48bfd6803bdc667db097a209f
# secret key e2a8764f65b5a6ab8996622d211e70413630a601069b1611f058a89249ba41fe

access_key = "f508eefcfa275aa5f76d317b6eb76bfcb8f68cf48bfd6803bdc667db097a209f"
secret_key = "e2a8764f65b5a6ab8996622d211e70413630a601069b1611f058a89249ba41fe"

scanner = "https://192.168.0.211:8834/scans"

headers = {
    "X-ApiKeys": "accessKey=%s; secretKey=%s;" % (access_key, secret_key)
}

res = requests.get(scanner, headers=headers, verify=False)
print(res.text)
