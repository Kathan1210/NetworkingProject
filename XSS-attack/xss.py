import requests

filename = "payloads.txt"
with open(filename) as file:
    linecontent = file.readlines()

payloads = [x.strip() for x in linecontent]
url = input("Enter URL: ")
vulnerability = []
for payload in payloads:
    payload = payload
    url_xss = url + payload
    r = requests.get(url_xss)
    if payload.lower() in r.text.lower():
        print("Vulnerable: " + payload)
        if payload not in vulnerability:
            vulnerability.append(payload)
    else:
        print("Not vulnerable!")


