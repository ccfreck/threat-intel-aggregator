import ipaddress
import requests
import os
from dotenv import load_dotenv

load_dotenv()

virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")

def getShodanIP(ip_str):
    url = f"https://internetdb.shodan.io/{ip_str}"
    response = requests.get(url)

    data = response.json()
    print("-----SHODAN DATA-----")
    print("IP: ", data["ip"])
    print("Ports: ", data["ports"])
    print("Hostnames: ", data["hostnames"])
    print("cpes: ", data["cpes"])
    print("tags: ", data["tags"])
    print("vulns: ", data["vulns"])
    print("---------------------")


def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def main():
    ip_str = "8.8.8.8"
    validIP = is_valid_ip(ip_str)

    if validIP:
        getShodanIP(ip_str)

if __name__ == "__main__":
    main()

