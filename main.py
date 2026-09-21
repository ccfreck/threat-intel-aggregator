import ipaddress
import requests
import os
from dotenv import load_dotenv

load_dotenv()

# KEY DECLARATIONS
virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")

# Shodan will return results freely, parse data into readable format
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

# VT get json response, parse meaningful data
def getVirusTotalIP(ip_str):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_str}"

    # VT will only give the response given their api key to validate, must pass in headers
    headers = {
        "x-apikey":virustotal_key
    }

    response = requests.get(url, headers=headers)
    data = response.json()
    attributes = data["data"]["attributes"]

    # useful data because VT will send SO much information
    print("-----VIRUSTOTAL DATA-----")
    print("IP:", data["data"]["id"])
    print("Reputation:", attributes["reputation"])
    print("Analysis Stats:", attributes["last_analysis_stats"])
    print("Country:", attributes["country"])
    print("Continent:", attributes["continent"])
    print("ASN:", attributes["asn"])
    print("AS Owner:", attributes["as_owner"])
    print("Network:", attributes["network"])
    print("Last Analysis:", attributes["last_analysis_date"])
    print("Tags:", attributes["tags"])
    print("-------------------------")

# try/catch to determine if the ip is valid using ipaddress package
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
        getVirusTotalIP(ip_str)

if __name__ == "__main__":
    main()

