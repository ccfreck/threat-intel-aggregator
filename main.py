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
    # print("-----SHODAN DATA-----")
    # print("IP: ", data["ip"])
    # print("Ports: ", data["ports"])
    # print("Hostnames: ", data["hostnames"])
    # print("cpes: ", data["cpes"])
    # print("tags: ", data["tags"])
    # print("vulns: ", data["vulns"])
    # print("---------------------")
    return data

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
    # print("-----VIRUSTOTAL DATA-----")
    # print("IP:", data["data"]["id"])
    # print("Reputation:", attributes["reputation"])
    # print("Analysis Stats:", attributes["last_analysis_stats"])
    # print("Country:", attributes["country"])
    # print("Continent:", attributes["continent"])
    # print("ASN:", attributes["asn"])
    # print("AS Owner:", attributes["as_owner"])
    # print("Network:", attributes["network"])
    # print("Last Analysis:", attributes["last_analysis_date"])
    # print("Tags:", attributes["tags"])
    # print("-------------------------")
    return attributes

def getAbuseIPDB(ip_str):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": abuseipdb_key,
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, params={"ipAddress": ip_str})
    data = response.json()
    attributes = data["data"]
    # print("-----ABUSEIPDB DATA-----")
    # print("IP:", attributes["ipAddress"])
    # print("Abuse Confidence Score:", attributes["abuseConfidenceScore"])
    # print("ISP:", attributes["isp"])
    # print("Hostnames:", attributes["hostnames"])
    # print("Total Reports:", attributes["totalReports"])
    # print("Last Reported:", attributes["lastReportedAt"])
    # print("------------------------")
    return attributes

def printReport(report):
    print("\n========== THREAT INTELLIGENCE REPORT ==========")
    print("IP:", report["ip"])

    print("\n----- SHODAN -----")
    print("Ports:", report["shodan"]["ports"])
    print("Hostnames:", report["shodan"]["hostnames"])
    print("CPEs:", report["shodan"]["cpes"])
    print("Tags:", report["shodan"]["tags"])
    print("Vulnerabilities:", report["shodan"]["vulns"])

    print("\n----- VIRUSTOTAL -----")
    print("Reputation:", report["virustotal"]["reputation"])
    print("Analysis Stats:", report["virustotal"]["last_analysis_stats"])
    print("Country:", report["virustotal"]["country"])
    print("Continent:", report["virustotal"]["continent"])
    print("ASN:", report["virustotal"]["asn"])
    print("AS Owner:", report["virustotal"]["as_owner"])
    print("Network:", report["virustotal"]["network"])
    print("Last Analysis:", report["virustotal"]["last_analysis_date"])
    print("Tags:", report["virustotal"]["tags"])

    print("\n----- ABUSEIPDB -----")
    print("Abuse Confidence Score:", report["abuseipdb"]["abuseConfidenceScore"])
    print("ISP:", report["abuseipdb"]["isp"])
    print("Hostnames:", report["abuseipdb"]["hostnames"])
    print("Total Reports:", report["abuseipdb"]["totalReports"])
    print("Last Reported:", report["abuseipdb"]["lastReportedAt"])

    print("\n================================================")

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
        abuseipdb_data = getAbuseIPDB(ip_str)
        vt_data = getVirusTotalIP(ip_str)
        shodan_data = getShodanIP(ip_str)

        report = {
            "ip": ip_str,
            "shodan": shodan_data,
            "virustotal": vt_data,
            "abuseipdb":abuseipdb_data
        }
        printReport(report)

if __name__ == "__main__":
    main()

