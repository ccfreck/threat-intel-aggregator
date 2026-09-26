After calling each API function, `main()` creates one dictionary containing the results:

```python
shodan_data = getShodanIP(ip_str)

virustotal_data = getVirusTotalIP(ip_str)

abuseipdb_data = getAbuseIPDB(ip_str)

report = {
    "ip": ip_str,
    "shodan": shodan_data,
    "virustotal": virustotal_data,
    "abuseipdb": abuseipdb_data
}
```

The structure looks like:

```text
report
│
├── ip
│   └── "8.8.8.8"
│
├── shodan
│   ├── ip
│   ├── ports
│   ├── hostnames
│   ├── cpes
│   ├── tags
│   └── vulns
│
├── virustotal
│   ├── reputation
│   ├── last_analysis_stats
│   ├── country
│   ├── continent
│   ├── asn
│   ├── as_owner
│   ├── network
│   ├── last_analysis_date
│   └── tags
│
└── abuseipdb
    ├── ipAddress
    ├── abuseConfidenceScore
    ├── isp
    ├── hostnames
    ├── totalReports
    └── lastReportedAt
```

Validating each threat intel source's return val:

SHODAN:

```python
return response.json()
```

i.e.,

```json
{
    "ip": "8.8.8.8",
    "ports": [53, 443],
    "hostnames": ["dns.google"],
    "cpes": [],
    "tags": [],
    "vulns": []
}
```

VIRUS_TOTAL:

```python
return response.json()["data"]["attributes"]
```

to get meaningful values.

i.e.,

```json
{
    "data": {
        "type": "ip_address",
        "id": "8.8.8.8",
        "attributes": {
            "reputation": 0,
            "country": "US",
            "continent": "NA",
            "asn": 15169,
            "as_owner": "Google LLC",
            "network": "8.8.8.0/24",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 90,
                "harmless": 0
            },
            "tags": [],
            ...
        }
    }
}
```

ABUSEIPDB:

```python
return response.json()["data"]
```

i.e.,

```json
{
    "data": {
        "ipAddress": "8.8.8.8",
        "abuseConfidenceScore": 0,
        "isp": "Google LLC",
        "hostnames": ["dns.google"],
        "totalReports": 0,
        "lastReportedAt": None
    }
}
```