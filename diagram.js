```mermaid
flowchart TD
    A[Start Program] --> B[main()]
    
    B --> C[Set IP Address]
    C --> D[is_valid_ip(ip_str)]
    
    D -->|Valid IP| E[Query Threat Intelligence APIs]
    D -->|Invalid IP| F[Return False / Stop]

    E --> G[getShodanIP]
    E --> H[getVirusTotalIP]
    E --> I[getAbuseIPDB]

    G --> G1[Shodan API]
    G1 --> G2[Return Shodan JSON]

    H --> H1[VirusTotal API]
    H1 --> H2[Extract data.attributes]
    H2 --> H3[Return VirusTotal Attributes]

    I --> I1[AbuseIPDB API]
    I1 --> I2[Extract data]
    I2 --> I3[Return AbuseIPDB Data]

    G2 --> J[Create report dictionary]
    H3 --> J
    I3 --> J
    C --> J

    J --> K["report = {<br/>ip<br/>shodan<br/>virustotal<br/>abuseipdb<br/>}"]

    K --> L[printReport(report)]

    L --> M[Print Shodan Data]
    L --> N[Print VirusTotal Data]
    L --> O[Print AbuseIPDB Data]

    M --> P[Final Threat Intelligence Report]
    N --> P
    O --> P
```