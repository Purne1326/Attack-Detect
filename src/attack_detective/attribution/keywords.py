"""Extra network-behaviour keywords per ATT&CK technique ("enriched" index).

RULES
1. Write keywords from the ATT&CK technique page and general networking knowledge only.
2. Never copy wording from the feature dictionary (explain/feature_dictionary.py) and never use CICIDS label names
   (PortScan, Patator, Hulk, GoldenEye, slowloris, ...). Otherwise attribution is not fair.
3. Report results both with (enriched) and without (plain) these keywords.
"""

KEYWORDS = {
    # Discovery / reconnaissance
    "T1046": "probing many ports and services on remote hosts; many short connection attempts; "
             "SYN probes that receive little or no response; resets; packets without payload",
    "T1595": "active scanning of remote infrastructure; many probe connections; short-lived flows; "
             "little data exchanged",
    "T1595.001": "scanning IP blocks; sweeping addresses; many connection attempts; few replies",
    "T1595.002": "vulnerability scanning; many requests to a server; probing responses",
    "T1018": "discovering remote systems on the network; ping sweeps; connection attempts to many hosts",
    # Credential access
    "T1110": "repeated authentication attempts; many short login sessions to the same service; "
             "similar small requests repeated; failed logins; credential guessing",
    "T1110.001": "password guessing; many login attempts against one account; repeated short sessions",
    "T1110.003": "password spraying; one password tried on many accounts; repeated login sessions",
    "T1110.004": "credential stuffing; many login attempts with stolen credentials",
    # Impact: denial of service
    "T1498": "network flood; extremely high packet rate and byte rate; bandwidth exhaustion; "
             "large volume of traffic toward a target",
    "T1498.001": "direct network flood; very high packet rate from sources toward the target",
    "T1498.002": "reflection amplification; large responses; very high byte rate",
    "T1499": "endpoint denial of service; exhausting server resources; many connections held "
             "open; slow partial requests; long idle connections; server stops replying",
    "T1499.002": "service exhaustion flood; very many requests to a web service; high request rate",
    "T1499.003": "application exhaustion flood; repeated expensive requests to an application",
    # Initial access / exploitation
    "T1190": "exploiting a public-facing web application; crafted or large HTTP requests; "
             "injected input in requests; unusual request payloads; server error responses",
    "T1189": "drive-by compromise via a website; malicious scripts delivered in web responses",
    "T1133": "access through external remote services; remote login from outside",
    # Command and control / exfiltration
    "T1071": "command and control over application layer protocols; regular periodic beaconing; "
             "small repeated messages; long-lived connection with idle periods",
    "T1071.001": "web protocols for command and control; periodic HTTP requests; small regular messages",
    "T1095": "non-application layer protocol for command and control; raw TCP or UDP channel",
    "T1571": "non-standard port used for communication",
    "T1105": "ingress tool transfer; downloading files to a compromised host; large inbound transfer",
    "T1041": "exfiltration over the command and control channel; large outbound data transfer",
    "T1048": "exfiltration over an alternative protocol; large outbound transfer",
    # Lateral movement
    "T1021": "remote services such as SSH, RDP or SMB used to log in to other hosts",
    "T1021.004": "SSH remote login sessions",
    "T1210": "exploitation of remote services on internal hosts",
}
