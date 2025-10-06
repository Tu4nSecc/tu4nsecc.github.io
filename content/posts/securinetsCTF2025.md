---
title: "Securinets CTF 2025"
date: 2025-10-06T18:59:10+07:00
draft: false
categories: ["CTF", "writeup"]
cover: "/images/securinets_2025/SilentVisitor/mota.png"
---

SecurinetsCTF 2025 event link: https://quals.securinets.tn/

# Securinets CTF 2025 – Silent Visitor
![Challenge Banner](/images/securinets_2025/SilentVisitor/mota.png)

![image](/images/securinets_2025/SilentVisitor/anh1.png)
Challenge name: **Silent Visitor** 
Difficulty: **Easy** 
Describe: A user reported suspicious activity on their Windows workstation. Can you investigate the incident and uncover what really happened?
**author:** Enigma522
**link chall:** https://drive.google.com/file/d/1-nrWp4YFP0ULqQAHS2JNWzeLPyeiKbgQ/view?usp=sharing
## Question 1:
What is the SHA256 hash of the disk image provided?
- Given the provided disk image test.ad1, the task was to determine its SHA-256 hash. I computed it with:
```velocity
sha256sum test.ad1
```
- **answer:** 
```velocity
122b2b4bf1433341ba6e8fefd707379a98e6e9ca376340379ea42edb31a5dba2 
```
## Question 2:
Identify the OS build number of the victim’s system?
- I inspected the victim user's NTUSER.DAT hive and navigated to:
SOFTWARE → Microsoft → Windows NT → CurrentVersion → Winlogon.
![image](/images/securinets_2025/SilentVisitor/anh2.png)
- The BuildNumber value shown in the registry was 0x4a65 (hex). Converting that hex value to decimal:
![image](/images/securinets_2025/SilentVisitor/anh3.png)
- **answer:**  
```velocity
19045 
```
## Question 3:
What is the ip of the victim's machine?
- I examined the system’s registry under the path
ControlSet001\Services\Tcpip\Parameters\Interfaces\{GUID}
and found the DhcpIPAddress key.
The value of this key was 192.168.206.131, which indicates the IP address assigned to the victim’s machine via DHCP.
![image](/images/securinets_2025/SilentVisitor/anh4.png)
- **answer:**  
```velocity
192.168.206.131 
```
## Question 4:
What is the name of the email application used by the victim?
- I examined the user’s AppData\Roaming directory and found a folder path indicating the presence of an email client:
AppData → Roaming → Thunderbird → Profiles → 6red5uxz.default-release.
The “Thunderbird” folder clearly shows that the victim used Mozilla Thunderbird as their email application.
- **answer:**  
```velocity
Thunderbird
```
## Question 5:
What is the email of the victim?
## Question 6:
What is the email of the attacker?
- I inspected the victim’s Thunderbird mail store (Sent / Mail folders) and examined the email headers. The correspondence shows the victim’s address as ammar55221133@gmail.com and the correspondent as Mohamed Masmoudi with the address masmoudim522@gmail.com. From the headers and message threads, the attacker’s email address is masmoudim522@gmail.com
```velocity=
From - Sat Apr 05 17:44:52 2025
X-Mozilla-Status: 0001
X-Mozilla-Status2: 00000000
Return-Path: <ammar55221133@gmail.com>
Received: from [192.168.206.131] ([196.229.176.255])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ac7c013f80dsm319261066b.119.2025.04.04.15.34.34
 †††
 for <masmoudim522@gmail.com>
 †††
 (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
 †††
 Fri, 04 Apr 2025 15:34:35 -0700 (PDT)
Content-Type: multipart/alternative;
 boundary="------------raR1SEF8jeVEr70i0C3YovfW"
Message-ID: <935a0322-e611-4354-af36-de6b23274b1f@gmail.com>
Date: Sat, 5 Apr 2025 00:34:32 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: Project idea
To: mohamed Masmoudi <masmoudim522@gmail.com>
References: <CAJwm=751GYmE-TX1Mh+Gs=yWfBkxJHG-iWb8Kzd+n-QmkR+Ymg@mail.gmail.com>
Content-Language: en-US
From: ammar test <ammar55221133@gmail.com>
In-Reply-To: <CAJwm=751GYmE-TX1Mh+Gs=yWfBkxJHG-iWb8Kzd+n-QmkR+Ymg@mail.gmail.com>
This is a multi-part message in MIME format.
--------------raR1SEF8jeVEr70i0C3YovfW
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 8bit
nice can you send me what you did
On 4/5/2025 12:31 AM, mohamed Masmoudi wrote:
> Hope your week’s going okay :)
> So I was thinking for the class project, maybe we could build a small 
> Node.js API — something super basic, like a course registration thing 
> or a little student dashboard.
> I already played around with some boilerplate code to get us started. 
> I’ll clean it up a bit and share it with you.
> Let me know what you think!ro
--------------raR1SEF8jeVEr70i0C3YovfW
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 8bit
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  </head>
  <body>
    <p>nice can you send me what you did</p>
    <div class="moz-cite-prefix">On 4/5/2025 12:31 AM, mohamed Masmoudi
      wrote:<br>
    </div>
    <blockquote type="cite"
cite="mid:CAJwm=751GYmE-TX1Mh+Gs=yWfBkxJHG-iWb8Kzd+n-QmkR+Ymg@mail.gmail.com">
      <meta http-equiv="content-type" content="text/html; charset=UTF-8">
      <div dir="ltr">
 †††
 <p class="gmail-">Hope your week’s going okay :)</p>
 †††
 <p class="gmail-">So I was thinking for the class project, maybe
 ††††
 we could build a small Node.js API — something super basic,
          like a course registration thing or a little student
          dashboard.</p>
        <p class="gmail-">I already played around with some boilerplate
 ††††
 code to get us started. I’ll clean it up a bit and share it
          with you.</p>
 †††
 <p class="gmail-">Let me know what you think!ro</p>
        <br>
      </div>
    </blockquote>
  </body>
</html>
--------------raR1SEF8jeVEr70i0C3YovfW--
From - Sat Apr 05 17:50:33 2025
Content-Type: multipart/alternative;
 boundary="------------q85m0GUDIiuretamoqJ1I1Zi"
Message-ID: <791576c6-9bef-4f9b-800a-426212cd75e6@gmail.com>
Date: Sat, 5 Apr 2025 19:50:28 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: run this
To: mohamed Masmoudi <masmoudim522@gmail.com>
References: <CAJwm=77ngOVR=zxaYaB78WHQ=NebedFi1stLmNCYp-biF+Qm5g@mail.gmail.com>
Content-Language: en-US
From: ammar <ammar55221133@gmail.com>
In-Reply-To: <CAJwm=77ngOVR=zxaYaB78WHQ=NebedFi1stLmNCYp-biF+Qm5g@mail.gmail.com>
This is a multi-part message in MIME format.
--------------q85m0GUDIiuretamoqJ1I1Zi
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 8bit
thanks
On 4/5/2025 5:44 PM, mohamed Masmoudi wrote:
> Hey hey!
> Just pushed up the starter code here:
 https://github.com/lmdr7977/student-api
> You can just clone it and run |npm install|, then |npm run dev| to get 
> it going. Should open on port 3000.
> I set up a couple of helpful scripts in there too, so feel free to 
> tweak whatever.
> Lmk if anything’s broken 
--------------q85m0GUDIiuretamoqJ

```
- **answer:** 
```velocity
ammar55221133@gmail.com
```
- **answer:** 
```velocity
masmoudim522@gmail.com
```
## Quetion 7:
What is the URL that the attacker used to deliver the malware to the victim?
![image](/images/securinets_2025/SilentVisitor/anh5.png)
- I examined the repository referenced in the victim’s mail (https://github.com/lmdr7977/student-api) and opened the package.json. The postinstall script contained an EncodedCommand which, after Base64 decoding, produced the following PowerShell snippet:
![image](/images/securinets_2025/SilentVisitor/anh6.png)
- This shows the attacker delivered the malware using the URL https://tmpfiles.org/dl/23860773/sys.exe
- **answer:** 
```velocity
https://tmpfiles.org/dl/23860773/sys.exe
```
## Quetion 8:
What is the SHA256 hash of the malware file?
![image](/images/securinets_2025/SilentVisitor/anh7.png)
- I uploaded the malware file sys.exe to VirusTotal for analysis. The report indicated that 10 out of 72 security vendors flagged it as malicious.
Under the Details tab, the SHA-256 hash of the file was listed as:
- **answer:** 
```velocity
be4f01b3d537b17c5ba7dc1bb7cd4078251364398565a0ca1e96982cff820b6d
```
Quetion 9:
## What is the IP address of the C2 server that the malware communicates with?
Quetion 10:
## What port does the malware use to communicate with its Command & Control (C2) server?
- I reviewed the VirusTotal analysis for the sys.exe sample. Under the Contacted URLs and Contacted IP addresses sections the sample shows requests to http://40.113.161.85:5000/..., indicating the malware contacted the host at IP 40.113.161.85 on port 5000.
![image](/images/securinets_2025/SilentVisitor/anh8.png)
- **answer:** 
```velocity
40.113.161.85
```
- **answer:** 
```velocity
5000
```
## Quetion 11:
What is the url if the first Request made by the malware to the c2 server?
- In the malware behavior section I inspected the network communication logs. The first HTTP request shown is a GET to:
http://40.113.161.85:5000/helppppiscofebabe23
This confirms the initial C2 request path used by the sample.
![image](/images/securinets_2025/SilentVisitor/anh9.png)
- **answer:** 
```velocity
http://40.113.161.85:5000/helppppiscofebabe23
```
## Quetion 12:
The malware created a file to identify itself. What is the content of that file?
- In the behavior analysis section of the malware report, I noticed the malware created and wrote to the file:
C:\Users\Public\Documents\id.txt.
I then located and examined this file in the forensic image. The file contained the following unique identifier string:
![image](/images/securinets_2025/SilentVisitor/anh10.png)
![image](/images/securinets_2025/SilentVisitor/anh11.png)
- This indicates the malware likely used it as a unique ID to identify the infected host.
- **answer:** 
```velocity
3649ba90-266f-48e1-960c-b908e1f28aef
```
## Quetion 13:
Which registry key did the malware modify or add to maintain persistence?
![image](/images/securinets_2025/SilentVisitor/anh12.png)
In the behavioral analysis section of the VirusTotal report, I observed the registry activity performed by the malware. It accessed and modified several keys under HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE.
Among them, the key: 
- **answer:** 
```velocity
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyApp
```
- was specifically added to ensure persistence — causing the malicious executable to run automatically whenever the user logs in.
## Quetion 14:
What is the content of this registry?
- In the behavior analysis section of the report, I found that the malware wrote a file named sys.exe to the victim’s Documents directory:
C:\Users\<USER>\Documents\sys.exe.
By examining the infected user’s directory (C:\Users\ammar\Documents\), I confirmed that the same file sys.exe was present there.
This indicates that the malware dropped its payload in the user’s Documents folder.
![image](/images/securinets_2025/SilentVisitor/anh13.png)
- **answer:** 
```velocity
C:\Users\ammar\Documents\sys.exe
```
## Quetion 15:
The malware uses a secret token to communicate with the C2 server. What is the value of this key?
- I performed a string search on the sys.exe file using the command:
```velocity
strings sys.exe | grep "main.secret"
```
- The result revealed a hardcoded secret key used by the malware to authenticate or communicate with its Command & Control (C2) server.
The extracted key value is:e7bcc0ba5fb1dc9cc09460baaa2a6986
- **answer:** 
```velocity
e7bcc0ba5fb1dc9cc09460baaa2a6986
```