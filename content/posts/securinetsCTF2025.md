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


# Securinets CTF 2025 – Lost File

![mota](/images/securinets_2025/lostfile/mota.png)
Challenge name: **Lost File** 
Difficulty: **Easy** 
Describe: My friend told me to run this executable, but it turns out he just wanted to encrypt my precious file.
And to make things worse, I don’t even remember what password I used. 😳
Good thing I have this memory capture taken at a very convenient moment, right?
**author:** Kaizo
**link chall:** https://drive.google.com/file/d/1AO3nhe859X8DIA5DyMsulFplDv9ddkn-/view?usp=sharing

I began by loading disk.ad1 into FTK Imager and navigating to the victim profile Documents and Settings\RagdollFan2005\Desktop. Two files stood out immediately: the program locker_sim.exe and the ciphertext to_encrypt.txt.enc.
![image](/images/securinets_2025/lostfile/anh1.png)

- To understand the encryption, I reversed locker_sim.exe in Ghidra.
- In the main function, you just need to copy the code below and put it in chatgpt, it will explain.
```velocity

int __cdecl _main(int _Argc,char **_Argv,char **_Env)

{
  int iVar1;
  DWORD DVar2;
  int iVar3;
  BYTE *pBVar4;
  undefined4 *puVar5;
  CHAR *pCVar6;
  char local_69c [260];
  size_t local_598;
  void *local_594;
  size_t local_590;
  void *local_58c;
  char local_588 [260];
  undefined4 local_484;
  undefined4 local_480;
  undefined4 local_47c;
  undefined4 local_478;
  undefined4 local_474;
  undefined4 local_470;
  undefined4 local_46c;
  undefined4 local_468;
  size_t local_454;
  void *local_450;
  char local_44c [259];
  char cStack_349;
  CHAR local_348 [259];
  char cStack_245;
  undefined4 local_244 [64];
  undefined1 local_141;
  BYTE local_140 [255];
  undefined1 local_41;
  FILE *local_40;
  BYTE *local_3c;
  size_t local_38;
  int local_34;
  DWORD local_30;
  char *local_2c;
  size_t local_28;
  char *local_24;
  int *local_14;
  
  local_14 = &_Argc;
  ___main();
  if (_Argc < 2) {
    return 1;
  }
  local_2c = _Argv[1];
  pBVar4 = local_140;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    pBVar4[0] = '\0';
    pBVar4[1] = '\0';
    pBVar4[2] = '\0';
    pBVar4[3] = '\0';
    pBVar4 = pBVar4 + 4;
  }
  iVar3 = read_computername_from_registry(local_140,0x100);
  if (iVar3 != 0) {
    strncpy((char *)local_140,"UNKNOWN_HOST",0xff);
    local_41 = 0;
  }
  fflush((FILE *)(_iob_exref + 0x20));
  puVar5 = local_244;
  for (iVar3 = 0x41; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  pCVar6 = local_348;
  for (iVar3 = 0x41; iVar3 != 0; iVar3 = iVar3 + -1) {
    pCVar6[0] = '\0';
    pCVar6[1] = '\0';
    pCVar6[2] = '\0';
    pCVar6[3] = '\0';
    pCVar6 = pCVar6 + 4;
  }
  local_30 = _GetModuleFileNameA@12((HMODULE)0x0,local_348,0x104);
  if ((local_30 == 0) || (0x103 < local_30)) {
    local_244[0]._0_2_ = 0x2e;
  }
  else {
    for (local_24 = local_348 + (local_30 - 1);
        ((local_348 <= local_24 && (*local_24 != '\\')) && (*local_24 != '/'));
        local_24 = local_24 + -1) {
    }
    if (local_24 < local_348) {
      local_244[0]._0_2_ = 0x2e;
    }
    else {
      local_28 = (int)local_24 - (int)local_348;
      if (local_28 == 0) {
        strncpy((char *)local_244,local_348,0x103);
        local_141 = 0;
      }
      else {
        if (0x103 < local_28) {
          local_28 = 0x103;
        }
        strncpy((char *)local_244,local_348,local_28);
        *(undefined1 *)((int)local_244 + local_28) = 0;
      }
    }
  }
  local_34 = strlen((char *)local_244);
  if ((local_34 == 0) ||
     ((*(char *)((int)local_244 + local_34 + -1) != '\\' &&
      (*(char *)((int)local_244 + local_34 + -1) != '/')))) {
    _snprintf(local_44c,0x104,"%s\\secret_part.txt",local_244);
  }
  else {
    _snprintf(local_44c,0x104,"%ssecret_part.txt",local_244);
  }
  local_450 = (void *)0x0;
  local_454 = 0;
  read_file_to_buffer(local_44c,(int *)&local_450,&local_454);
  _DeleteFileA@4(local_44c);
  iVar3 = strlen(local_2c);
  iVar1 = strlen((char *)local_140);
  local_38 = local_454 + iVar3 + iVar1 + 10;
  local_3c = (BYTE *)malloc(local_38);
  if (local_454 == 0) {
    _snprintf((char *)local_3c,local_38,"%s|%s|",local_2c,local_140);
  }
  else {
    _snprintf((char *)local_3c,local_38,"%s|%s|%s",local_2c,local_140,local_450);
  }
  DVar2 = strlen((char *)local_3c);
  iVar3 = sha256_buf(local_3c,DVar2,(BYTE *)&local_474);
  if (iVar3 == 0) {
    local_484 = local_474;
    local_480 = local_470;
    local_47c = local_46c;
    local_478 = local_468;
    iVar3 = strlen((char *)local_244);
    if ((*(char *)((int)local_244 + iVar3 + -1) == '\\') ||
       (iVar3 = strlen((char *)local_244), *(char *)((int)local_244 + iVar3 + -1) == '/')) {
      _snprintf(local_588,0x104,"%sto_encrypt.txt",local_244);
    }
    else {
      _snprintf(local_588,0x104,"%s\\to_encrypt.txt",local_244);
    }
    local_58c = (void *)0x0;
    local_590 = 0;
    iVar3 = read_file_to_buffer(local_588,(int *)&local_58c,&local_590);
    if (iVar3 == 0) {
      local_594 = (void *)0x0;
      local_598 = 0;
      iVar3 = aes256_encrypt_simple
                        (&local_474,(BYTE *)&local_484,local_58c,local_590,&local_594,&local_598);
      if (iVar3 == 0) {
        iVar3 = strlen((char *)local_244);
        if ((*(char *)((int)local_244 + iVar3 + -1) == '\\') ||
           (iVar3 = strlen((char *)local_244), *(char *)((int)local_244 + iVar3 + -1) == '/')) {
          _snprintf(local_69c,0x104,"%sto_encrypt.txt.enc",local_244);
        }
        else {
          _snprintf(local_69c,0x104,"%s\\to_encrypt.txt.enc",local_244);
        }
        local_40 = (FILE *)fopen(local_69c,"wb");
        if (local_40 == (FILE *)0x0) {
          iVar3 = 1;
        }
        else {
          fwrite(local_594,1,local_598,local_40);
          fclose(local_40);
          if (local_450 != (void *)0x0) {
            free(local_450);
          }
          if (local_58c != (void *)0x0) {
            free(local_58c);
          }
          if (local_594 != (void *)0x0) {
            free(local_594);
          }
          free(local_3c);
          iVar3 = 0;
        }
        return iVar3;
      }
      puts("Encryption failed");
      return 1;
    }
    printf("Target file not found: %s\n");
    return 1;
  }
  puts("SHA256 failed");
  return 1;
}
```
**What the program does (logic of _main)**

- Requires exactly one CLI argument (argv[1]). If none, exits with 1.
- Reads COMPUTERNAME from the registry key
HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName.
- If it fails, it falls back to "UNKNOWN_HOST".
- Resolves the directory of the EXE (GetModuleFileNameA + manual dirname).
- Tries to read secret_part.txt from that directory and deletes it immediately after reading.
- Builds a single byte-exact string S into local_3c:
- If secret_part.txt was not read:
- S = argv1 + "|" + COMPUTERNAME + "|"
- If secret_part.txt was read:
- S = argv1 + "|" + COMPUTERNAME + "|" + secret_part_content
- Computes SHA-256(S) via sha256_buf.
- The 32-byte digest is split as follows:
- AES-256 key = the entire 32 bytes of the digest. (Pointer &local_474.)
- IV = the first 16 bytes of that same digest (they’re explicitly copied into local_484…, which is passed as the IV).
- Reads plaintext from to_encrypt.txt in the same directory.
- Calls aes256_encrypt_simple(key, iv, buf, len, &out, &outlen) which uses the Windows CryptoAPI to perform AES-256-CBC with PKCS#7 padding.
- Writes the ciphertext to to_encrypt.txt.enc in the same directory, frees buffers, and returns 0 on success.

**Variable/argument mapping (quick reference)**
- local_2c → argv[1] (the single required command-line argument). 
- local_140 → buffer that receives COMPUTERNAME from the registry.
- local_450 (+ local_454 size) → contents of secret_part.txt if it exists.
- local_3c → the assembled string S that is hashed.
- sha256_buf → produces the 32-byte digest into local_474…local_468.
- local_484…local_478 → copy of the first 16 bytes of the digest (used as IV).

Now we need to find 3 parts argv1, COMPUTERNAME, secret_part.
Start the first part:
```velocity
import sys
import os
def printable(s):
    return ''.join([chr(c) if 32 <= c < 127 else '.' for c in s])

def find_all(data, sub):
    start = 0
    while True:
        idx = data.find(sub, start)
        if idx == -1:
            return
        yield idx
        start = idx + 1
def extract_ascii(data, center_pos, pattern_len, back_limit=512, fwd_limit=2048):
    left = max(0, center_pos - back_limit)
    prev_bar = data.rfind(b'|', left, center_pos)
    if prev_bar == -1:
        argv1 = data[left:center_pos]
    else:
        argv1 = data[prev_bar+1:center_pos]
    right_search_start = center_pos + pattern_len
    right_search_end = min(len(data), right_search_start + fwd_limit)
    next_bar = data.find(b'|', right_search_start, right_search_end)
    if next_bar == -1:
        secret = data[right_search_start:right_search_end]
    else:
        secret = data[right_search_start:next_bar]

    return argv1, secret

def extract_utf16(data, center_pos, pattern_len, back_limit=1024, fwd_limit=4096):
    BAR = b'|\x00'
    left = max(0, center_pos - back_limit)
    prev_bar = data.rfind(BAR, left, center_pos)
    if prev_bar == -1:
        argv1_bytes = data[left:center_pos]
    else:
        argv1_bytes = data[prev_bar+len(BAR):center_pos]
    right_search_start = center_pos + pattern_len
    right_search_end = min(len(data), right_search_start + fwd_limit)
    next_bar = data.find(BAR, right_search_start, right_search_end)
    if next_bar == -1:
        secret_bytes = data[right_search_start:right_search_end]
    else:
        secret_bytes = data[right_search_start:next_bar]
    try:
        argv1 = argv1_bytes.decode('utf-16le', errors='ignore').strip('\x00')
    except Exception:
        argv1 = ''
    try:
        secret = secret_bytes.decode('utf-16le', errors='ignore').strip('\x00')
    except Exception:
        secret = ''
    return argv1, secret

def scan_for_cmdline_utf16(data, exe_hint=b'.exe'):
    results = []
    exe16 = b'.\x00e\x00x\x00e\x00'
    for pos in find_all(data, exe16):
        start = max(0, pos - 300)
        end = min(len(data), pos + 800)
        chunk = data[start:end]
        try:
            txt = chunk.decode('utf-16le', errors='ignore')
        except Exception:
            continue
        if '.exe' in txt:
            snippet = txt
            if len(snippet) > 400:
                snippet = snippet[:400]
            exe_idx = snippet.lower().find('.exe')
            has_arg = False
            if exe_idx != -1 and exe_idx + 4 < len(snippet):
                rest = snippet[exe_idx+4:]
                import re
                m = re.search(r'\s+(\S{1,80})', rest)
                has_arg = bool(m)
            if has_arg:
                results.append((start, snippet))
    return results

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 find_argv1_and_secret_from_mem.py mem.vmem COMPUTERNAME")
        sys.exit(1)
    mem_path = sys.argv[1]
    compname = sys.argv[2]
    if not os.path.exists(mem_path):
        print("File not found:", mem_path)
        sys.exit(1)

    with open(mem_path, 'rb') as f:
        data = f.read()
    patt_ascii = ('|' + compname + '|').encode('ascii', errors='ignore')
    hits_ascii = list(find_all(data, patt_ascii))
    comp16 = compname.encode('utf-16le', errors='ignore')
    patt_utf16 = b'|\x00' + comp16 + b'|\x00'
    hits_utf16 = list(find_all(data, patt_utf16))

    print("=== ASCII hits for pattern '|%s|' : %d ===" % (compname, len(hits_ascii)))
    argv1_candidates = set()
    secret_snippets = []
    for i, pos in enumerate(hits_ascii, 1):
        argv1_bytes, secret_bytes = extract_ascii(data, pos, len(patt_ascii))
        argv1_str = printable(argv1_bytes).strip()
        secret_str = printable(secret_bytes).strip()
        if argv1_str:
            argv1_candidates.add(argv1_str)
        secret_snippets.append(secret_str)
        print(f"\n-- ASCII HIT #{i} at offset {pos} --")
        print("argv1 (raw/printable):", repr(argv1_str[:120]))
        print("secret (snippet, printable):", repr(secret_str[:200]))

    print("\n=== UTF-16LE hits for pattern '|%s|' : %d ===" % (compname, len(hits_utf16)))
    for i, pos in enumerate(hits_utf16, 1):
        argv1_str, secret_str = extract_utf16(data, pos, len(patt_utf16))
        if argv1_str:
            argv1_candidates.add(argv1_str)
        print(f"\n-- UTF16 HIT #{i} at offset {pos} --")
        print("argv1 (utf16 decoded):", repr(argv1_str[:120]))
        print("secret (utf16 decoded, snippet):", repr(secret_str[:200]))
    print("\n=== Heuristic: UTF-16LE command line scans near '.exe' ===")
    cmd_hits = scan_for_cmdline_utf16(data)
    if not cmd_hits:
        print("(no obvious cmdline snippets found)")
    else:
        for idx, (off, snip) in enumerate(cmd_hits, 1):
            print(f"\n-- CMDLINE SNIPPET #{idx} around offset {off} --")
            print(snip)
    print("\n=== SUMMARY: argv1 candidates (deduplicated) ===")
    if argv1_candidates:
        for cand in sorted(argv1_candidates, key=lambda x: (len(x), x)):
            print("-", cand)
    else:
        print("(no argv1 candidates found; consider increasing limits or using Volatility 'cmdline'/'consoles')")

if __name__ == "__main__":
    main()
```
Run this code as follows:
```velocity=
python3 find_argv1_and_secret_from_mem.py mem.vmem RAGDOLLF-F9AC5A > argv1_scan.txt
```
We get the first part "hmmisitreallyts"
![image](/images/securinets_2025/lostfile/anh2.png)
The second part is "RAGDOLLF-F9AC5A"
![image](/images/securinets_2025/lostfile/anh3.png)
The third part we find it in the trash
We get the third part "sigmadroid"
![image](/images/securinets_2025/lostfile/anh4.png)
Now calculate the hash for it
![image](/images/securinets_2025/lostfile/anh5.png)
```velocity
KEY (SHA-256):
1117e5b8fdff9d7be375e7a88354c497b93788da64a3968621499687f10474e5
```
```velocity
IV = 16 byte đầu của KEY:
1117e5b8fdff9d7be375e7a88354c497
```
![image](/images/securinets_2025/lostfile/anh6.png)
flag is: Securinets{screen+registry+mft??}