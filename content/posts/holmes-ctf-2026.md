---
title: "Holmes CTF 2026"
date: 2026-09-17T14:20:00+07:00
draft: false
description: "Holmes CTF 2026 writeups: Paper Ghost and DIOGENES Sherlock 08."
categories: ["CTF", "writeup", "forensics"]
cover: "/images/holmes_2026/paper_ghost/anh1.png"
---

Paper Ghost challenge link: https://drive.google.com/drive/folders/1SCN6WeJOJ1yRRv5zTcL_T0W5MmW4Aj54?usp=sharing

# Paper Ghost

Challenge name: **Paper Ghost**

Difficulty: **Easy**

Category: **Digital Forensics / Windows Forensics**

Describe: The story will unfold through the PDFs provided with each challenge's downloadable ZIP. All characters, locations and events are fictional. Any resemblance to real people, places or events is purely coincidental.

**link chall:** https://drive.google.com/drive/folders/1SCN6WeJOJ1yRRv5zTcL_T0W5MmW4Aj54?usp=sharing

- The challenge provides a Windows triage collection. The investigation mainly uses Windows Registry artifacts, Recent files and Jump Lists, SRUM network usage data, and the Windows Search index.

- The main tools used during the investigation were:

```velocity
Registry Explorer
LECmd
JLECmd
Timeline Explorer
SrumECmd
WindowsEDB-to-CSV.exe
Sublime Text
```

---

## Question 1:

The rookie's first move was a planted USB. When did Clara Voss first connect the device Elias Venn left at her desk? `(YYYY-MM-DD hh:mm:ss)`

- Since the question asks about the first connection of a USB device, I started with the `SYSTEM` registry hive:

```velocity
Triage\C\Windows\System32\config\SYSTEM
```

- I loaded the hive into Registry Explorer and inspected the USB artifacts. The relevant device was a Lexar USB flash drive.

- The raw USB storage information is under:

```velocity
SYSTEM\ControlSet001\Enum\USBSTOR
```

- Registry Explorer also provides a parsed USB view containing fields such as `Installed`, `First Installed`, `Last Connected`, and `Last Removed`.

- The Lexar USB entry showed:

```velocity
First Installed: 2026-08-19 15:35:50
```

![image](/images/holmes_2026/paper_ghost/usb.png)

<!-- Ảnh cần chụp: Registry Explorer ở tab USB hoặc USBSTOR. Chụp nguyên dòng của Lexar USB, để thấy rõ Serial Number, First Installed, Last Connected và Last Removed. Quan trọng nhất là First Installed = 2026-08-19 15:35:50. -->

- The first installation time corresponds to the first time Windows enumerated this specific removable device on the workstation.

- **answer:**

```velocity
2026-08-19 15:35:50
```

---

## Question 2:

Every USB carries a serial scar. What serial number did the dropped device leave behind? `(string)`

- I continued with the same USB and expanded the raw `USBSTOR` registry tree:

```velocity
SYSTEM
\ControlSet001
\Enum
\USBSTOR
\Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00
```

- The child key under the Lexar device was:

```velocity
RS200000000627E4&0
```

- This is the complete device instance serial stored by Windows. The `&0` suffix is part of the raw device-instance key and must be included.

![image](/images/holmes_2026/paper_ghost/anh2.png)

<!-- Ảnh cần chụp: Registry Explorer với cây bên trái mở tới USBSTOR -> Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00 -> RS200000000627E4&0. Phải để nhìn rõ toàn bộ serial, đặc biệt phần &0. -->

- **answer:**

```velocity
RS200000000627E4&0
```

---

## Question 3:

VON BORK's payload hid inside a fake update package Elias delivered. What is the full path of the payload? `(full path of file, starting with drive letter)`

- The challenge refers to a fake update package, so I first checked the user's Recent files. One interesting shortcut was:

```velocity
Driver Update Package.lnk
```

- Parsing the shortcut with LECmd showed that it pointed to:

```velocity
C:\Users\cvoss\Desktop\DIOGENES_26\Driver Update Package.pdf
```

- That PDF was the lure, but the question asks for the actual malicious payload. I then checked program-execution artifacts inside Clara Voss's `NTUSER.DAT`.

- In Registry Explorer, I opened:

```velocity
NTUSER.DAT
\Software
\Microsoft
\Windows NT
\CurrentVersion
\AppCompatFlags
\Compatibility Assistant
\Store
```

- The PCA Store contained an entry related to:

```velocity
CO-LT-0469 update package\update.exe
```

- I then checked UserAssist:

```velocity
NTUSER.DAT
\Software
\Microsoft
\Windows
\CurrentVersion
\Explorer
\UserAssist
```

- Registry Explorer decoded the UserAssist data and showed the complete executable path:

```velocity
E:\CO-LT-0469 update package\update.exe
```

![image](/images/holmes_2026/paper_ghost/anh3.png)

<!-- Ảnh cần chụp: Registry Explorer tab UserAssist. Chụp dòng E:\CO-LT-0469 update package\update.exe và để lộ các cột Program Name, Run Counter và Last Executed. Ảnh này dùng được cho cả câu 3 và câu 4. -->

- **answer:**

```velocity
E:\CO-LT-0469 update package\update.exe
```

---

## Question 4:

Believing it a routine update, Voss launched the spyware. At what exact timestamp did she execute the malicious package? `(YYYY-MM-DD hh:mm:ss)`

- The UserAssist entry from the previous question also records the last execution time for the program.

- The relevant row contained:

```velocity
Program Name:  E:\CO-LT-0469 update package\update.exe
Run Counter:   1
Last Executed: 2026-08-19 15:36:25
```

- This also fits the incident timeline: the USB was first connected at `15:35:50`, and the malicious update was executed only 35 seconds later.

![image](/images/holmes_2026/paper_ghost/anh4.png)

<!-- Ảnh cần chụp: Có thể dùng lại ảnh câu 3. Nếu muốn tách riêng, crop sát dòng update.exe và cột Last Executed = 2026-08-19 15:36:25. -->

- **answer:**

```velocity
2026-08-19 15:36:25
```

---

## Question 5:

DIOGENES tagged the USB with an asset name that surfaced as the device name on connection. What was it? `(string)`

- The question asks for the device name that Windows displayed when the USB was connected.

- In the normal USBSTOR key, the Lexar device had the generic name:

```velocity
Lexar USB Flash Drive USB Device
```

- I then checked the software-device enumeration data at:

```velocity
SYSTEM
\ControlSet001
\Enum
\SWD
\WPDBUSENUM
```

- The entry associated with the Lexar removable device contained:

```velocity
FriendlyName = CO-USB-0091
```

![image](/images/holmes_2026/paper_ghost/CO-USB-0091.png)

<!-- Ảnh cần chụp: Registry Explorer tại SYSTEM\ControlSet001\Enum\SWD\WPDBUSENUM. Chọn đúng entry liên quan Lexar USB và chụp bảng Values bên phải, trong đó FriendlyName = CO-USB-0091 phải nhìn rõ. -->

- There was also another device entry named `VTOYEFI`, but that represented a different volume/device component. The asset-style name associated with the USB was `CO-USB-0091`.

- **answer:**

```velocity
CO-USB-0091
```

---

## Question 6:

Once C2 Access was live, VON BORK's listening post woke the microphone to spy on Voss's meetings. At what time did capture begin? `(YYYY-MM-DD hh:mm:ss)`

- Since the question specifically mentions microphone access, I checked the Windows Capability Access Manager records in Clara Voss's `NTUSER.DAT`:

```velocity
NTUSER.DAT
\Software
\Microsoft
\Windows
\CurrentVersion
\CapabilityAccessManager
\ConsentStore
\microphone
\NonPackaged
```

- Under `NonPackaged`, there was an entry for the malicious executable:

```velocity
E:#CO-LT-0469 update package#update.exe
```

- The `#` characters represent path separators in this registry structure.

- The values were:

```velocity
LastUsedTimeStart = 134316274881131799
LastUsedTimeStop  = 134316276632589248
```

![image](/images/holmes_2026/paper_ghost/microphone.png)

<!-- Ảnh cần chụp: Registry Explorer tại ConsentStore\microphone\NonPackaged\E:#CO-LT-0469 update package#update.exe. Chụp cả cây registry bên trái và hai value LastUsedTimeStart, LastUsedTimeStop bên phải. -->

- These values are Windows FILETIME timestamps. Converting `LastUsedTimeStart` gives:

```velocity
2026-08-19 15:38:08
```

- **answer:**

```velocity
2026-08-19 15:38:08
```

---

## Question 7:

VON BORK mapped Voss's office through her webcam — who came and went, what lay on her desk. For how many seconds did the webcam stream? `(number)`

- The question now asks about webcam usage, so I checked the corresponding webcam entry in the same Capability Access Manager data:

```velocity
NTUSER.DAT
\Software
\Microsoft
\Windows
\CurrentVersion
\CapabilityAccessManager
\ConsentStore
\webcam
\NonPackaged
\E:#CO-LT-0469 update package#update.exe
```

- The malware entry contained:

```velocity
LastUsedTimeStart = 134316277486814313
LastUsedTimeStop  = 134316278756619812
```

![image](/images/holmes_2026/paper_ghost/webcam.png)

<!-- Ảnh cần chụp: Registry Explorer tại ConsentStore\webcam\NonPackaged\E:#CO-LT-0469 update package#update.exe. Chụp rõ LastUsedTimeStart và LastUsedTimeStop. -->

- Windows FILETIME is measured in units of 100 nanoseconds, so one second is `10,000,000` FILETIME units.

- I calculated the webcam duration as:

```velocity
(134316278756619812 - 134316277486814313) / 10000000
= 126.9805499 seconds
```

- The challenge asks for a whole number of seconds, giving:

```velocity
127
```

- **answer:**

```velocity
127
```

---

## Question 8:

The riverside relay drank Voss's secrets. How many decimal megabytes of outbound traffic flowed from the compromised machine to the C2? `(***.******)`

- The question asks for outbound network traffic, so I checked the Windows System Resource Usage Monitor database:

```velocity
Triage\C\Windows\System32\SRU\SRUDB.dat
```

- I parsed the database with SrumECmd:

```velocity
SrumECmd.exe -f "D:\CTF_Share\PaperGhost\PaperGhost\Triage\C\Windows\System32\SRU\SRUDB.dat" -r "D:\CTF_Share\PaperGhost\PaperGhost\Triage\C\Windows\System32\config\SOFTWARE" --csv "D:\CTF_Share\PaperGhost\PaperGhost\Parsed\srum"
```

- I opened the Network Usage output in Timeline Explorer and filtered for `update.exe`.

- The relevant record was:

```velocity
Id:             228
Timestamp:      2026-08-19 15:50:00
Exe Info:       \device\harddiskvolume5\co-lt-0469 update package\update.exe
User Name:      cvoss
Bytes Received: 615595
Bytes Sent:     172064531
Interface Type: IF_TYPE_ETHERNET_CSMACD
```

![image](/images/holmes_2026/paper_ghost/srumecmd.png)

<!-- Ảnh cần chụp: Timeline Explorer mở file Network Usage do SrumECmd xuất. Filter update.exe và chụp đúng dòng có Timestamp 2026-08-19 15:50:00, Exe Info, User Name, Bytes Received và Bytes Sent = 172064531. -->

- The question asks for traffic flowing **outbound**, so I used `Bytes Sent`.

- It specifically asks for **decimal megabytes**, therefore:

```velocity
172064531 / 1000000 = 172.064531
```

- **answer:**

```velocity
172.064531
```

---

## Question 9:

Voss reviewed DIOGENES contractors NAPOLEON may now hunt. What set of credentials did the spying surface for a developer working on DIOGENES tickets? `(username:password)`

- The final question refers to a developer working on DIOGENES tickets. I first checked the Recent files and Jump Lists to reconstruct which DIOGENES documents Voss had opened.

- LECmd and JLECmd showed that the following directory had existed:

```velocity
C:\Users\cvoss\Desktop\DIOGENES_26
```

- The Jump List contained four important PDF files:

```velocity
C:\Users\cvoss\Desktop\DIOGENES_26\EXT-0419.pdf
C:\Users\cvoss\Desktop\DIOGENES_26\IT_SUPPORT.pdf
C:\Users\cvoss\Desktop\DIOGENES_26\Driver Update Package.pdf
C:\Users\cvoss\Desktop\DIOGENES_26\Schedule.pdf
```

![image](/images/holmes_2026/paper_ghost/anh5.png)

<!-- Ảnh cần chụp: Timeline Explorer mở CSV do JLECmd xuất. Chụp cột Path hoặc Local Path sao cho nhìn thấy đủ 4 file EXT-0419.pdf, IT_SUPPORT.pdf, Driver Update Package.pdf và Schedule.pdf. -->

- The metadata also preserved the original file sizes and MFT entry numbers:

```velocity
EXT-0419.pdf              33496 bytes   MFT 0x1ED79
IT_SUPPORT.pdf            32989 bytes   MFT 0x1ED7B
Driver Update Package.pdf 30641 bytes   MFT 0x1ED78
Schedule.pdf              35287 bytes   MFT 0x1ED7C
```

- The Microsoft Edge Jump List showed that Edge had opened the same DIOGENES documents, including `EXT-0419.pdf` and `IT_SUPPORT.pdf`.

![image](/images/holmes_2026/paper_ghost/anh6.png)

<!-- Ảnh cần chụp: Timeline Explorer với App Id Description = Microsoft Edge (Chromium), chụp các dòng EXT-0419.pdf và IT_SUPPORT.pdf. Nếu màn hình rộng, để thêm Last Modified/Target Accessed để thể hiện các file đã được mở. -->

- The original PDFs were not present in the collected `Desktop` directory, so I moved to the Windows Search index. Windows Search can retain indexed text and metadata from supported documents even when the original document is no longer present in the triage copy.

- I located the `Windows.edb` evidence file and opened it using:

```velocity
WindowsEDB-to-CSV.exe | https://github.com/kacos2000/WinEDB/blob/master/WindowsEDB-to-CSV.exe
```

- After loading `Windows.edb`, I exported the database to CSV files.

![image](/images/holmes_2026/paper_ghost/anh7.png)

<!-- Ảnh cần chụp: WindowsEDB-to-CSV.exe sau khi load Windows.edb và export thành công. Nếu tool tạo nhiều CSV, chụp thêm thư mục output để thấy file có tên dạng SystemIndex_PropertyStore_file_.pdf_Records... -->

- One of the exported files was a PDF-related `SystemIndex_PropertyStore` CSV. I opened that output with Notepad/Sublime Text and searched for:

```velocity
EXT-0419
```

- The Windows Search index still contained the indexed text from `EXT-0419.pdf`.

- The recovered record identified the contractor as:

```velocity
Name:          Tom Ainsworth
Title:         Software Developer, DIOGENES Ticketing Support (External Contractor)
Contractor ID: EXT-0419
Username:      tainsworth
Password:      D10g3n3s_T1ck3ts#2026
Access scope:  EXT-3 (ticketing host only)
```

![image](/images/holmes_2026/paper_ghost/anh8.png)

<!-- Ảnh cần chụp: Đây là ảnh quan trọng nhất của câu 9. Mở file CSV/text export từ WindowsEDB-to-CSV bằng Notepad hoặc Sublime Text, search EXT-0419. Crop sao cho cùng một ảnh nhìn thấy: EXT-0419.pdf, Tom Ainsworth, Software Developer/DIOGENES Ticketing Support, Username: tainsworth và Password: D10g3n3s_T1ck3ts#2026. -->

- The record directly identifies Tom Ainsworth as an external developer working on DIOGENES ticketing support and exposes the matching username and password.

- **answer:**

```velocity
tainsworth:D10g3n3s_T1ck3ts#2026
```

---

## Incident Timeline

- The artifacts can be combined into the following timeline:

```velocity
2026-08-19 15:35:50
Lexar USB RS200000000627E4&0 was first connected.

2026-08-19 15:36:25
Voss executed E:\CO-LT-0469 update package\update.exe.

2026-08-19 15:38:08
update.exe started using the microphone.

2026-08-19 15:42:28
update.exe started using the webcam.

2026-08-19 15:44:35
The webcam session ended after approximately 127 seconds.

2026-08-19 15:50:00
SRUM recorded 172064531 outbound bytes for update.exe.
```

- Windows Search indexing also preserved the missing `EXT-0419.pdf` contractor record, allowing the DIOGENES developer credentials to be recovered even though the original PDF was absent from the collected Desktop directory.

---

## Final Answers

```velocity
Q1: 2026-08-19 15:35:50
Q2: RS200000000627E4&0
Q3: E:\CO-LT-0469 update package\update.exe
Q4: 2026-08-19 15:36:25
Q5: CO-USB-0091
Q6: 2026-08-19 15:38:08
Q7: 127
Q8: 172.064531
Q9: tainsworth:D10g3n3s_T1ck3ts#2026
```

---

---

---

# Borrow Name Forensic Write-up

Challenge link: [https://drive.google.com/file/d/1SltVmbWg8Eykz-DmtAjnmnEL_EQ1fAwH/view?usp=sharing](https://drive.google.com/file/d/1SltVmbWg8Eykz-DmtAjnmnEL_EQ1fAwH/view?usp=sharing)

## Challenge Description

In this challenge, analysts investigate a simulated Active Directory compromise carried out by an APT group. The investigation combines PCAP analysis, malware reverse engineering, Windows event logs, LDAP permission analysis, credential recovery, privilege escalation, and lateral movement.

The attacker uses an Adaptix C2 infrastructure to communicate with the compromised workstation. The objective is to reconstruct the attack chain, recover encrypted beacon information, identify the custom BOF used to obtain NTLM credentials, determine how the attacker abused Active Directory permissions, and track the subsequent movement to the domain controller.

The challenge provides network traffic, a disk image, and Windows event logs. All artefacts must be analysed statically and offline. Recovered binaries and BOFs should not be executed.

**Difficulty:** Medium

## Scope and input files

This write-up is written so that another analyst can repeat the investigation using only the files supplied in the <code>danger</code> directory.

The supplied evidence is:

- <code>danger\capture.pcapng</code>: network traffic containing the Adaptix C2 traffic, the first and second beacon registration, credential material, and later lateral movement.
- <code>danger\Q3_Salary_Review.img</code>: the WS02 disk image, containing the implant and other endpoint artefacts.
- <code>danger\C\Windows\System32\winevt\logs\Microsoft-Windows-NTLM%4Operational.evtx</code>: the Windows NTLM Operational log.
- <code>danger\check.php</code>: a small decoy/checker file; it is not the forensic source for the answers.

No file from a pre-generated analysis directory is required. In the commands below, <code>results</code> is only an optional output directory created by the reader during the investigation. It is not part of the challenge package.

Do not execute the implant, the BOF, a DLL, or the uploaded service binary. Everything below can be done by reading bytes, parsing logs, calculating hashes, and decoding copied network data.

<!-- SCREENSHOT NOTE - Capture the initial <code>danger</code> directory in File Explorer or PowerShell. The image must show the three main artefacts: <code>capture.pcapng</code>, <code>Q3_Salary_Review.img</code>, and the <code>C:\Windows\System32\winevt\logs</code> directory. Do not include a self-created results directory if the image is meant to prove that the challenge supplied only the <code>danger</code> directory. -->

## Final answers

| # | Question | Answer |
|---:|---|---|
| 1 | C2 framework | <code>Adaptix</code> |
| 2 | SessionKey:EncryptionKey | <code>53fc4c03c7b461befe5dcb268e3d9208:4580221ac3fe51be1797524a048e552d</code> |
| 3 | Privilege-escalation CVE | <code>CVE-2026-27912</code> |
| 4 | Custom BOF MD5 | <code>56c92e28050c334b1b54974ffd022192</code> |
| 5 | Writable object's ObjectSID | <code>S-1-5-21-2253468260-689643353-167204612-1125</code> |
| 6 | Password-discovery attack and time | <code>Internal_Monologue:2026-09-09 20:44:11</code> |
| 7 | Credentials used for the attack | <code>afenwick:*Seash5lls*</code> |
| 8 | Target account and new password | <code>jreed:Aigohng8vai0seish4zi</code> |
| 9 | New logon type | <code>9</code> |
| 10 | Uploaded agent path | <code>\\192.168.56.11\ADMIN$\svc_bkup</code> |
| 11 | Service group | <code>defragsvc</code> |
| 12 | New BeaconID:SessionKey | <code>ddc68fa7:289122cf1ec91c67eb89c30642adfea4</code> |

<!-- SCREENSHOT NOTE - Capture the final answer table after verifying every value in the sections below. If the write-up is published, redact the passwords and keep the unredacted values only in the private CTF submission. -->

## Reproducibility setup

Create a separate output directory if you want to save derived files:

~~~powershell
New-Item -ItemType Directory -Force results
Get-ChildItem -Recurse -File danger | Select-Object FullName,Length
~~~

The investigation can be performed with:

- Wireshark or tshark for the PCAP.
- IDA for static disassembly.
- CyberChef for a visual verification of the RC4 operation.
- PowerShell <code>Get-WinEvent</code> for the EVTX.
- Python 3 for deterministic parsing, RC4, carving, and hashing.

The following small Python functions are included in the relevant sections so that no hidden helper files are needed.

<!-- SCREENSHOT NOTE - Capture the terminal after running <code>Get-ChildItem</code>. This proves that the original input is in <code>danger</code> and that any later result files were created by the analyst. -->

## Question 1 - What C2 was used?

## Answer

<code>Adaptix</code>

The conversation endpoint is not the answer:

~~~text
192.168.56.22:50258 -> 192.168.56.1:8818
192.168.56.11:54162 -> 192.168.56.1:8818
~~~

Those addresses prove that the same listener receives traffic from WS02 and later from DC02. The question asks for the framework name, so the canonical answer is <code>Adaptix</code>, not <code>192.168.56.1:8818</code> and not the longer repository name <code>AdaptixC2</code>.

## Step 1: Confirm the listener in Wireshark

Open <code>danger\capture.pcapng</code>. Use:

~~~text
tcp.port == 8818
tcp.stream eq 0
http
http.request
~~~

The first long conversation is from <code>192.168.56.22</code> to <code>192.168.56.1:8818</code>. A later conversation is from <code>192.168.56.11</code> to the same listener. The HTTP-looking paths include:

~~~text
/updates/check.php
/api/v1/status
/content.html
~~~

This identifies a long-lived beacon-style communication pattern, but the framework name comes from the binary fingerprint in the disk image.

<!-- SCREENSHOT NOTE - In Wireshark, capture Statistics -> Protocol Hierarchy and Statistics -> Conversations -> IPv4. The Conversations view should show <code>192.168.56.22</code>, <code>192.168.56.11</code>, <code>192.168.56.1</code>, port <code>8818</code>, and, if available, Stream 0/Stream 1. Also capture the filter bar with <code>tcp.port == 8818</code> and the Follow TCP Stream window for Stream 0. -->

![Question 1 evidence](/images/holmes_2026/borrowname/cau1_1.png)

## Step 2: Extract the executable without executing it

The image is a raw disk image. If a forensic image tool is available, mount it read-only and copy the suspicious executable to a staging directory. If no image mounter is available, the following Python carver can locate PE files inside the image by validating <code>MZ</code> and <code>PE</code> headers.

~~~python
from pathlib import Path
import struct

image = Path("danger/Q3_Salary_Review.img").read_bytes()
out = Path("results")
out.mkdir(exist_ok=True)

hits = []
offset = 0

while True:
    offset = image.find(b"MZ", offset)
    if offset < 0:
        break

    if offset + 0x40 <= len(image):
        e_lfanew = struct.unpack_from("<I", image, offset + 0x3C)[0]
        pe = offset + e_lfanew

        if pe + 4 <= len(image) and image[pe:pe + 4] == b"PE\x00\x00":
            end = image.find(b"MZ", offset + 2)
            if end < 0:
                end = len(image)

            candidate = image[offset:end]
            name = out / ("pe_%08x.bin" % offset)
            name.write_bytes(candidate)

            if b"ConnectorHTTP" in candidate or b"13ConnectorHTTP" in candidate:
                print("Likely winupdate candidate:", name, len(candidate))

            hits.append(name)
    offset += 2

print("PE candidates:", len(hits))
~~~

This script creates only inert copies. Load the candidate containing <code>13ConnectorHTTP</code> into IDA as a PE if the section headers are intact. If the candidate is only a carved fragment, use it for strings and use the original mounted file for full analysis.

<!-- SCREENSHOT NOTE - Capture the carver output in the terminal, especially the line <code>Likely winupdate candidate</code>. If you mount the image, capture the read-only mount and the copy of <code>winupdate.exe</code> to staging. Never double-click the file. -->

## Step 3: Confirm the Adaptix fingerprint

The relevant strings are:

~~~text
13ConnectorHTTP
9Connector
\\.\pipe\%08lx
~~~

The numeric prefix is the C++ RTTI name length:

~~~text
13ConnectorHTTP -> ConnectorHTTP
9Connector       -> Connector
~~~

Several independent indicators agree:

- The HTTP transport is named <code>ConnectorHTTP</code>.
- A base <code>Connector</code> class is present.
- The binary uses a GCC/MinGW-style RTTI representation.
- The configuration contains a 4-byte length, an encrypted blob, and a 16-byte key.
- The binary implements RC4.
- A 16-byte runtime SessionKey is appended to the first registration packet.
- The named-pipe pattern matches the Adaptix agent fingerprint.

Public references:

- AdaptixC2 repository: https://github.com/Adaptix-Framework/AdaptixC2
- Adaptix Beacon documentation: https://adaptix-framework.gitbook.io/adaptix-framework/extenders/agents/beacon
- Wireshark filter reference: https://www.wireshark.org/docs/man-pages/wireshark-filter.html

Useful search terms:

~~~text
13ConnectorHTTP
9Connector
ConnectorHTTP
Fully encrypted communications
HTTP/S Beacon Listener
BOF & Async BOF support
~~~

<!-- SCREENSHOT NOTE - In IDA, open the Strings window and press Ctrl+F for <code>13ConnectorHTTP</code>, <code>9Connector</code>, and <code>\\.\\pipe\\%08lx</code>. For each result, capture the string, address, and xrefs window if available. Then capture the AdaptixC2 GitHub page with Ctrl+F for <code>HTTP/S Beacon Listener</code> or <code>Fully encrypted communications</code>, including the URL bar. -->

![Question 1 evidence](/images/holmes_2026/borrowname/cau1_2.png)

## Question 2 - What SessionKey:EncryptionKey was used?

## Answer

~~~text
53fc4c03c7b461befe5dcb268e3d9208:4580221ac3fe51be1797524a048e552d
~~~

The challenge displays the answer in the order <code>SessionKey:EncryptionKey</code>. The recovery order is different:

1. Follow the program from <code>start</code> to the configuration parser.
2. Recover the static <code>EncryptionKey</code> from the configuration blob and prove that it is used by RC4.
3. Use that key to decrypt the first registration value in the PCAP.
4. Read the 16-byte <code>SessionKey</code> from the decrypted registration structure.
5. Stop here. Do not decode the hostname and task records until Question 3.

This distinction matters. In this sample the static EncryptionKey is what decrypts the first registration packet; the SessionKey is discovered inside that decrypted packet. The SessionKey is then used for later beacon/task traffic. They are not interchangeable.

<!-- SCREENSHOT NOTE - Capture a small IDA or write-up diagram showing the order: recover <code>EncryptionKey</code> from <code>.rdata</code> -> use RC4 to decrypt the registration in the PCAP -> read <code>SessionKey</code>. Add an arrow showing that the submission format is still SessionKey:EncryptionKey. -->

## Step 2.1: Start at the real program entry

Do not jump directly to a function address. In IDA:

1. Open View -> Open subviews -> Functions.
2. Find <code>start</code>.
3. Double-click <code>start</code>.
4. Follow the call whose target is <code>sub_14000DDF7</code>.
5. In <code>sub_14000DDF7</code>, follow the constructor call to <code>sub_140002DEE</code>.

The control-flow route is:

~~~text
start
  -> sub_14000DDF7
     -> sub_140002DEE
        -> sub_1400035B0 / sub_1400035EE
~~~

The purpose of this route is to let the evidence lead us to the configuration object. The function name alone does not prove anything; the allocations, stores, and later field reads do.

Equivalent C-like control flow:

~~~c
int start(void)
{
    return sub_14000DDF7();
}

int sub_14000DDF7(void)
{
    Agent agent;
    sub_140002DEE(&agent);
    return run_agent(&agent);
}
~~~

<!-- SCREENSHOT NOTE - In IDA, capture <code>start</code> with <code>call sub_14000DDF7</code>. Capture a second image of <code>sub_14000DDF7</code> with the call to <code>sub_140002DEE</code>. Circle the call on each image and add the note “double-click target”. These are the first two images for Question 2. -->

![Question 2 evidence 1](/images/holmes_2026/borrowname/cau2_1.png)

![Question 2 evidence 2](/images/holmes_2026/borrowname/cau2_2.png)

## Step 2.2: Follow the constructor sub_140002DEE

The constructor creates several child objects. The configuration-related branch contains:

~~~asm
mov     ecx, 0C8h
call    sub_1400035B0

mov     rbx, rax
mov     rcx, rbx
call    sub_1400035EE

mov     rax, [rbp+arg_0]
mov     [rax+8], rbx
~~~

On Windows x64, <code>RCX</code> is the first argument and <code>RAX</code> is the return value. The code therefore means:

~~~c
AgentObject *child = allocate_object(0xC8);
initialize_config_object(child);
agent->field_08 = child;
~~~

The reason to follow <code>sub_1400035EE</code>, instead of an arbitrary neighboring call, is data flow. The object is allocated, initialized, stored in <code>[parent+8]</code>, and then a field such as <code>[parent+8]+0x28</code> is read by later code. That makes it a configuration-bearing object.

Other constructor children such as <code>sub_140003AC0</code>, <code>sub_140003AFE</code>, and <code>sub_14000CC8E</code> may initialize unrelated agent state. Record them in the constructor screenshot, but follow the branch that creates the 0xC8-byte object and stores it at <code>[parent+8]</code>.

<!-- SCREENSHOT NOTE - In <code>sub_140002DEE</code>, capture the complete block from <code>mov ecx, 0C8h</code> through <code>mov [rax+8], rbx</code>. Also capture the constructor graph view if it shows the object-creation branches. If calls to <code>sub_140003AC0</code>, <code>sub_140003AFE</code>, or <code>sub_14000CC8E</code> are visible, keep them in the same image and circle the 0xC8 branch being followed. -->

![Question 2 evidence 3](/images/holmes_2026/borrowname/cau2_3.png)

![Question 2 evidence 4](/images/holmes_2026/borrowname/cau2_4.png)

## Step 2.3: Recover the blob size with sub_14000100D

Inside <code>sub_1400035EE</code>, the first useful call is:

~~~asm
mov     [rbp+var_38], 0
call    sub_14000100D
mov     [rbp+var_24], eax

mov     eax, [rbp+var_24]
mov     ecx, eax
call    sub_1400129E0
mov     [rbp+var_40], rax
~~~

Open <code>sub_14000100D</code>:

~~~asm
sub_14000100D proc near
push    rbp
mov     rbp, rsp
mov     eax, 114h
pop     rbp
retn
sub_14000100D endp
~~~

The C-like translation is:

~~~c
uint32_t config_blob_size(void)
{
    return 0x114;
}

uint8_t *config_copy = allocate(0x114);
~~~

This is the first important size proof: the embedded configuration is 0x114 bytes, or 276 bytes.

<!-- SCREENSHOT NOTE - Double-click <code>sub_14000100D</code> from its call site and capture the function containing <code>mov eax, 114h</code> and <code>retn</code>. Also capture the return to <code>sub_1400035EE</code> showing <code>mov ecx, eax</code> and <code>call sub_1400129E0</code>. Add “0x114 = 276 bytes” to the image. -->

![Question 2 evidence 5](/images/holmes_2026/borrowname/cau2_5.png)

![Question 2 evidence 6](/images/holmes_2026/borrowname/cau2_6.png)

## Step 2.4: Find the source blob with sub_140001000

The next relevant call is selected by its data flow:

~~~asm
mov     ebx, [rbp+var_24]
call    sub_140001000
mov     rdx, rax
mov     rax, [rbp+var_40]
mov     r8, rbx
mov     rcx, rax
call    sub_140003DE0
~~~

The Windows x64 arguments are:

~~~text
RCX = destination
RDX = source
R8  = length
~~~

So the call is equivalent to:

~~~c
copy_bytes(
    destination = config_copy,
    source      = sub_140001000(),
    length      = 0x114
);
~~~

Open <code>sub_140001000</code>. The important instruction is:

~~~asm
lea     rax, unk_140017000
retn
~~~

C-like translation:

~~~c
uint8_t *sub_140001000(void)
{
    return &unk_140017000;
}
~~~

The static configuration therefore starts at <code>0x140017000</code>.

<!-- SCREENSHOT NOTE - Capture the <code>call sub_140001000</code> site in <code>sub_1400035EE</code>, then double-click <code>sub_140001000</code> and capture <code>lea rax, unk_140017000</code>. Do not capture only the address; show the data flow <code>sub_140001000 -> RDX source -> sub_140003DE0</code>. -->

![Question 2 evidence 7](/images/holmes_2026/borrowname/cau2_7.png)

![Question 2 evidence 8](/images/holmes_2026/borrowname/cau2_8.png)

## Step 2.5: Understand the helpers around the parser

The calls around the parser have distinct roles:

- <code>sub_1400129E0</code>: allocation wrapper; it receives a size in <code>ECX</code> and returns a pointer in <code>RAX</code>.
- <code>sub_140003DE0</code>: copy helper; its first three arguments are destination, source, and length.
- <code>sub_14000E650</code>: creates a small parser object, with a size of 0x18 in this path.
- <code>sub_14000E6D4</code>: initializes that parser with the blob pointer, blob length, and offset zero.
- <code>sub_14000ED52</code>: reads a bounded 32-bit little-endian value and advances the parser cursor.
- <code>sub_14000EBAE</code>: returns the parser's buffer pointer.
- <code>sub_14000ECEA</code>: reads a byte/flag in the same parser flow.

The initialization call is represented by:

~~~asm
mov     ecx, 18h
call    sub_14000E650
mov     rbx, rax

mov     rax, [rbp+var_40]
mov     edx, [rbp+var_24]
mov     r8d, edx
mov     rdx, rax
mov     rcx, rbx
call    sub_14000E6D4
~~~

C-like translation:

~~~c
Parser *parser = allocate_parser(0x18);
parser_init(parser, config_copy, 0x114);
~~~

The parser initializer stores the buffer at <code>parser+8</code>, stores the length at <code>parser+0</code> and <code>parser+4</code>, and sets <code>parser+0x10</code> to zero.

~~~asm
mov     rax, [rbp+arg_0]
mov     rdx, [rbp+arg_8]
mov     [rax+8], rdx

mov     rax, [rbp+arg_0]
mov     edx, [rbp+arg_10]
mov     [rax], edx

mov     rax, [rbp+arg_0]
mov     edx, [rbp+arg_10]
mov     [rax+4], edx

mov     rax, [rbp+arg_0]
mov     dword ptr [rax+10h], 0
~~~

C-like translation:

~~~c
void parser_init(Parser *p, uint8_t *buffer, uint32_t size)
{
    p->buffer = buffer;
    p->size = size;
    p->capacity = size;
    p->offset = 0;
}
~~~

<!-- SCREENSHOT NOTE - Capture the call sites of <code>sub_14000E650</code> and <code>sub_14000E6D4</code> inside <code>sub_1400035EE</code>. If IDA shows the body of <code>sub_14000E6D4</code>, capture the RCX/RDX/R8 stores through the instruction that sets <code>[rax+10h] = 0</code>. This proves that the parser starts at offset 0. -->

![Question 2 evidence 9](/images/holmes_2026/borrowname/cau2_9.png)

## Step 2.6: Read the first DWORD with sub_14000ED52

The reader contains a bounds check:

~~~asm
mov     rax, [rbp+arg_0]
mov     edx, [rax]
mov     eax, [rax+10h]
sub     edx, eax
cmp     edx, 3
ja      loc_read_value
mov     eax, 0

mov     rdx, [rax+8]
mov     eax, [rax+10h]
add     rdx, rax
call    sub_140003DE0

add     edx, 4
mov     [rax+10h], edx
~~~

C-like translation:

~~~c
uint32_t read_u32(Parser *p)
{
    if (p->size - p->offset < 4)
        return 0;

    uint32_t value = read_le32(p->buffer + p->offset);
    p->offset += 4;
    return value;
}
~~~

The first four bytes of the blob are:

~~~text
00 01 00 00
~~~

Because the blob is little-endian, this is:

~~~text
0x00000100 = 0x100 = 256
~~~

That explains the layout:

~~~text
4 bytes   : 0x100
0x100     : encrypted configuration bytes
0x10      : key candidate
Total     : 0x114
~~~

<!-- SCREENSHOT NOTE - Capture all of <code>sub_14000ED52</code>, especially <code>sub edx, eax</code>, <code>cmp edx, 3</code>, the data read, and <code>add edx, 4</code>. Also capture the Hex View at <code>unk_140017000</code> showing <code>00 01 00 00</code>. Add “little-endian DWORD = 0x100” to the image. -->

![Question 2 evidence 10](/images/holmes_2026/borrowname/cau2_10.png)

![Question 2 evidence 11](/images/holmes_2026/borrowname/cau2_11.png)

## Step 2.7: Locate and copy the 16-byte key candidate

The parser buffer helper is short:

~~~asm
sub_14000EBAE proc near
mov     rax, [rbp+arg_0]
mov     rax, [rax+8]
retn
sub_14000EBAE endp
~~~

C-like translation:

~~~c
uint8_t *parser_buffer(Parser *p)
{
    return p->buffer;
}
~~~

The caller computes:

~~~asm
call    sub_14000EBAE
mov     edx, [rbp+var_34]
add     rdx, 4
add     rdx, rax
~~~

At this point:

~~~text
RAX = buffer
var_34 = 0x100
RDX = buffer + 4 + 0x100 = buffer + 0x104
~~~

The next copy call is:

~~~asm
mov     rax, [rbp+arg_0]
mov     rax, [rax+8]
mov     r8d, 10h
mov     rcx, rax
call    sub_140003DE0
~~~

Under the Windows x64 calling convention:

~~~text
RCX = destination: a new 16-byte allocation
RDX = source:     buffer + 0x104
R8  = length:     0x10
~~~

C-like translation:

~~~c
uint8_t *encryption_key = allocate(16);
memcpy(encryption_key, parser_buffer(parser) + 0x104, 16);
~~~

The bytes at <code>0x140017000 + 0x104</code> are:

~~~text
45 80 22 1A C3 FE 51 BE 17 97 52 4A 04 8E 55 2D
~~~

Therefore the candidate is:

~~~text
4580221ac3fe51be1797524a048e552d
~~~

<!-- SCREENSHOT NOTE - Capture the complete <code>sub_14000EBAE</code>, even though it is short. Then capture the call site containing <code>+4</code>, <code>+var_34</code>, and <code>call sub_140003DE0</code> with <code>r8d, 10h</code>. Finally, capture the Hex View starting at <code>0x140017104</code> and circle the 16-byte key. Use at least three separate images for this step. -->

![Question 2 evidence 12](/images/holmes_2026/borrowname/cau2_12.png)

![Question 2 evidence 13](/images/holmes_2026/borrowname/cau2_13.png)

## Step 2.8: Prove that the candidate is used as a crypto key

Immediately after the copy, the program passes the 16-byte allocation to a wrapper:

~~~asm
mov     rax, [rbp+arg_0]
mov     rsi, [rax+8]

mov     ebx, [rbp+var_34]

mov     rax, [rbp+var_30]
mov     rcx, rax
call    sub_14000EBAE
add     rax, 4

mov     r9d, 10h
mov     r8, rsi
mov     edx, ebx
mov     rcx, rax

call    sub_14000CC0B
~~~

The arguments are:

~~~text
RCX = buffer + 4
RDX = 0x100 bytes of data
R8  = the 16-byte copied value
R9  = 0x10
~~~

C-like translation:

~~~c
crypto_wrapper(
    parser_buffer(parser) + 4,
    0x100,
    encryption_key,
    0x10
);
~~~

The wrapper itself only forwards the arguments:

~~~asm
sub_14000CC0B proc near
mov     [rbp+arg_0], rcx
mov     [rbp+arg_8], edx
mov     [rbp+arg_10], r8
mov     [rbp+arg_18], r9d

mov     r8d, [rbp+arg_18]
mov     rcx, [rbp+arg_10]
mov     edx, [rbp+arg_8]
mov     rax, [rbp+arg_0]

mov     r9d, r8d
mov     r8, rcx
mov     rcx, rax
call    sub_14000CBBC
retn
sub_14000CC0B endp
~~~

C-like translation:

~~~c
void crypto_wrapper(uint8_t *data, uint32_t length,
                    uint8_t *key, uint32_t key_length)
{
    rc4_transform(data, length, key, key_length);
}
~~~

<!-- SCREENSHOT NOTE - Capture the <code>sub_14000CC0B</code> call site with all four arguments visible, then capture the complete <code>sub_14000CC0B</code> wrapper. Label the arguments RCX=data, RDX=0x100, R8=key, and R9=0x10. This is direct evidence that the copied 16 bytes are used as the key. -->

![Question 2 evidence 14](/images/holmes_2026/borrowname/cau2_14.png)

## Step 2.9: Follow the RC4 dispatcher sub_14000CBBC

The dispatcher creates a 256-byte local state array:

~~~asm
sub_14000CBBC proc near
sub     rsp, 120h
mov     [rbp+arg_0], rcx
mov     [rbp+arg_8], edx
mov     [rbp+arg_10], r8
mov     [rbp+arg_18], r9d

mov     ecx, [rbp+arg_18]
lea     rdx, [rbp+var_100]
mov     rax, [rbp+arg_10]
mov     r8d, ecx
mov     rcx, rax
call    sub_14000C9B0

lea     rcx, [rbp+var_100]
mov     edx, [rbp+arg_8]
mov     rax, [rbp+arg_0]
mov     r8, rcx
mov     rcx, rax
call    sub_14000CAA0
retn
sub_14000CBBC endp
~~~

C-like translation:

~~~c
void rc4_transform(uint8_t *data, uint32_t length,
                   uint8_t *key, uint32_t key_length)
{
    uint8_t S[256];

    rc4_ksa(key, S, key_length);
    rc4_prga_xor(data, length, S);
}
~~~

The reason to open <code>sub_14000C9B0</code> first is that it receives the key, the key length, and a 256-byte state array. That is the signature of RC4's Key Scheduling Algorithm.

<!-- SCREENSHOT NOTE - Capture the complete <code>sub_14000CBBC</code>. Circle <code>var_100</code> or the 0x100-byte stack area, the call to <code>sub_14000C9B0</code>, and the call to <code>sub_14000CAA0</code>. Add “KSA then PRGA”. This image connects the candidate key to RC4. -->

![Question 2 evidence 15](/images/holmes_2026/borrowname/cau2_15.png)

![Question 2 evidence 16](/images/holmes_2026/borrowname/cau2_16.png)

## Step 2.10: Prove RC4 KSA in sub_14000C9B0

The relevant KSA instructions perform:

~~~asm
mov     [rbp+arg_0], rcx
mov     [rbp+arg_8], rdx
mov     [rbp+arg_10], r8d
mov     [rbp+var_8], 0
mov     [rbp+var_4], 0
...
movzx   eax, byte ptr [key + (i % key_length)]
...
movzx   edx, byte ptr [S + i]
...
mov     [rbp+var_8], edx
...
swap S[i], S[j]
add     [rbp+var_4], 1
~~~

The complete loop has the recognizable form:

~~~text
S[i] = i for i = 0..255
j = (j + S[i] + key[i % key_length]) mod 256
swap(S[i], S[j])
~~~

C-like translation:

~~~c
void rc4_ksa(const uint8_t *key, uint8_t S[256], uint32_t key_len)
{
    uint32_t j = 0;

    for (uint32_t i = 0; i < 256; i++)
        S[i] = (uint8_t)i;

    for (uint32_t i = 0; i < 256; i++)
    {
        j = (j + S[i] + key[i % key_len]) & 0xff;

        uint8_t t = S[i];
        S[i] = S[j];
        S[j] = t;
    }
}
~~~

This proves the key candidate is passed to an RC4 KSA with a key length of 0x10. Thus:

~~~text
EncryptionKey = 4580221ac3fe51be1797524a048e552d
~~~

<!-- SCREENSHOT NOTE - In <code>sub_14000C9B0</code>, capture the <code>S[i] = i</code> initialization through <code>0xFF</code>, the <code>i % key_length</code> calculation, and the swap. If the function does not fit, use three consecutive images and label their order. Find the function by following the call from <code>sub_14000CBBC</code>; do not guess the address. -->

![Question 2 evidence 17](/images/holmes_2026/borrowname/cau2_17.png)

## Step 2.11: Prove the PRGA in sub_14000CAA0

The second helper receives:

~~~text
RCX = data
RDX = data length
R8  = S[256]
~~~

Its operation is the RC4 PRGA:

~~~c
void rc4_prga_xor(uint8_t *data, uint32_t length, uint8_t S[256])
{
    uint32_t i = 0;
    uint32_t j = 0;

    for (uint32_t n = 0; n < length; n++)
    {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;

        uint8_t t = S[i];
        S[i] = S[j];
        S[j] = t;

        uint8_t stream = S[(S[i] + S[j]) & 0xff];
        data[n] ^= stream;
    }
}
~~~

The KSA/PRGA pair is why the key bytes at <code>buffer + 0x104</code> are not merely random trailing bytes. The program uses them to transform the 0x100-byte configuration.

<!-- SCREENSHOT NOTE - Double-click <code>sub_14000CAA0</code> from <code>sub_14000CBBC</code>. Capture the function from start to finish, especially the i/j increments, S-box swap, index calculation, and XOR with the data. If IDA does not name the variables clearly, circle the memory reads/writes and label them “PRGA”. -->

![Question 2 evidence 18](/images/holmes_2026/borrowname/cau2_18.png)

## Step 2.12: Translate the whole configuration parser

The important part of <code>sub_1400035EE</code> is the sequence:

~~~asm
call    sub_14000100D
mov     [rbp+var_24], eax
mov     eax, [rbp+var_24]
mov     ecx, eax
call    sub_1400129E0
mov     [rbp+var_40], rax

call    sub_140001000
mov     rdx, rax
mov     rax, [rbp+var_40]
mov     r8, rbx
mov     rcx, rax
call    sub_140003DE0

mov     ecx, 18h
call    sub_14000E650
...
call    sub_14000E6D4
...
call    sub_14000ED52
mov     [rbp+var_34], eax
...
call    sub_14000EBAE
...
call    sub_140003DE0
...
call    sub_14000CC0B
~~~

A readable translation is:

~~~c
void initialize_config(AgentConfig *agent)
{
    uint32_t total = sub_14000100D();       // 0x114
    uint8_t *copy = sub_1400129E0(total);   // allocate
    uint8_t *source = sub_140001000();      // &unk_140017000

    sub_140003DE0(copy, source, total);     // copy embedded blob

    Parser *p = sub_14000E650(0x18);
    sub_14000E6D4(p, copy, total);

    uint32_t encrypted_size = sub_14000ED52(p); // 0x100
    uint8_t *key = sub_1400129E0(0x10);

    memcpy(key, sub_14000EBAE(p) + 4 + encrypted_size, 0x10);
    sub_14000CC0B(
        sub_14000EBAE(p) + 4,
        encrypted_size,
        key,
        0x10
    );

    agent->config_size = sub_14000ED52(p);
    agent->field_18 = sub_14000ED52(p);
    agent->field_1c = sub_14000ED52(p);
    agent->field_10 = sub_14000ED52(p);
    agent->field_14 = sub_14000ED52(p);
    agent->field_04 = sub_14000ED52(p);
    agent->flags = sub_14000ECEA(p);
    agent->count = sub_14000ED52(p);
}
~~~

This is not claimed to be the original source. It is a faithful data-flow translation of the assembly.

<!-- SCREENSHOT NOTE - Capture one large image of <code>sub_1400035EE</code> from the call to <code>sub_14000100D</code> through the call to <code>sub_14000CC0B</code>. If the text is too small, split it into function start, parser setup, key copy, crypto call, and final field reads. Label each image with the function name and current offset. -->

## Step 2.13: Locate the runtime SessionKey in the constructor

The static EncryptionKey is in the embedded configuration. The SessionKey is different: it is generated at runtime and stored at object offset <code>+0x68</code>.

Near the end of <code>sub_140002DEE</code>:

~~~asm
mov     ecx, 10h
call    sub_1400129E0
mov     rdx, [rbp+arg_0]
mov     [rdx+68h], rax

mov     [rbp+var_14], 0
jmp     short loc_14000301F

loc_14000301F:
mov     eax, [rbp+var_14]
cmp     eax, 0Fh
jg      loc_done

mov     rcx, [rbp+arg_0]
mov     rax, [rcx+68h]
mov     edx, [rbp+var_14]
add     rax, rdx
call    sub_140013310

add     [rbp+var_14], 1
jmp     short loc_14000301F
~~~

C-like translation:

~~~c
agent->session_key = allocate(16);

for (uint32_t i = 0; i <= 15; i++)
    agent->session_key[i] = sub_140013310();
~~~

The call <code>sub_140013310</code> returns one generated byte per iteration. The output is not expected to be visible as a fixed hex string in the static image.

<!-- SCREENSHOT NOTE - Return to <code>sub_140002DEE</code>, scroll near the end, and capture from <code>mov ecx, 10h</code> through the loop containing <code>cmp ... 0Fh</code>, the call to <code>sub_140013310</code>, and the store to <code>[obj+68h]</code>. This image is required to prove that the SessionKey is generated at runtime. Capture <code>sub_140013310</code> separately if you want to explain the source of each byte. -->

![Question 2 evidence 19](/images/holmes_2026/borrowname/cau2_19.png)

![Question 2 evidence 20](/images/holmes_2026/borrowname/cau2_20.png)

## Step 2.14: Follow the registration packet builder

The constructor stores the key at <code>[agent+0x68]</code>. Later, <code>sub_140003202</code> appends exactly 16 bytes to the registration packet:

~~~asm
mov     rax, [rbp+arg_0]
mov     rdx, [rax+68h]

mov     rax, [rbp+var_20]
mov     r8d, 10h
mov     rcx, rax

call    sub_14000EA84
~~~

C-like translation:

~~~c
packet_append(
    packet,
    agent->session_key,
    0x10
);
~~~

The helper <code>sub_14000EA84</code> is the packet-buffer append routine. It receives a destination packet object, a source pointer, and a 16-byte length.

The relevant flow is:

~~~text
sub_140002DEE
  -> allocate 16 bytes
  -> sub_140013310 called 16 times
  -> agent + 0x68 = runtime SessionKey
  -> sub_140003202
  -> sub_14000EA84(packet, SessionKey, 0x10)
  -> first registration packet
~~~

<!-- SCREENSHOT NOTE - In <code>sub_140003202</code>, capture the load from <code>[rax+68h]</code>, <code>r8d, 10h</code>, and the call to <code>sub_14000EA84</code>. Then capture the body of <code>sub_14000EA84</code> if you want to prove that it appends bytes to the packet. Add “16 bytes from agent+0x68” to the image. -->

## Step 2.15: Find the SessionKey in the first PCAP registration

Now open <code>danger\capture.pcapng</code> in Wireshark and select the first C2 stream:

~~~text
tcp.stream eq 0
tcp.port == 8818
~~~

Find the first registration request and locate the <code>X-Beacon-ID</code> or <code>X-Beacon-Id</code> value. Copy only the Base64 value after the colon.

The static key recovered above is:

~~~text
4580221ac3fe51be1797524a048e552d
~~~

In CyberChef use this recipe:

~~~text
From Base64
-> RC4
-> To Hex
~~~

Set RC4 as follows:

~~~text
Passphrase:      4580221ac3fe51be1797524a048e552d
Passphrase type: Hex
Input format:    Latin1
Output format:   Hex
~~~

The reason for <code>Latin1</code> input is that <code>From Base64</code> already produced raw bytes. Selecting Hex as the input format makes CyberChef interpret the raw byte string incorrectly. Selecting UTF8 for the key also changes the key bytes.

The decrypted registration output begins with a header similar to:

~~~text
be4c014958debcbb0000000400000000000000000000000004e401b5...
~~~

Find the 4-byte big-endian length marker:

~~~text
00000010
~~~

It means that the next 16 bytes are a value of length 0x10:

~~~text
53 fc 4c 03 c7 b4 61 be fe 5d cb 26 8e 3d 92 08
~~~

Remove spaces:

~~~text
53fc4c03c7b461befe5dcb268e3d9208
~~~

That is the first beacon's SessionKey. Stop the decode at this point for Question 2. The next length-prefixed fields contain values such as the hostname and computer name; they are deliberately used in Question 3 and later correlation.

<!-- SCREENSHOT NOTE - In Wireshark, capture the first packet with the <code>X-Beacon-ID</code> header and highlight the Base64 value. Capture CyberChef with the complete recipe, <code>Passphrase type = Hex</code>, <code>Input format = Latin1</code>, and output beginning <code>be4c014958debbcb</code>. Also capture the output around <code>00000010</code> and the 16-byte SessionKey. Do not decode or explain <code>core.diogenes.htb</code> in Question 2; leave it for Question 3. -->

![Question 2 evidence 21](/images/holmes_2026/borrowname/cau2_21.png)

![Question 2 evidence 22](/images/holmes_2026/borrowname/cau2_22.png)

## Step 2.16: Optional reproducible RC4 checker

The following code checks the CyberChef result without depending on CyberChef:

~~~python
from base64 import b64decode

def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]

    out = bytearray()
    i = 0
    j = 0

    for value in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(value ^ S[(S[i] + S[j]) & 0xff])

    return bytes(out)

cipher_b64 = "PASTE_THE_X_BEACON_ID_VALUE_HERE"
cipher = b64decode(cipher_b64)
key = bytes.fromhex("4580221ac3fe51be1797524a048e552d")
plain = rc4(cipher, key)

print(plain.hex())
pos = plain.find(b"\x00\x00\x00\x10")
if pos >= 0 and pos + 20 <= len(plain):
    session_key = plain[pos + 4:pos + 20]
    print("SessionKey:", session_key.hex())
~~~

This script only reads a copied header value and prints bytes. It does not connect to the C2 server.

<!-- SCREENSHOT NOTE - Capture the terminal output showing <code>SessionKey: 53fc4c03...</code>. If the full Base64 input should not be disclosed, redact the input but leave the key, the <code>00000010</code> position, and the SessionKey output visible for verification. -->

## Question 2 conclusion

The static reverse-engineering path proves:

~~~text
EncryptionKey = 4580221ac3fe51be1797524a048e552d
~~~

The first registration packet proves:

~~~text
SessionKey = 53fc4c03c7b461befe5dcb268e3d9208
~~~

Submit:

~~~text
53fc4c03c7b461befe5dcb268e3d9208:4580221ac3fe51be1797524a048e552d
~~~

## Question 3 - Which CVE was used for privilege escalation?

## Answer

<code>CVE-2026-27912</code>

The strings <code>ResetNightmare</code> and <code>UPN-write</code> are not plaintext in the original PCAP. They become visible only after the relevant Adaptix task record is decrypted. This is why searching <code>danger\capture.pcapng</code> directly does not find them.

## Step 3.1: Reproduce the CyberChef decryption

The evidence for this question is the encrypted task body shown in <code>cau3.png</code>. It is already the hexadecimal ciphertext for the task record, so the CyberChef recipe needs only RC4.

~~~text
RC4

Passphrase:    53fc4c03c7b461befe5dcb268e3d9208
Passphrase type: Hex
Input format:   Hex
Output format:  Latin1
~~~

Paste the hexadecimal task body into CyberChef, add the RC4 operation, and set the fields exactly as shown above. The decrypted output contains:

~~~text
[*] Action: ResetNightmare (CVE-2026-27912)
[*] UPN-write + enterprise AS-REQ + kadmin/changepw password reset
[*] Impersonating afenwick for LDAP operations
~~~

The first line gives the CVE answer directly. The second line identifies the operation as ResetNightmare: a writable UPN-related attribute is used, an enterprise AS-REQ is sent for <code>kadmin/changepw</code>, and the target password is reset. The third line connects the action to the compromised <code>afenwick</code> account.

![Question 3 - decrypted task record in CyberChef](/images/holmes_2026/borrowname/cau3.png)

<!-- SCREENSHOT NOTE - Capture the CyberChef window for Question 3: the RC4 recipe, passphrase <code>53fc4c03c7b461befe5dcb268e3d9208</code>, passphrase type Hex, input format Hex, output format Latin1, and the plaintext lines containing <code>ResetNightmare</code> and <code>CVE-2026-27912</code>. Do not search for these strings directly in the original PCAP because they appear only after decryption. -->

## Step 3.2: Interpret the decrypted action

Read the plaintext in order:

1. The operator impersonates <code>afenwick</code> for LDAP operations.
2. A writable UPN-related attribute is changed.
3. An enterprise AS-REQ is sent for <code>kadmin/changepw</code>.
4. The KDC issues a TGT for the target identity.
5. The target password is reset.

A public NVD lookup can be used as a secondary reference:

https://nvd.nist.gov/vuln/detail/CVE-2026-27912

For the challenge answer, the authoritative evidence is the decrypted task output visible in the CyberChef result. Do not move the hostname fields into Question 2; they belong to the later registration and correlation analysis.

## Question 4 - What is the MD5 of the custom BOF?

## Answer

<code>56c92e28050c334b1b54974ffd022192</code>

## Recover the exact BOF from the supplied PCAP

The BOF is not supplied as a standalone file. It is embedded in an Adaptix response. The reproducible workflow is to reassemble the HTTP response, decrypt the <code>data</code> field with the SessionKey from Question 2, and remove the Adaptix task/object wrapper.

The relevant beacon is <code>192.168.56.22</code>, using SessionKey <code>53fc4c03c7b461befe5dcb268e3d9208</code>. The target is application message index <code>174</code> inside the reassembled flow. This is not necessarily the same number as Wireshark's <code>tcp.stream</code> value.

Create <code>q4_extract_bof.py</code> in the challenge root. The complete read-only extraction script is included below. It reads <code>danger/capture.pcapng</code>, decrypts bytes, writes an inert recovered file, and calculates hashes. It never loads or executes the BOF.

~~~python
"""Recover the custom NTLM BOF from the supplied PCAP without executing it."""

from collections import defaultdict
from hashlib import md5, sha256
from pathlib import Path

from scapy.all import IP, Raw, TCP, rdpcap

PCAP = Path("danger/capture.pcapng")
OUT = Path("results/ntlm_capture_bof.bin")
DECRYPTED_OUT = Path("results/q4_decrypted_record.bin")
CLIENT_IP = "192.168.56.22"
SESSION_KEY = bytes.fromhex("53fc4c03c7b461befe5dcb268e3d9208")
TARGET_STREAM = 174
JSON_PREFIX = b'{"status": "ok", "data": "'
JSON_SUFFIX = b'", "metrics":'
BOF_OFFSET = 0x14
BOF_LENGTH = 9484

MARKERS = (
    b"StringToByteArray",
    b"FormatNTLMv2Hash",
    b"FormatNTLMv1Hash",
    b"GetSecBufferByteArray",
    b"ParseNTResponse",
    b"GetNTLMCreds",
    b"AcquireCredentialsHandleA",
    b"InitializeSecurityContextA",
    b"AcceptSecurityContext",
)

def rc4(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    out = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)

def reassemble(packets):
    chunks = sorted(
        (int(packet[TCP].seq), bytes(packet[Raw].load))
        for packet in packets
        if TCP in packet and Raw in packet
    )
    output = bytearray()
    next_seq = None
    for sequence, chunk in chunks:
        if next_seq is None:
            next_seq = sequence
        if sequence < next_seq:
            skip = next_seq - sequence
            if skip >= len(chunk):
                continue
            chunk = chunk[skip:]
            sequence = next_seq
        if sequence > next_seq:
            output.extend(b"\x00" * (sequence - next_seq))
        output.extend(chunk)
        next_seq = sequence + len(chunk)
    return bytes(output)

def headers(raw_headers: bytes):
    result = {}
    for line in raw_headers.split(b"\r\n")[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            result[key.lower()] = value.strip()
    return result

def parse_http_stream(data: bytes):
    position = 0
    while position < len(data):
        starts = [x for x in (data.find(b"HTTP/", position), data.find(b"POST ", position)) if x >= 0]
        if not starts:
            return
        start = min(starts)
        header_end = data.find(b"\r\n\r\n", start)
        if header_end < 0:
            return
        raw_headers = data[start:header_end]
        header_map = headers(raw_headers)
        body_start = header_end + 4

        if b"chunked" in header_map.get(b"transfer-encoding", b"").lower():
            cursor = body_start
            body = bytearray()
            while True:
                line_end = data.find(b"\r\n", cursor)
                if line_end < 0:
                    return
                size = int(data[cursor:line_end].split(b";", 1)[0], 16)
                cursor = line_end + 2
                if size == 0:
                    trailer_end = data.find(b"\r\n\r\n", cursor)
                    if trailer_end < 0:
                        return
                    position = trailer_end + 4
                    break
                body.extend(data[cursor:cursor + size])
                cursor += size + 2
            yield raw_headers.split(b"\r\n", 1)[0], bytes(body)
            continue

        length = int(header_map.get(b"content-length", b"0") or b"0")
        body_end = body_start + length
        if body_end > len(data):
            return
        yield raw_headers.split(b"\r\n", 1)[0], data[body_start:body_end]
        position = body_end

def find_target_response():
    packets = rdpcap(str(PCAP))
    flows = defaultdict(list)
    for packet in packets:
        if IP in packet and TCP in packet and Raw in packet:
            flow = (packet[IP].src, int(packet[TCP].sport), packet[IP].dst, int(packet[TCP].dport))
            flows[flow].append(packet)

    for flow, flow_packets in flows.items():
        # Responses travel from the C2 server to the beacon host.
        if flow[2] != CLIENT_IP:
            continue
        for stream_index, (first_line, body) in enumerate(parse_http_stream(reassemble(flow_packets))):
            if stream_index != TARGET_STREAM or not first_line.startswith(b"HTTP/"):
                continue
            if not body.startswith(JSON_PREFIX):
                continue
            end = body.find(JSON_SUFFIX, len(JSON_PREFIX))
            if end < 0:
                continue
            return flow, body[len(JSON_PREFIX):end]
    raise RuntimeError("Target response was not found; verify the SessionKey/client IP and PCAP.")

def main():
    flow, encrypted = find_target_response()
    decrypted = rc4(encrypted, SESSION_KEY)
    bof = decrypted[BOF_OFFSET:BOF_OFFSET + BOF_LENGTH]
    marker_hits = [marker.decode("ascii") for marker in MARKERS if marker in bof]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    DECRYPTED_OUT.write_bytes(decrypted)
    OUT.write_bytes(bof)

    print("flow:", flow)
    print("stream:", TARGET_STREAM)
    print("encrypted record length:", len(encrypted))
    print("encrypted record MD5:", md5(encrypted).hexdigest())
    print("decrypted record length:", len(decrypted))
    print("BOF offset:", hex(BOF_OFFSET))
    print("BOF length:", len(bof))
    print("trailer length:", len(decrypted) - BOF_OFFSET - len(bof))
    print("marker hits:", ", ".join(marker_hits))
    print("MD5:", md5(bof).hexdigest())
    print("SHA256:", sha256(bof).hexdigest())
    print("saved decrypted record:", DECRYPTED_OUT)
    print("saved:", OUT)

if __name__ == "__main__":
    main()
~~~

Run it with:

~~~powershell
py -3.10 -m pip install scapy
py -3.10 q4_extract_bof.py
~~~

The important extraction values are:

~~~text
SessionKey: 53fc4c03c7b461befe5dcb268e3d9208
Application stream index: 174
BOF offset: 0x14
BOF length: 9484 bytes
~~~

The <code>0x14</code>-byte prefix is the Adaptix task/object wrapper. The next <code>9484</code> bytes are the custom COFF BOF, followed by a trailer. The recovered bytes should contain the following static markers:

~~~text
StringToByteArray
FormatNTLMv2Hash
FormatNTLMv1Hash
GetSecBufferByteArray
ParseNTResponse
GetNTLMCreds
AcquireCredentialsHandleA
InitializeSecurityContextA
AcceptSecurityContext
~~~

Finally, calculate the hash again without executing the recovered file:

~~~powershell
Get-FileHash .\\results\\ntlm_capture_bof.bin -Algorithm MD5
Get-FileHash .\\results\\ntlm_capture_bof.bin -Algorithm SHA256
~~~

The MD5 value required by the challenge is <code>56c92e28050c334b1b54974ffd022192</code>. Keep the recovered file as a non-executable analysis artefact and do not double-click it.

![Question 4 - export and carve evidence](/images/holmes_2026/borrowname/cau4_1.png)

![Question 4 - decrypted BOF evidence](/images/holmes_2026/borrowname/cau4_2.png)

![Question 4 - hash evidence](/images/holmes_2026/borrowname/cau4_3.png)

<!-- SCREENSHOT NOTE - Capture Wireshark while selecting or exporting the target response and record the packet/application stream used. Capture the terminal output from <code>q4_extract_bof.py</code> with the full MD5. In IDA, load <code>results\\ntlm_capture_bof.bin</code> as raw x64 only for static inspection; do not run it, and capture Strings/Imports containing the SSPI and NTLM markers. -->

## Question 5 - What ObjectSID belonged to the writable object?

## Answer

<code>S-1-5-21-2253468260-689643353-167204612-1125</code>

The decoded LDAP task output contains:

~~~text
ObjectDN: CN=afenwick,OU=Analysts,OU=Staff,DC=core,DC=diogenes,DC=htb
ObjectSID: S-1-5-21-2253468260-689643353-167204612-1125
ActiveDirectoryRights: WriteProperty
ObjectAceType: 28630ebb-41d5-11d1-a9c1-0000f80367c1
~~~

The important fact is not only the SID. The <code>WriteProperty</code> ACE explains why the later UPN manipulation is possible.

Once the decoded task text has been saved as <code>results\decoded_tasks.txt</code>, verify it with:

~~~powershell
Select-String -Path results\decoded_tasks.txt -Pattern "ObjectDN|ObjectSID|WriteProperty|ObjectAceType"
~~~

<!-- SCREENSHOT NOTE - Capture the LDAP block containing <code>ObjectDN</code>, <code>ObjectSID</code>, <code>ActiveDirectoryRights: WriteProperty</code>, and <code>ObjectAceType</code>. Press Ctrl+F for <code>ObjectSID</code> and include the username <code>afenwick</code> in the image. -->

![Question 5 evidence](/images/holmes_2026/borrowname/cau5.png)

## Question 6 - Which password-discovery attack was used and when?

## Answer

<code>Internal_Monologue:2026-09-09 20:44:11</code>

The timestamp comes directly from the supplied EVTX, not from a generated helper output.

Query Event ID 4021 offline:

~~~powershell
$evtx = "danger\C\Windows\System32\winevt\logs\Microsoft-Windows-NTLM%4Operational.evtx"
Get-WinEvent -Path $evtx |
    Where-Object Id -eq 4021 |
    Format-List -Property TimeCreated,Id,Message
~~~

The relevant record contains:

~~~text
TimeCreated: 2026-09-09T20:44:11.7450443Z
Computer: ws02.core.diogenes.htb
ProcessName: winupdate
Username: afenwick
DomainName: DIOCORE
Hostname: WS02
NtlmUsageReason: NTLM was called directly by the calling application.
NtlmVersion: NTLMv2
~~~

The direct NTLM call, the custom SSPI/NTLM BOF, the <code>winupdate</code> process, and the NTLMv2 response in the PCAP together identify Internal Monologue.

Public references:

- https://github.com/eladshamir/Internal-Monologue/
- https://github.com/safedv/RustSoliloquy
- https://support.microsoft.com/en-au/topic/overview-of-ntlm-auditing-enhancements-in-windows-11-version-24h2-and-windows-server-2025-b7ead732-6fc5-46a3-a943-27a4571d9e7b

The answer uses UTC exactly as recorded in the EVTX. Do not convert it to local Vietnam time.

<!-- SCREENSHOT NOTE - Capture Event ID <code>4021</code> with <code>TimeCreated</code>, <code>ProcessName: winupdate</code>, <code>Username: afenwick</code>, <code>NtlmUsageReason</code>, and <code>NtlmVersion: NTLMv2</code>. Press Ctrl+F in the event output for <code>4021</code>, <code>2026-09-09T20:44:11</code>, and <code>NTLM was called directly</code>. Also capture the Microsoft page with Ctrl+F for <code>4021</code> and the Internal Monologue page with Ctrl+F for <code>SSPI</code>. -->

![Question 6 evidence](/images/holmes_2026/borrowname/cau6.png)

## Question 7 - Which credentials were used to perform the attack?

## Answer

<code>afenwick:*Seash5lls*</code>

The PCAP contains an NTLMv2 response for <code>afenwick</code>:

~~~text
afenwick::DIOCORE:1122334455667788:032b0b4aa446b7d68c6780135ef2ec24:010100...
~~~

The recovered cleartext credential is then confirmed by the decoded task record:

~~~text
Impersonating afenwick for LDAP operations
~~~

The password was used as the credential context for the LDAP part of ResetNightmare.

For a repeatable report, print the relevant lines from the decoded task text:

~~~powershell
Select-String -Path results\decoded_tasks.txt -Pattern "afenwick::DIOCORE|Impersonating afenwick"
~~~

The NTLMv2 response is evidence of the authentication exchange; it is not itself the cleartext password. Keep the password only in the private authorized report.

<!-- SCREENSHOT NOTE - Capture one NTLMv2 block containing <code>afenwick::DIOCORE</code> and one task-output block containing <code>Impersonating afenwick for LDAP operations</code>. If the password is visible, keep that image only in the private submission and redact it in any public version. -->

![Question 7 evidence](/images/holmes_2026/borrowname/cau7.png)

## Question 8 - Which user was targeted and what was the resulting password?

## Answer

<code>jreed:Aigohng8vai0seish4zi</code>

The decoded ResetNightmare sequence says:

~~~text
Step 1: Setting fake UPN on afenwick -> jreed
Step 2: AS-REQ enterprise for kadmin/changepw as jreed
AS-REP received - KDC issued TGT for jreed
Resetting password for: jreed@CORE.DIOGENES.HTB
New password: Aigohng8vai0seish4zi
Password change success!
Verified: jreed accepts the new password
~~~

This is a direct answer: <code>jreed</code> is the target and the new password is the value printed after <code>New password:</code>.

~~~powershell
Select-String -Path results\decoded_tasks.txt -Pattern "fake UPN|jreed@CORE|New password|Password change success|Verified"
~~~

<!-- SCREENSHOT NOTE - Capture the continuous output from <code>Setting fake UPN on afenwick -> jreed</code> through <code>Verified: jreed accepts the new password</code>. The image must show the target, UPN, KDC/TGT, and password-reset success. If multiple images are needed, label them 1/2/3 in order. -->

![Question 8 evidence](/images/holmes_2026/borrowname/cau8.png)

## Question 9 - What new logon type was created after privilege escalation?

## Answer

<code>9</code>

The decoded output records:

~~~text
The user impersonated successfully: DIOCORE\jreed (logon: 9)
~~~

Logon type 9 is commonly associated with NewCredentials. The challenge asks for the number, so submit only <code>9</code>.

~~~powershell
Select-String -Path results\decoded_tasks.txt -Pattern "logon: 9|NewCredentials"
~~~

<!-- SCREENSHOT NOTE - Capture the exact line <code>DIOCORE\jreed (logon: 9)</code>, including the task heading or context immediately above it if available. Press Ctrl+F for <code>logon: 9</code>. -->

![Question 9 evidence](/images/holmes_2026/borrowname/cau9.png)

## Question 10 - What path was used to upload the new agent?

## Answer

<code>\\192.168.56.11\ADMIN$\svc_bkup</code>

The decoded output uses the hostname form:

~~~text
Trying to connect to dc02
Uploading binary (103936 bytes) to: \\dc02\ADMIN$\svc_bkup
Binary uploaded successfully (103936 bytes written)
~~~

The local recon data maps <code>dc02.core.diogenes.htb</code> to <code>192.168.56.11</code>. The checker asks for the IP-form UNC path:

~~~text
\\192.168.56.11\ADMIN$\svc_bkup
~~~

Do not remove the leading two backslashes, the administrative share, or the filename.

~~~powershell
Select-String -Path results\decoded_tasks.txt -Pattern "Trying to connect|Uploading binary|ADMIN\$|svc_bkup"
~~~

<!-- SCREENSHOT NOTE - Capture the block from <code>Trying to connect to dc02</code> through <code>Binary uploaded successfully</code>, including the 103936-byte count. Also capture the mapping of <code>dc02</code> or <code>dc02.core.diogenes.htb</code> to <code>192.168.56.11</code>. Press Ctrl+F for <code>Uploading binary</code>, <code>ADMIN$</code>, and <code>svc_bkup</code>. -->

![Question 10 evidence](/images/holmes_2026/borrowname/cau10.png)

## Question 11 - Which service group was used to start the new agent?

## Answer

<code>defragsvc</code>

The service sequence is:

~~~text
Opening service: defragsvc
Original service binary path: "C:\Windows\system32\svchost.exe -k defragsvc"
Service path was changed to: "\\dc02\ADMIN$\svc_bkup"
Service was started
Service path was restored to: "C:\Windows\system32\svchost.exe -k defragsvc"
~~~

The value appears both as the service name and as the <code>svchost.exe -k</code> service group.

~~~powershell
Select-String -Path results\decoded_tasks.txt -Pattern "Opening service|svchost.exe -k|Service was started|Service path was restored"
~~~

<!-- SCREENSHOT NOTE - Capture all five lines from <code>Opening service: defragsvc</code> through <code>Service path was restored</code>. Circle <code>defragsvc</code> both in the service name and in the <code>-k</code> parameter. -->

![Question 11 evidence](/images/holmes_2026/borrowname/cau11.png)

## Question 12 - What is the new BeaconID:SessionKey?

## Answer

<code>ddc68fa7:289122cf1ec91c67eb89c30642adfea4</code>

After lateral movement, the second beacon registers from DC02:

~~~text
type be4c0149
id   ddc68fa7
host core.diogenes.htb
computer DC02
user SYSTEM
process svc_bkup
possible key 289122cf1ec91c67eb89c30642adfea4
~~~

The second flow is:

~~~text
192.168.56.11:54162 -> 192.168.56.1:8818
~~~

Do not confuse it with the first beacon:

~~~text
First:  58debbcb:53fc4c03c7b461befe5dcb268e3d9208
Second: ddc68fa7:289122cf1ec91c67eb89c30642adfea4
~~~

## Step 12.1: Decrypt the second X-Beacon-ID in CyberChef

Use the Base64 value from the second flow's <code>X-Beacon-ID</code> header:

~~~text
Cl7gYyGw6OsT4yDjuRKh1/IIIliFthBvHdi8nHSSzaXAxjYny5Pn813viE+OLb5Zyokx9xmNd8GN3lrTwjie00eDVXoNvAc6Vfrqw/m0oGhyeHUBMdyO87QxFJ3T4Bacqkk/5jek1SbUvb9gs4UMCHGE3A==
~~~

Build this exact CyberChef recipe:

~~~text
From Base64
-> RC4
-> To Hex

RC4 passphrase: 4580221ac3fe51be1797524a048e552d
Passphrase type: Hex
RC4 input format: Latin1
RC4 output format: Latin1
~~~

The <code>From Base64</code> operation converts the header to raw bytes. RC4 then decrypts those bytes with the static EncryptionKey from Question 2. <code>To Hex</code> makes the binary registration structure searchable.

The output shown in <code>cau12.png</code> begins with:

~~~text
be4c0149ddc68fa7
~~~

Search the output for the marker <code>00000010</code>. This is a four-byte length value of 16. The next 16 bytes are:

~~~text
289122cf1ec91c67eb89c30642adfea4
~~~

The surrounding fields also decode to <code>core.diogenes.htb</code>, <code>DC02</code>, <code>SYSTEM</code>, and <code>svc_bkup</code>. Therefore the registration record confirms both halves of the answer:

~~~text
BeaconID: ddc68fa7
SessionKey: 289122cf1ec91c67eb89c30642adfea4
~~~

![Question 12 - decrypting X-Beacon-ID in CyberChef](/images/holmes_2026/borrowname/cau12.png)

<!-- SCREENSHOT NOTE - Capture the CyberChef window with the full Base64 input, From Base64 -> RC4 -> To Hex recipe, static key <code>4580221ac3fe51be1797524a048e552d</code>, RC4 input/output format Latin1, the output prefix <code>be4c0149ddc68fa7</code>, and the <code>00000010</code> marker followed by the 16-byte SessionKey. Also capture the source Wireshark request containing the second beacon's <code>X-Beacon-ID</code> header. -->

## Correlation timeline

The complete incident chain is:

~~~text
1. WS02 / afenwick registers to the Adaptix listener.
2. The agent contains the HTTP ConnectorHTTP fingerprint.
3. IDA reveals the embedded RC4 configuration and EncryptionKey.
4. The first registration packet reveals the SessionKey.
5. The decoded NTLM event identifies direct NTLM use by winupdate.
6. The custom BOF formats NTLMv2 material.
7. afenwick credentials are used for LDAP.
8. WriteProperty allows the UPN-related operation.
9. ResetNightmare / CVE-2026-27912 resets jreed's password.
10. Logon type 9 appears for the impersonated jreed context.
11. svc_bkup is uploaded through \\dc02\ADMIN$.
12. defragsvc starts the new agent.
13. DC02 registers the second beacon ddc68fa7.
~~~

<!-- SCREENSHOT NOTE - Create one final timeline image by combining small crops: Wireshark stream, IDA RC4/configuration, EVTX 4021, LDAP WriteProperty, ResetNightmare, SMB upload, service start, and the second beacon. Number the crops 1-13 so the reader can see how the answers connect. -->

## Safe submission checklist

- Use <code>Adaptix</code>, not the listener IP.
- Submit Question 2 in the exact order <code>SessionKey:EncryptionKey</code>.
- Use lowercase MD5 for Question 4.
- Preserve the complete SID in Question 5.
- Keep the underscore in <code>Internal_Monologue</code>.
- Use the UTC timestamp from the EVTX.
- Preserve the two leading backslashes in the UNC path.
- Do not execute any recovered PE, BOF, DLL, or service binary.
- Keep passwords and raw credential material inside the authorized lab report only.
