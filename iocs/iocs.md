\# 🔍 Indicators of Compromise (IOCs)



> \*\*Lab:\*\* Endpoint Security Monitoring Lab  

> \*\*Date:\*\* April 7, 2026  

> \*\*Analyst:\*\* Mallela Seshagiri  

> \*\*Environment:\*\* Isolated Virtual Lab (VMware Workstation)



\---



\## 📁 File IOCs



| Type | Value |

|------|-------|

| Filename | `malware1.exe` |

| Filename | `malware.exe` |

| File Path | `C:\\Users\\malle\\Downloads\\malware1.exe` |

| File Path | `C:\\Users\\malle\\Downloads\\malware.exe` |

| File Size (Variant 1) | `7,680 bytes (7.5 KB)` |

| File Size (Variant 2) | `7,168 bytes (7 KB)` |

| File Type | `PE32 executable (GUI) Intel i386, MS Windows` |

| Signed | ❌ No — unsigned, no publisher |

| Timestamp (Variant 1) | `07-04-2026 15:59` |

| Timestamp (Variant 2) | `07-04-2026 17:48` |



\---



\## 🌐 Network IOCs



| Type | Value |

|------|-------|

| C2 IP (Attacker) | `192.168.195.128` |

| C2 IP (Alt) | `192.168.195.130` |

| C2 Port — Session 1 | `4444 (TCP)` |

| C2 Port — Session 2 | `4443 (TCP)` |

| Victim IP | `192.168.195.129` |

| Local Port Used | `50547` |

| Protocol | `TCP` |

| Direction | `Outbound — victim → attacker` |

| Connection State | `ESTABLISHED` |

| Connection Timestamp | `07-04-2026 16:12:35` |



\---



\## ⚙️ Process IOCs



| Process | PID | Status | Detail |

|---------|-----|--------|--------|

| `malware1.exe` | `5892` | 🚩 MALICIOUS | Unsigned, C2 connection established, spawned cmd.exe |

| `malware.exe` | `6880` | 🚩 MALICIOUS | Highlighted red in Process Explorer, connected to 192.168.195.128:4443 |

| `cmd.exe` | `2180` | ⚠️ SUSPICIOUS | Spawned BY malware — not user initiated |

| `cmd.exe` | `2172` | ⚠️ SUSPICIOUS | Second shell spawned by malware process |

| `conhost.exe` | `7768` | ⚠️ SUSPICIOUS | Console host for malware-spawned cmd.exe |

| `conhost.exe` | `604` | ⚠️ SUSPICIOUS | Console host for second cmd.exe instance |



\---



\## 🔗 Behavioral IOCs



| Behavior | Why It's Suspicious |

|----------|---------------------|

| Unsigned EXE executed from Downloads folder | Legitimate software is typically signed |

| Process with no Company Name in Process Explorer | Strong indicator of custom/malicious binary |

| Non-browser process making outbound TCP connection | `malware.exe` has no legitimate reason to connect outbound |

| Outbound connection to non-standard port (4443/4444) | Not HTTP/HTTPS — consistent with C2 traffic |

| `cmd.exe` spawned by unknown parent process | Should only be spawned by user or known system process |

| `conhost.exe` as child of malware process | Confirms interactive shell was opened post-exploitation |

| Process highlighted red in Process Explorer | No verified publisher = unsigned / unrecognized binary |



\---



\## 🛠️ Attacker Tooling IOCs



| Type | Value |

|------|-------|

| Framework | `Metasploit Framework v6.4.116-dev` |

| Tool | `msfvenom` |

| Payload | `windows/meterpreter/reverse\_tcp` |

| LHOST | `192.168.195.128` |

| LPORT | `4443 / 4444` |

| Output Format | `-f exe` |

| Raw Payload Size | `354 bytes` |

| Final EXE Size | `7,168 – 7,680 bytes` |

| Architecture | `x86 (Intel i386)` |



\---



\## 🎯 Detection Rules (Sigma-style)



\### Rule 1 — Unsigned EXE Running from Downloads

```yaml

title: Unsigned Executable Launched from Downloads Folder

status: experimental

description: Detects execution of unsigned PE files from user Downloads directory

logsource:

&#x20; category: process\_creation

&#x20; product: windows

detection:

&#x20; selection:

&#x20;   Image|contains: '\\Downloads\\'

&#x20;   Signed: 'false'

&#x20; condition: selection

level: high

tags:

&#x20; - attack.execution

&#x20; - attack.t1204.002

```



\### Rule 2 — Non-Browser Outbound on Port 4443/4444

```yaml

title: Suspicious Outbound TCP on Port 4443 or 4444

status: experimental

description: Detects non-browser processes making outbound TCP to common C2 ports

logsource:

&#x20; category: network\_connection

&#x20; product: windows

detection:

&#x20; selection:

&#x20;   DestinationPort:

&#x20;     - 4443

&#x20;     - 4444

&#x20;   Initiated: 'true'

&#x20; filter:

&#x20;   Image|contains:

&#x20;     - 'chrome.exe'

&#x20;     - 'firefox.exe'

&#x20;     - 'msedge.exe'

&#x20; condition: selection and not filter

level: high

tags:

&#x20; - attack.command\_and\_control

&#x20; - attack.t1071.001

```



\### Rule 3 — cmd.exe Spawned by Suspicious Parent

```yaml

title: cmd.exe Spawned by Non-Standard Parent

status: experimental

description: Detects cmd.exe launched by unexpected parent processes

logsource:

&#x20; category: process\_creation

&#x20; product: windows

detection:

&#x20; selection:

&#x20;   Image|endswith: '\\cmd.exe'

&#x20; filter:

&#x20;   ParentImage|endswith:

&#x20;     - '\\explorer.exe'

&#x20;     - '\\powershell.exe'

&#x20;     - '\\cmd.exe'

&#x20;     - '\\svchost.exe'

&#x20; condition: selection and not filter

level: medium

tags:

&#x20; - attack.execution

&#x20; - attack.t1059.003

```



\---



\## 🗺️ MITRE ATT\&CK Mapping



| Technique ID | Name | Evidence |

|-------------|------|---------|

| `T1204.002` | Malicious File | malware.exe executed from Downloads |

| `T1059.003` | Windows Command Shell | cmd.exe spawned by malware process |

| `T1071.001` | C2 over TCP | Connection to 192.168.195.128/130 on 4443/4444 |

| `T1105` | Ingress Tool Transfer | Payload transferred and staged on victim |

| `T1049` | System Network Connections Discovery | netstat used to verify connections |

| `T1057` | Process Discovery | tasklist used to find malware PID |

| `T1036` | Masquerading | Unsigned EXE with no publisher info |



\---



\## 🔬 Tools Used for Detection



| Tool | Finding |

|------|---------|

| `netstat` | Confirmed ESTABLISHED connection to 192.168.195.130:4444 |

| `tasklist` | Identified malware1.exe at PID 5892 |

| `TCPView` | Linked malware1.exe PID 5892 to C2 connection at port 4444 |

| `Process Explorer` | Full process tree showing malware → cmd.exe → conhost.exe chain |



\---



> ⚠️ \*\*Disclaimer:\*\* All IOCs above were generated in an isolated virtual lab environment for educational purposes only.  

> IP addresses are private lab addresses (192.168.195.0/24). Do not use for production threat hunting without validation.

