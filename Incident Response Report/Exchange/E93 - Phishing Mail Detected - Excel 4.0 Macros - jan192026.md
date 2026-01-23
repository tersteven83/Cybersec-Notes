# Incident Response Report: SOC146 - Phishing with Excel 4.0 Macros

**Incident ID**: SOC146 / EventID 93, **Date of Report**: "Jan 19, 2026"
**Analyst**: Steven Razanajatovo, **Severity**: High, 
**Status**: Closed, **Verdict**: True Positive

## Executive summary
On June 13, 2021, at 02:13 PM, the SOC received an alert (SOC146) regarding a phishing email containing a malicious Excel attachment targeting "**Lars**" (`lars@letsdefend.io`).

Investigation confirmed that the user opened an attachment utilizing Excel 4.0 Macros (XLM) to evade standard detection. Upon execution, the macro initiated network connections to multiple external domains (`visionconsulting.ro` and `sparkblue.lk`) to download secondary payloads (`dot.html`). The incident is classified as a True Positive malware infection via phishing.

## Incident overview
- **Alert Rule**: SOC146 - Phishing Mail Detected - Excel 4.0 Macros

- **Event Time**: Jun 13, 2021, 02:13 PM

- **Sender**: `trenton@tritowncomputers.com`

- **Recipient**: `lars@letsdefend.io`

- **Subject**: `RE: Meeting Notes`

- **Action**: Allowed

## Investigation timeline & analysis
### Delivery analysis
The phishing email used a "Reply" style subject line (RE: Meeting Notes) to establish false trust.

- **Source IP**: `24.213.228.54`.

- **Attachment Analysis**: The email contained a malicious attachment with MD5 hash `9458859abfd384f38362af01fb306f14`.

- **Reputation**: The file is flagged as malicious by 10/63 vendors on VirusTotal, specifically noting the presence of legacy Excel 4.0 (XLM) macros often used by malware families like Emotet or Qakbot.

### Execution & C2 communication
Log analysis confirmed that the user opened the file and enabled macros, triggering excel.exe to initiate network connections.

- **Domain 1**: `nws.visionconsulting.ro` (IP: `188.213.19.81`)

    - **Time**: 02:20 PM (7 minutes after delivery)

    - **Request**: `GET https://nws.visionconsulting.ro/N1G1KCXA/dot.html`

- **Domain 2**: `royalpalm.sparkblue.lk` (IP: `192.232.219.67`)

    - **Time**: 02:20 PM

    - **Request**: GET `https://royalpalm.sparkblue.lk/vCNhYrq3Yg8/dot.html`

### Technique assessment
The use of `dot.html` as a payload often indicates a technique where the malware downloads a disguised DLL or binary and executes it via `rundll32` or `regsvr32`. The successful connection suggests the dropper was active.

## Indicators of Compromise (IOCs)
The following artifacts identify the malicious infrastructure.

| Type  | Value  | Context  |
|---|---|---|
| File Hash (MD5)  | `9458859abfd384f38362af01fb306f14`  | Malicious Excel Attachment  |
| Domain  | `nws.visionconsulting.ro`  | C2 / Payload Delivery  |
| Domain  | `royalpalm.sparkblue.lk`  | C2 / Payload Delivery  |
| Sender Email  | `trenton@tritowncomputers.com`  | Phishing Sender  |

## Containment & Remediation
- **Isolation**: Isolate the device used by `lars@letsdefend.io` to prevent lateral movement.

- **Process Termination**: Kill `excel.exe` or any suspicious child processes (e.g., `regsvr32`, `rundll32`, `cmd.exe`).

- **Email Purge**: Search for and delete the email `RE: Meeting Notes` from the user's mailbox.

- **Blocking**: Block the domains `nws.visionconsulting.ro` and `royalpalm.sparkblue.lk` at the web proxy.

## Recommendations
1. **Disable XLM Macros**: Configure Group Policy to block Excel 4.0 (XLM) macros entirely, as they are a deprecated feature heavily abused by threat actors.

2. **Attack Surface Reduction**: Enable ASR rules to "Block all Office applications from creating child processes."