# Incident Response Report: SOC282 - Phishing Alert
**Date:** Dec 16, 2025, **Analyst:** Steven Razanajatovo, **Platform:** LetsDefend (Simulation), **Alert ID:** 257, **Severity:** High

## Executive Summary
On May 13, 2024, the SOC received an alert (SOC282) regarding a deceptive email sent to **Felix[@]letsdefend.io**. The email, purporting to offer a "Free Coffee Voucher," contained a malicious URL.

Investigation confirmed this was a phishing attempt. The email originated from a suspicious SMTP server and contained a link to a ZIP file flagged as malicious by threat intelligence vendors. The user clicked the malicious link at 12:59 PM. Remediation actions were taken to isolate the threat and block the malicious indicators.

## Incident Overview
- **Alert Rule:** SOC282 - Phishing Alert - Deceptive Mail Detected

- **Event Time:** May 13, 2024, 09:22 AM

- **Recipient:** Felix[@]letsdefend.io

- **Device Action:** Allowed (initially)

## Investigation timeline & analysis
### Email Header Analysis
The email was identified as suspicious due to the reputation of the sending infrastructure.

- **Sender Address:** free[@]coffeeshooop.com

- **SMTP Address**: 103[.]80.134.63

- **Reputation Check:** The SMTP IP 103[.]80.134.63 was flagged as suspicious by 9/95 vendors on VirusTotal.

### Social Engineering & Content
- **Subject**: "Free Coffee Voucher"

- **Lure**: The email utilized a common social engineering tactic (free gifts/vouchers) to entice the user into clicking a button.

- **Payload Location**: The button redirected the user to a ZIP file rather than a legitimate voucher page.

### User interaction & payload analysis
The user interacted with the email approximately 3.5 hours after delivery.

- **Click Time**: 2024-05-13, 12:59 PM

- **Malicious URL**: hxxps[://]download[.]cyberlearn[.]academy/download/download?url=hxxps[://]files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee[.]zip

- **Downloaded Artifact**: free-coffee.zip (Inferred from URL)

- **Payload Analysis**:

  - **SHA256**: 6f33ae4bf134c49faa14517a275c039ca1818b24fc2304649869e399ab2fb389

  - **MD5**: 73f0f77181e1f06a9dbc41ea9e7a03fe

  - **Threat Intel**: The archive was flagged as malicious by 15/64 vendors on VirusTotal.

## Indicators of Compromise (IoCs)
The following artifacts were identified and should be added to the organization's blocklists.
| Type  | Value  |
|---|---|
| Sender Email  | free[@]coffeeshooop.com  |
| Sender IP  | 103[.]80.134.63  |
| URL  | hxxps[://]download[.]cyberlearn[.]academy/download/download?url=hxxps[://]files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee[.]zip  |
| File Hash (SHA256)  | 6f33ae4bf134c49faa14517a275c039ca1818b24fc2304649869e399ab2fb389  |
|  File Hash (MD5) | 73f0f77181e1f06a9dbc41ea9e7a03fe  |

## Containment & remediation
- **User Isolation**: Given the user clicked the link, the endpoint associated with Felix was isolated to scan for successful exploitation or payload extraction.

- **Email Purge**: The malicious email was deleted from the user's inbox to prevent further interaction.

- **Blocking**:

  - The sender domain coffeeshooop.com was blocked.

  - The URL domain download.cyberlearn.academy was added to the web proxy blocklist.


## Recommendations
1. **Phishing Simulation**: Enroll the user (Felix) in remedial anti-phishing training, specifically focusing on validating sender addresses and hovering over links before clicking.

2. **Email Filtering**: Increase spam filter strictness for domains with poor reputation or newly registered domains (like the misspelled coffeeshooop.com).

3. **Endpoint Protection**: Ensure EDR policies are set to automatically scan and block archives downloaded from unverified sources.