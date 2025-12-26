# Incident Response Report: SOC202 - FakeGPT Malicious Chrome Extension

**Incident ID**: SOC202 / EventID 153 ,**Date of Report**: Dec 24, 2025, 
**Analyst**: Steven Razanajatovo, **Severity**: High, 
**Status**: Closed, **Verdict**: True Positive

## Executive Summary
On May 29, 2023, the SOC detected the installation of a suspicious browser extension on the endpoint "**Samuel**" (172.16.17.173).

Investigation confirmed that the user downloaded a malicious Chrome extension disguised as "ChatGPT for Google." Upon installation, the extension initiated network connections to known malicious domains (`chatgptgoogle.org` and `chatgptforgoogle.pro`), likely for Command and Control (C2) or data exfiltration purposes. The incident is classified as a True Positive data leakage threat.

## Incidient overview
**Alert Rule:** SOC202 - FakeGPT Malicious Chrome Extension

**Event Time**: May 29, 2023, 01:01 PM

**Hostname**: Samuel

**File Name:** hacfaophiklaeolhnmckojjjjbnappen.crx

**Incident Type:** Data Leakage

## Investigation Timeline & Analysis
### Installation vector
The user manually navigated to the Chrome Web Store to install the extension.

- **13:01:44**: User accessed the URL: `https://chrome.google.com/webstore/detail/chatgpt-for-google/hacfaophiklaeolhnmckojjjjbnappen`.

- **13:02:01**: The extension was successfully installed, and the user visited the landing page `chrome://extensions/?id=hacfaophiklaeolhnmckojjjjbnappen`.

- **File Hash**: The extension file (.crx) hash `7421f9abe5e618a0d517861f4709df53292a5f137053a227bfb4eb8e152a4669` is flagged as malicious by Exodia Labs on VirusTotal.
![Exodia Labs report on Virustotal](../img/E153-exodia-report.png)

### Network traffic & C2 Communication
Immediately following installation, the extension generated traffic to several external domains flagged as malicious.

- **Primary C2**: Connection observed to `www.chatgptgoogle.org` (Resolving to `18[.]140.6.45` and others).

  - **Reputation**: 7/95 malicious on VirusTotal.
![Primary C2](../img/E153-primaryC2-VT.png)

- **Secondary C2**: Connection to `www.chatgptforgoogle.pro` (Resolving to 52[.]76.101.124).

- **Additional Infrastructure**: DNS queries were observed for version.`chatgpt4google.workers.dev`, indicating the use of Cloudflare Workers for infrastructure evasion.

## Indicators of Compromise (IoCs)
The following artifacts identify the malicious extension and its infrastructure.
| Type  | Value  | Context  |
|---|---|---|
| Extension ID  | `hacfaophiklaeolhnmckojjjjbnappen`  |  Chrome Extension ID |
| File Hash (SHA256)  |`7421f9abe5e618a0d517861f4709df53292a5f137053a227bfb4eb8e152a4669`  | Extension CRX File  |
| Domain  | `www.chatgptgoogle.org`  | C2 Domain  |
| Domain  | `www.chatgptforgoogle.pro`  | C2 Domain  |
| IP Address  | `18.140.6.45`  | C2 IP  |
| IP address  | `52.76.101.124`  | C2 IP  |

## Containment & Remediation
- **Extension Removal**: Force remove the extension with ID `hacfaophiklaeolhnmckojjjjbnappen` from the endpoint.

- **Session Reset**: Reset all active browser sessions and cookies for the user "Samuel," as the extension may have stolen session tokens (Data Leakage risk).

- **Credential Rotation**: Force a password reset for any accounts accessed by the user while the extension was active.

- **Blocking**: Add `chatgptgoogle.org` and `chatgptforgoogle.pro` to the web proxy blocklist.

## Recommendations
1. **Browser Policy**: Implement Group Policy (GPO) to restrict browser extension installations to an approved "allowlist" only.

2. **Shadow IT Awareness**: Educate users on the risks of installing unapproved "productivity" tools, specifically those claiming to integrate AI services like ChatGPT, which are common vectors for malware.