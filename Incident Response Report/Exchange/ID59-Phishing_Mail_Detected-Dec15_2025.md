# Incident Report: Phishing Mail Detected
**Date:** Dec 15, 2025, **Analyst:** Steven Razanajatovo, **Platform:** LetsDefend (Simulation), **Alert ID:** SOC101, **Severity:** Low
## Executive Summary
A phishing attempt was detected on February 14th, 2021. Upon investigation, this was classified as a True Positive. The incident involved a suspicious email threatening the user and demanding payment to restore account access. The email was successfully identified and removed from the user's inbox.

## Investigation Steps
- **Source Analysis:** Analyzed the source IP address of the SMTP server. VirusTotal flagged this IP as malicious with a score of 5/95.

- **Sender Reputation:** Checked the sender's reputation using Cisco Talos Intelligence. While the specific reputation was "unknown," the domain name (**ihackedyourcomputer.com**) is clearly indicative of malicious intent.

- Content Analysis: The email body used coercive language, demanding a ransom payment from the user to regain access to their data.

## Indicator of Compromise
| Type  | Value | Description       |
|-------|-----|------------|
| IP Address | 27.128.173.81  | SMTP IP address   | 
| Sender Email   | hahaha@ihackedyourcomputer.com | Attacker's email address     |
| Domain Name | ihackedyourcomputer.com  | Attacker's domain name      |

## Remediation & Action Taken:

- **Decision:** True Positive (Phishing/Extortion).

- **Action:** Removed the email from the inbox.


## Recommendation
Conduct user security awareness training on identifying phishing indicators. Instruct users to report suspicious emails immediately rather than interacting with them.