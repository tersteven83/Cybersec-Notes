# Incident Response Report: SOC326 - Impersonating Domain (Typosquatting)
**Incident:** SOC326 / EventID 304, **Date of Report:** "Dec 22, 2025", 
**Analyst:** Steven Razanajatovo, **Severity:** High,
**Status:** Closed, **Verdict:** True Positive

## Executive summary
On September 17, 2024, the SOC received a Threat Intelligence alert (SOC326) indicating a suspicious MX record change for a domain impersonating the organization: **letsdefwnd[.]io**.

Subsequent investigation revealed that this domain was actively used in a phishing campaign against internal users. Specifically, a user (**mateo[@]letsdefend.io)** received a phishing email on September 18, 2024, and clicked the malicious link contained within. The incident is classified as a True Positive, involving successful delivery and user interaction with a typosquatted domain.

## Incident overview
- **Alert Rule**: SOC326 - Impersonating Domain MX Record Change Detected

- **Event Time (Alert):** Sep 17, 2024, 12:05 PM

- **Malicious Domain**: letsdefwnd[.]io (Typosquatting letsdefend.io)

- **Device Action**: Allowed

## Investigation timeline & analysis
### Threat Intelligence Trigger
The investigation began with an automated report from `no-reply[@]cti-report.io` warning of a potential impersonation attempt.

- **Indicator**: The MX record for  `letsdefwnd[.]io` was set to mail.`mailerhost[.]net`, a configuration often associated with spam/phishing infrastructure.

- **Trigger Reason**: The domain `letsdefwnd[.]io` is a "typosquat" of the legitimate `letsdefend.io` domain, created to deceive users.

### Phishing campaign discovery
Searching the email security gateway for the identified domain revealed an active phishing attempt delivered the following day.

- **Email Delivery**: Sep 18, 2024, 08:00 AM.

- **Sender**: `voucher[@]letsdefwnd.io`.

- **Recipient**: `mateo[@]letsdefend.io`.

- **Subject**: "Congratulations! You've Won a Voucher".

- **Content Analysis**: The email impersonated the organization (LetsDefend) and contained a URL redirecting to the typosquatted website.

### User interaction
Log analysis confirmed that the recipient interacted with the malicious email approximately 5 hours after delivery.

- **Click Time**: 2024-09-18, 13:32:13.

- **Action**: The user accessed the malicious URL `http[:]//www.letsdefwnd.io/`.

## Indicator of Compromise (IoCs)
The following artifacts were identified and require blocking across email and web gateways.

| Type  | Value  | Content  |
|---|---|---|
| Domain  | `letsdefwnd.io`  | Typosquatted / Phishing Domain  |
| Sender Address  | `voucher[@]letsdefwnd.io`  | Phishing sender  |
| URL  | `http[://]www.letsdefwnd.io/`  | Malicious landing page  |
| MX Record  | `mail[.]mailerhost.net`  | Suspicous Mail Server  |