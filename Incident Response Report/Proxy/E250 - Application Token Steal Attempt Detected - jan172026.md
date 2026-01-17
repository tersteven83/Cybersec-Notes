# Incident Response Report: SOC275 - Application Token Steal Attempt
**Incident ID**: SOC275 / EventID 250, **Date of Report**: "Jan 17, 2026", 
**Analyst**: Steven Razanajatovo, **Severity**: Medium, 
**Status**: Closed, **Verdict**: True Positive

## Executive summary
On April 19, 2024, at 08:23 AM, the SOC received an alert (SOC275) indicating a potential application token theft attempt targeting the user "**Gloriana**" (`gloriana@letsdefend.io`).

Investigation confirmed that the user's device (172.16.17.172) initiated a connection to a malicious external domain (`homespottersf.com`). This interaction involved a GET request to a fake password reset page, followed immediately by a POST request containing a sensitive token value (`123letsdefendisthebest123`) to a different external IP (`23.82.12.29`). This behavior is consistent with a successful token harvesting or "Man-in-the-Middle" (MitM) phishing attack. The incident is classified as a True Positive data leakage event.

## Incident overview
- **Alert Rule**: SOC275 - Application Token Steal Attempt Detected

- **Event Time**: Apr 19, 2024, 08:23 AM

- **Hostname**: Gloriana (172.16.17.172)

- **Target URL**: `http://homespottersf.com:8081/reset-password`

- **Action**: Redirect (302)

## Investigation timeline & analysis
### Initial Access (Get Request)
The user likely clicked a phishing link disguised as a password reset request.

- **Request**: `GET /reset-password?email=gloriana@letsdefend.io HTTP/1.1`

- **Destination**: `20.42.73.27` (hosting `homespottersf.com`).

- **Reputation**: The domain `homespottersf.com` is flagged as malicious by security vendors.

- **Response**: The server responded with a **302 Found** status, redirecting the user to a secondary destination.

### Data exfiltration (POST Request)
Immediately following the redirect, a POST request was observed, indicating the submission of credential or token data.

- **Request**: `POST /reset-password?token=123letsdefendisthebest123`

- **Destination**: `23.82.12.29`.

- **Significance**: The URL parameter token contains a specific value. In a real-world attack, this would likely be a valid session reset token that the attacker can now use to take over the account. The change in destination IP (from `20.42.73.27` to `23.82.12.29`) suggests a backend infrastructure where the initial landing page redirects to the harvester.

## Indicators of Compromise (IOCs)

The following artifacts identify the phishing infrastructure.
| Type  | Value  | Context  |
|---|---|---|
| Domain  | `homespottersf.com`  | Malicious landing page  |
| IP address  | `20.42.73.27`  | Hosting IP (Initial)  |
| IP address  | `23.82.12.29`  | Hosting IP (harvester)  |
| URL Pattern  | `/reset-password?token=`  | Token Exfiltration URL  |

## containment & remediation
- **Account Reset**: Immediately reset the password for `gloriana@letsdefend.io`.

- **Session Revocation**: Revoke all active sessions for the user to invalidate any tokens that may have been stolen.

- **Blocking**: Block `homespottersf.com`, `20.42.73.27`, and `23.82.12.29` at the web proxy and firewall.

- **User Training**: Enroll the user in phishing awareness training, specifically regarding "Password Reset" lures.

## Recommendations
1. **Link Analysis**: Implement email security tools that rewrite URLs (e.g., "Safe Links") to analyze destination domains at the time of click.

2. **MFA**: Ensure Multi-Factor Authentication (MFA) is enforced. Even if a password reset token is stolen, MFA can prevent the attacker from finalizing the login or password change process.