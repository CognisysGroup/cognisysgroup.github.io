---
title: Beyond the Perimeter How an On-Premises Domain Admin Compromise Unlocked the Cloud
author: Manan
date: 2026-04-17 12:55:00 +0100
categories: [red-team, cloud-security]
tags: [active-directory, entra-id, token-theft, mfa-bypass, red-team]
image:
  path: https://github.com/user-attachments/assets/c309c9e5-4c67-4317-a0df-3b226a6bfce7
  alt: 
render_with_liquid: false
---

Imagine a standard Red Team engagement scenario. Where you somehow manage to compromise a single low-privileged on-premises user. You execute a series of classic post-exploitation manoeuvres: moving laterally, exploiting legacy configurations, and navigating internal network segments. Finally, the "Holy Grail" is achieved, YESS! **Domain Admin** privileges within the internal Active Directory forest.

Historically, this would signal "game over." Domain Admin implies total control over every server, workstation, and user object within the internal environment. In modern organisations, Critical information infrastructure storing business logic, sensitive customer data, and organisational control has shifted to the cloud (**Azure AD**).

During our recent engagement, we demonstrated a sophisticated "bridge" attack that shattered the traditional dichotomy between internal and cloud security. We proved that by holding on-premises Domain Admin rights, we could target specific high-value workstations, bypass modern Multi-Factor Authentication (MFA) and Conditional Access policies, and pivot directly into the cloud as a **Global Administrator**. This post provides a detailed analysis of how this full compromise was executed.

We had Domain Admin privileges, but our major blockers were MFA & the Conditional Access Policies required to access an O365 account. That's when TOKENS come into play.

## Understanding Modern Token-Based Authentication

To understand how this pivot was possible, one must grasp the fundamentals of modern Single Sign-On (SSO) used by Microsoft 365. When a user logs in to a modern desktop application like Microsoft Outlook or Teams, they do not have to continuously enter their password. Instead, after an initial successful authentication (which includes MFA), the Entra ID security token service issues various tokens:

- **Access Tokens (AT):** Short-lived tokens that grant access to specific resources (e.g., MS Graph API or Exchange Online). Think of this as a temporary visitor's badge.
- **Refresh Tokens (RT):** Longer-lived tokens used to request a new Access Token without prompting the user to re-authenticate.

## Approach: Merging Internal and Cloud Post Exploitation

At Cognisys, we differentiate our methodology by moving beyond automated scanners and adopting a "Living off the Land" methodology. Holding Domain Admin privileges is not just a status; it is a capability. The manual approach involves using that level of access to systematically map the environment and identify the *highest-value targets* that link the internal network to the cloud.

We knew that our Domain Admin access allowed us to interact with any Windows system in the domain. We also knew that certain accounts would possess significant administrative roles in Entra ID. The objective was clear: combine standard internal toolsets with modern cloud enumeration tools to identify a highly privileged **Entra ID administrator, locate their active workstation, and target specific processes to hijack their active session**.

## Exploitation Phase: From On-Premises to Cloud Compromise

The attack chain progressed chronologically, pivoting from internal to cloud control in four distinct stages.

![Attack chain overview](https://github.com/user-attachments/assets/178af0c3-3a2e-4c8f-9fa2-b5ea49bae42a)

### The Cloud Reconnaissance: Enumerating Directory Roles

Following the initial Domain Admin compromise, our first objective was to understand the entity's cloud tenant structure. While holding DA on-premises gives control over synced identities, it does not directly grant cloud administrative rights.

We utilised compromised user's credentials to authenticate and run ROADrecon for enumerating the Entra. Members of highly privileged Directory Roles were identified, as illustrated in the following snapshot.

```bash
┌──(cognisys㉿ GCH-NUC)-[~/example]
└─$ roadrecon auth -u highprivilegeuser@example.com -p SecurePassword -c azcli
Tokens were written to .roadtools_auth

┌──(cognisys㉿ GCH-NUC)-[~/example]
└─$ cat .roadtools_auth
{"tokenType": "Bearer", "expiresOn": "2026-03-03 12:26:33", "tenantId": "Redacted-d169-435c-aa2d-Random-Tenant-ID", "_clientId": "Redacted-8ddb-461a-bbee-RandomID", "accessToken": "eyJ0eXAiOiJKV1QiiJSUzI1NiIsIng1d-redacted", "expiresIn": 4367}

┌──(cognisys㉿ GCH-NUC)-[~/example]
└─$ roadrecon gather
Starting data gathering phase 1 of 2 (collecting objects)
Gathered 7544 groups, switching to 3-phase approach for efficiency
Starting data gathering phase 2 of 3 (collecting properties and relationships)
```

*Running roadrecon*

![Identifying Global Administrator Roles](https://github.com/user-attachments/assets/ded869d6-4657-4aec-ad25-2a61677fa777)

### The Internal Hunt: Locating the Target Session

`highprivilegeuser@example.com` was identified as the user with high-level privileges. The next step was to find *where* this user was actively logged in on the internal network.

By utilising our Domain Admin rights, we queried active logon sessions on the workstation via `netexec --loggedon-users` module over SMB. This revealed that the Entra high-privilege user was logged onto a specific computer.

![Logged-on users via netexec](https://github.com/user-attachments/assets/0dbaa158-2263-4d72-bc3d-aca419a09cdc)

> **NOTE:** Workstations can also be identified under the owned objects by clicking on the USERID as shown below.

![Workstations under owned objects](https://github.com/user-attachments/assets/957f9df1-8376-4821-838f-2e71f8e0b27a)

### The Token Heist: Dumping Office Processes

Once logged in to the system as an Administrator, we checked for active Office 365 processes using the `tasklist /v` command. We confirmed that both **outlook.exe** and **teams.exe** were actively running under the Global Administrator's user context.

All we had to do was open a WinRM session and upload our so-called "CLEAN" script to dump these non-protected processes, as shown in the snapshot below.

![Dumping Office processes](https://github.com/user-attachments/assets/031a571d-dcc8-465c-9a90-12c58ef7c44e)

After the script runs, a `.dmp` file is generated for MS Teams (`ms-teams_14660.dmp`) that, as shown in the snapshot below, contains the access and refresh tokens.

![Tokens inside the memory dump](https://github.com/user-attachments/assets/c585113b-6d70-4261-9f16-f1659be56b39)

We exfiltrated the dump file over SMB to our system and used the command below to find the access and refresh tokens:

```bash
strings ms-teams.dmp | grep eyJ0eX
```

![Extracted tokens from dump](https://github.com/user-attachments/assets/effc7d01-a48d-4ad4-9d11-ac701f023bd2)

The accompanying snapshot clearly indicates that the high-privilege user's Entra tokens have been compromised, which can be reused with the roadrecon again and MSGRAPH to access APIs as a High Privileged User.

Link to the PowerShell script: [https://github.com/mjain61/WAMBAM](https://github.com/mjain61/WAMBAM)

## Remediation Strategy

1. **Deploy Privileged Access Workstations (PAWs):** Isolate administrative tasks on hardened devices dedicated solely to cloud management. These devices must be cloud-native (Entra ID joined only), have no everyday productivity applications installed, and be secured by strict, device-based Conditional Access policies.
2. **Implement Privileged Identity Management (PIM):** Ensure that administrative roles, such as "Global Administrator," are never permanently assigned. Require Just-In-Time (JIT) activation with mandatory approval workflows and a secondary MFA check during activation.
3. **Enforce Phishing-Resistant MFA:** Avoid standard push notifications. Mandate hardware keys (FIDO2), which reduce the reliance on stateless bearer tokens that are easily reusable if moved to a different device.
4. **Audit EDR for Memory Access:** Review and refine existing Endpoint Detection and Response (EDR) telemetry to specifically alert on non-standard processes attempting to read the memory of browser (`msedge.exe`) or Office-related applications (`outlook.exe`, `teams.exe`).

The core takeaway is this - the security of your internal network and your cloud identity perimeter are inextricably linked. Threat actors predictably seek the easiest entry point, and that vulnerability is increasingly found in the gap that allows them to leverage internal network administrative privileges to gain modern, token-based cloud access.

## References

- [MITRE ATT&CK: Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK: OS Credential Dumping: Process Memory (T1003.001)](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft Entra: Privileged Identity Management](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- [XPN Security — WAM BAM](https://blog.xpnsec.com/wam-bam/)
- [mrd0x — Stealing Tokens from Office Applications](https://mrd0x.com/stealing-tokens-from-office-applications/)
- [NetExec — Dump Token Broker Cache](https://www.netexec.wiki/smb-protocol/obtaining-credentials/dump-token-broker-cache)
- [xpn/WAMBam (GitHub)](https://github.com/xpn/WAMBam)
- [TrustedSec — Weaponization of Token Theft: A Red Team Perspective](https://trustedsec.com/blog/weaponization-of-token-theft-a-red-team-perspective)
- [g0ttfrid/Steal365 (GitHub)](https://github.com/g0ttfrid/Steal365/)
- [mjain61/WAMBAM (GitHub)](https://github.com/mjain61/WAMBAM)
