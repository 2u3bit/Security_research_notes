# Day 6: How to prevent token theft and AiTM using Microsoft Defender
In my last post, I elaborated on the vast information related to AiTM and how advanced these attacks have become. These incredibly sophisticated tactics included building fraudulent sites that captured users' login credentials, allowing attackers to take over sign-in sessions, and bypassing authentication protections—even with Multifactor Authentication (MFA) enabled.

Today, I'm going to explain more about how to detect and mitigate these kinds of attacks using Microsoft Defender. Related blogs used for this research are marked below the page under the resource section, so feel free to check them out.


## Detecting AiTM:
Automated tools used by adversaries: <br>
■ [Evilginx2](https://github.com/kgretzky/evilginx2)<br>
■ [Modlishka](https://github.com/drk1wi/Modlishka)<br>
■ [Muraena](https://github.com/muraenateam/muraena)<br>


### Overview
To detect token theft using Microsoft Defender and Microsoft Entra, focus on key Indicators of Compromise (IOCs), like impossible travel alerts.

Token theft detection can be tricky, but monitoring certain indicators, such as impossible travel, helps. In Entra ID, reviewing sign-in logs for anomalies is essential, though high log volumes can complicate this. Effective filtering and analysis are crucial.

**Example:** If a user in the US successfully signs in from Europe, it could indicate a compromise. Consider:

| **Key Factor**       | **Description**                                |
|----------------------|------------------------------------------------|
| **Successful login** | A login attempt that was successful            |
| **Location**         | The geographical location of the login attempt |
| **Timing**           | The interval between these login attempts      |

### Entra ID Protection
Entra ID Protection (P2) and Defender for Cloud Apps automatically raise alerts for certain events, with no extra setup needed. However, third-party apps may require manual configuration.

| **Alert Type**                  | **Description**                                                                 |
|---------------------------------|---------------------------------------------------------------------------------|
| **Anomalous Token**             | Flags tokens with unusual characteristics, like unexpected locations or token lifetime |
| **Unfamiliar sign-in properties** | Detects sign-ins from unfamiliar regions, often using proxies or VPNs          |
| **Unfamiliar session cookies**  | Flags anomalies in token claims, age, and other authentication details          |
| **Anonymous IP address**        | Detects sign-ins from anonymous IPs (e.g., Tor or anonymous VPNs)               |

### Defender for Cloud Apps

| **Alert Type**                       | **Description**                                                        |
|--------------------------------------|------------------------------------------------------------------------|
| **Suspicious inbox manipulation rule** | Alerts when attackers create rules to hide their activities             |
| **Impossible travel activity**       | Flags sign-ins from multiple locations simultaneously, often due to VPN use |
| **Activity from infrequent country** | Detects logins from unusual locations based on VPN or proxy usage       |

### Defender for Endpoints and Microsoft 365 Defender

| **Alert Type**            | **Description**                                                                  |
|---------------------------|----------------------------------------------------------------------------------|
| **Stolen session cookie used** | Alerts when session cookies are stolen and replayed in phishing attacks       |

### Defender for Office 365

| **Alert Type**                                      | **Description**                                                                              |
|-----------------------------------------------------|----------------------------------------------------------------------------------------------|
| **Malicious file email removed after delivery**     | Triggers when infected emails are delivered and then removed by Microsoft                     |
| **Campaign-related email removed after delivery**   | Triggers when campaign-associated emails are delivered and then removed by Microsoft          |

### Defender XDR Detection and Entra ID Protection Integration
Defender XDR and Entra ID Protection are integrated by default, enabling automatic attack disruption without pre-configuration.

| **Detection Type**                      | **Description**                                                    |
|-----------------------------------------|--------------------------------------------------------------------|
| **User compromised via AiTM phishing kit** | Detects when a user is compromised through a known AiTM phishing kit |
| **User compromised in AiTM phishing attack** | Detects when a user is compromised in an AiTM phishing attack       |
| **Possible AiTM phishing attempt in Okta** | Flags potential AiTM phishing attempts in Okta                      |

Additionally, [Continuous Access Evaluation (CAE)](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation) revokes access in real time when user conditions change, such as termination or relocation to an untrusted area.


### Detecting AiTM using advanced hunting queries

> When an attacker uses a stolen session cookie, the “SessionId” attribute in the AADSignInEventBeta table will be identical to the SessionId value used in the authentication process against the phishing site. Use this query to search for cookies that were first seen after OfficeHome application authentication (as seen when the user authenticated to the AiTM phishing site) and then seen being used in other applications in other countries:

```kusto
let OfficeHomeSessionIds = 
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where ApplicationId == "4765445b-32c6-49b0-83e6-1d93765276ca" //OfficeHome application 
| where ClientAppUsed == "Browser"
| where LogonType has "interactiveUser" 
| summarize arg_min(Timestamp, Country) by SessionId; 
AADSignInEventsBeta 
| where Timestamp > ago(1d) 
| where ApplicationId != "4765445b-32c6-49b0-83e6-1d93765276ca" 
| where ClientAppUsed == "Browser" 
| project OtherTimestamp = Timestamp, Application, ApplicationId, AccountObjectId, AccountDisplayName, OtherCountry = Country, SessionId 
| join OfficeHomeSessionIds on SessionId 
| where OtherTimestamp > Timestamp and OtherCountry != Country 
```
> Use this query to summarize for each user the countries that authenticated to the OfficeHome application and find uncommon or untrusted ones:  

```kusto
AADSignInEventsBeta 
| where Timestamp > ago(7d) 
| where ApplicationId == "4765445b-32c6-49b0-83e6-1d93765276ca" //OfficeHome application 
| where ClientAppUsed == "Browser" 
| where LogonType has "interactiveUser" 
| summarize Countries = make_set(Country) by AccountObjectId, AccountDisplayName 
```

> Use this query to find new email Inbox rules created during a suspicious sign-in session:

```kusto
//Find suspicious tokens tagged by AAD "Anomalous Token" alert
let suspiciousSessionIds = materialize(
AlertInfo
| where Timestamp > ago(7d)
| where Title == "Anomalous Token"
| join (AlertEvidence | where Timestamp > ago(7d) | where EntityType == "CloudLogonSession") on AlertId
| project sessionId = todynamic(AdditionalFields).SessionId);
//Find Inbox rules created during a session that used the anomalous token
let hasSuspiciousSessionIds = isnotempty(toscalar(suspiciousSessionIds));
CloudAppEvents
| where hasSuspiciousSessionIds
| where Timestamp > ago(21d)
| where ActionType == "New-InboxRule"
| where RawEventData.SessionId in (suspiciousSessionIds)
```


## Mitigation and prevention against AiTM 


### Protect Against AiTM Phishing

As MFA adoption grows, AiTM phishing (where attackers use advanced techniques) is expected to rise. Protecting against AiTM phishing is crucial.

### Key Protection Strategies:

- **Phish-resistant MFA solutions** (e.g., FIDO2, Certificate-based authentication)
- **Conditional Access** policies
- **Monitoring and alerts** through Microsoft 365 Defender and Azure AD Identity Protection

### Phish-Resistant MFA Solutions

Microsoft offers several primary authentication methods, with varying levels of protection against AiTM phishing:

| **Method**                            | **Protected Against AiTM** |
|---------------------------------------|----------------------------|
| FIDO2 security keys                   | ✅                          |
| Windows Hello for Business            | ✅                          |
| Certificate-based authentication      | ✅                          |
| Passwordless phone sign-in            | ❌                          |
| Phone number and SMS                  | ❌                          |
| Username and password                 | ❌                          |

*Only FIDO2, Windows Hello for Business, and Certificate-based authentication are protected against AiTM phishing by default. Username and password can be enhanced with Conditional Access for better protection.*

### Protected 2FA/MFA Methods
Not all 2FA/MFA methods offer protection against AiTM attacks. Here’s a breakdown:

| **Method**                                          | **Protected Against AiTM** |
|-----------------------------------------------------|----------------------------|
| SMS                                                 | ❌                          |
| Phone call                                          | ❌                          |
| Microsoft Authenticator App                         | ❌                          |
| Microsoft Authenticator + Number matching           | ❌                          |
| Microsoft Authenticator + Additional context        | ❌                          |
| Microsoft Authenticator + Number matching + context | ❌                          |

> ### Enable number matching
  To avoid that the victim only has to click “Verify” in the authenticator app, number matching requires the user to enter a   number displayed on the computer screen. This does not prevent the attack, but together with “additional context” it can     make the user guess twice before clicking through.
> Note: Number matching is the default when using Passwordless phone sign-in.

> ### Enable additional context in Microsoft Authenticator notifications
  Additional context adds a map of the rough location, based on the IP address of the client, to the notification in the       Microsoft Authenticator app. Combined with number matching this helps the user to identify poorly executed phishing          attacks. <br>
  
![PushNotifications](https://github.com/user-attachments/assets/a080e3e6-7bd0-4a96-a0dc-5ec7e415bb67)


> Note: *None of these methods alone provide AiTM protection; they must be combined with additional Conditional Access controls.*

### Conditional Access and Additional Controls

2FA/MFA alone doesn’t protect against AiTM; only when combined with Conditional Access do these methods offer protection:

| **Conditional Access Control**                    | **Protected Against AiTM** |
|---------------------------------------------------|----------------------------|
| Require device to be marked as compliant          | ✅                         |
| Require device to be Hybrid Azure AD joined       | ✅                         |
| Conditional Access Session Controls               | ❌                         |
| Conditional Access Trusted Locations              | ✅                         |
| Continuous Access Evaluation (CAE)                | ❌                         |
| Cross-tenant access                               | ✅                         |
| Conditional Access Session Controls               | ✅                         |

> *Conditional Access is key to protecting against AiTM.*

![image](https://github.com/user-attachments/assets/e4a71013-e604-4baf-bb07-ccb3e0aeff54)
> Sign-in is not possible when device compliance is required.

![TrustExternal](https://github.com/user-attachments/assets/c4fefd74-8751-4396-8f7b-cd1146348d38)
> Using the new “Cross-tenant access settings” you can extend this requirement to guest accounts from trusted companies. This feature allows you to trust the home tenant of the user to handle MFA and relay device compliance or hybrid Entra ID (Azure AD) joined device states to your tenant.

<img width="703" alt="conditional-access-policy-session-sign-in-frequency" src="https://github.com/user-attachments/assets/bfb6fbf0-8aff-45f3-a715-86dda5dfbd88">

> Setting the conditional access setting “Sign-in frequency” to a shorter time will not prevent the attack itself, but will limit the time window in which the attacker can use the phished session cookie. This session control should only be applied when accessing resources from unmanaged or shared devices. Otherwise, you risk too many Sign-In requests and angry users.

> NOTE: ***This setting will apply as soon as the conditional access policy is active and will invalidate all sessions from targeted users if they don’t match the defined time range. It does not only apply to new sessions***. 

> If you use “Persistent browser session” set to “Never persistent” the cookie is only valid for 24h hours and the browser will not store it after it’s closed.

![SessionPersistenceDisabled](https://github.com/user-attachments/assets/cc851dad-d8f2-4610-bc7b-0525f4f3cb25)
> You should apply this restriction to all administrative accounts.

> Note: ***This setting will not apply to already established sessions. You might want to consider revoking the sessions of all affected users to speed up the rollout.***

> Require MFA when registering security information or additional devices
> Important Note: *Sadly this conditional access policy does not add additional protection when using the “Require multi-factor authentication” grant control.*

![RequireMFA](https://github.com/user-attachments/assets/b7f1480a-659e-46eb-9788-742c1d0f1d46)

> When the initial sign-in was made with MFA the user will not be re-prompted for MFA again.

![RequireMFABypass](https://github.com/user-attachments/assets/6bbe1c6b-c820-41ea-88e8-530d353d6d50)

### Additional Protections

Some Microsoft security features do not directly protect against AiTM but offer other benefits:

| **Feature**                                 | **Protected Against AiTM** |
|---------------------------------------------|----------------------------|
| Custom Tenant branding                      | ❌                          |
| Azure AD Identity Protection                | ❌ (only alerting)          |
| Microsoft Defender for Endpoint             | ❌                          |
| Microsoft Defender for Cloud Apps           | ❌ (only alerting)          |
| Microsoft Defender for Office 365           | ❌ (only email removal)     |


### Revoking Sessions and MFA Registration

To mitigate damage after an attack:

- **Revoke sessions** via [portal.azure.com](https://portal.azure.com) to prevent attackers from using stolen cookies.
- **Check for new authentication methods** added by the attacker (e.g., FIDO2 keys) and reset passwords.

*Revoking sessions stop ongoing attacks but aren’t preventive. Always investigate further to ensure the attacker registers no new methods.*

![RevokeAllSessions](https://github.com/user-attachments/assets/84c7d37a-4429-42a4-850d-0858ed6074a2)

> The administrator can revoke all sessions with one click.

![image](https://github.com/user-attachments/assets/ea62f2cf-f481-450b-a250-a252b51d8a0b)

> The end user is requested to sign in again

![RevokeAllSessionsSignInLogs](https://github.com/user-attachments/assets/7b759475-a4e1-47ed-8a61-cb67d657ce02)


### Hunting possible illegitimate addition of a security method 
```kutso
let SecurityInfoRegistered = AuditLogs
| where OperationName == "User registered security info"
| extend UserPrincipalName = tostring(TargetResources[0].userPrincipalName)
| extend IPAddress = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, UserPrincipalName, OperationName, ResultDescription, IPAddress;
SigninLogs
| where ResultType == 0
| mv-expand todynamic(AuthenticationDetails)
| extend authenticationMethod = tostring(AuthenticationDetails.authenticationMethod)
| where authenticationMethod != "Previously satisfied"
| join kind=inner SecurityInfoRegistered on UserPrincipalName
| project-rename PossibleAttackerIPAddress = IPAddress1, SecurityInfoTimeGenerated = TimeGenerated1, SecurityInfoResultDescription = ResultDescription1, InitialLoginMethod = authenticationMethod
| extend TimeDifference = datetime_diff('second',TimeGenerated,SecurityInfoTimeGenerated)
| where TimeDifference < 0 and TimeDifference > -86400
| project TimeGenerated, TimeDifference, UserPrincipalName, OperationName, InitialLoginMethod, SecurityInfoResultDescription, IPAddress, PossibleAttackerIPAddress,  SecurityInfoTimeGenerated
| sort by TimeGenerated
```

### Hunting Administrators not using FIDO2 or WHfB
```kutso
let ConditionalAccessDisplayName = "Require MFA for administrators";
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where ResultType == 0
| mv-expand todynamic(AuthenticationDetails)
| extend authenticationMethod = tostring(AuthenticationDetails.authenticationMethod)
| where authenticationMethod !in ("FIDO2 security key","Previously satisfied","Windows Hello for Business")
| mv-expand ConditionalAccessPolicies_dynamic
| where ConditionalAccessPolicies_dynamic.displayName == ConditionalAccessDisplayName  and ConditionalAccessPolicies_dynamic.result != "notApplied"
```


# **Demo Introduction**:
![image](https://github.com/user-attachments/assets/d549fd01-fa46-463f-83dd-ab10047986f3)

## Attack Story
The attacker was able to compromise the organization by leveraging a phishing email, stealing authentication cookies, and then spreading the attack internally through phishing and malicious documents.

### Attack Timeline

| Time     | Event                                                                                   |
|----------|-----------------------------------------------------------------------------------------|
| T        | **Phishing email sent**<br>**Sender:** bob.egan@trey-research.com<br>**Subject:** Improve your security with Microsoft Defender for Cloud<br>**URL:** [http://xxx.companyportal.cloud/](http://xxx.companyportal.cloud/) |
| T+10     | The link in the email becomes malicious after passing through the MDO (Microsoft Defender for Office 365) sandbox. |
| T+15     | **Sonia Rogers** clicks on the link and authenticates with MFA (Multi-Factor Authentication).<br>**Role:** Cloud Architect<br>**Email:** sonia@xxx.m365dpoc.com |
| T+18     | Sonia's ESTSAUTH cookies are stolen by the attacker. |
| T+30     | The attacker logs in as Sonia using the stolen ESTSAUTH cookies, bypassing authentication and gaining access. |
| T+35     | The attacker creates an inbox forwarding rule in Darol's email account, forwarding emails to their own address. |
| T+38     | The attacker creates a new container in an Azure Storage account. |
| T+40     | The attacker uploads a malicious file to the container and generates a URL with a SAS (Shared Access Signature) key.<br>**File Name:** generateAccountPlan.doc |
| T+45     | The attacker, posing as Sonia, sends an internal phishing email with a link to the file in the Azure container.<br>**Sender:** sonia@xxx.m365dpoc.com<br>**Subject:** Account Plan Automation<br>**URL:** [link to the malicious file in the Azure storage account] |
| T+65     | **Kelly Gibson** clicks on the link, downloads the file, and executes the payload.<br>**Role:** Account Strategist<br>**Email:** kelly@xxx.m365dpoc.com |
| T+70     | Malicious activities begin. The attacker gains further access or control after the payload is executed. |





# Resources
■ [Detecting and mitigating a multi-stage AiTM phishing and BEC campaign](https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/?msockid=19dba958fccb6dd6182dbd54fd836cb6)<br>
■ [Configure automatic attack disruption capabilities in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption?view=o365-worldwide)<br>
■ [Automatically disrupt adversary-in-the-middle (AiTM) attacks with XDR](https://techcommunity.microsoft.com/t5/microsoft-defender-xdr-blog/automatically-disrupt-adversary-in-the-middle-aitm-attacks-with/ba-p/3821751)<br>
■ [From cookie theft to BEC: Attackers use AiTM phishing sites as an entry point to further financial fraud](https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/) <br>
■ [Identifying Adversary-in-the-Middle (AiTM) Phishing Attacks through 3rd-Party Network Detection](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/identifying-adversary-in-the-middle-aitm-phishing-attacks/ba-p/3991358)<br>
■ [DEV-1101 enables high-volume AiTM campaigns with open-source phishing kit](https://www.microsoft.com/en-us/security/blog/2023/03/13/dev-1101-enables-high-volume-aitm-campaigns-with-open-source-phishing-kit/)<br>
■ [Alert grading for session cookie theft alert](https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert?view=o365-worldwide) <br>
■ [Cross-tenant access with Microsoft Entra External ID](https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview?WT.mc_id=AZ-MVP-5004810) <br>
■ [How number matching works in multifactor authentication ](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match?WT.mc_id=AZ-MVP-5004810) <br>
■ [How to use additional context in Microsoft Authenticatorn](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-additional-context?WT.mc_id=AZ-MVP-5004810) <br>
■ [Conditional Access: Target resources](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps) <br>
■ [Common Conditional Access policy: Require MFA for administrators](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa?WT.mc_id=AZ-MVP-5004810) <br>


