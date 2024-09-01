# Day 6: How to prevent token theft and AiTM using Microsoft Defender
In my last post, I elaborately described the vast information related to AiTM and how advanced these attacks have become. These incredibly sophisticated tactics included building fraudulent sites that captured users' login credentials, allowing attackers to take over sign-in sessions and bypass authentication protections—even with Multifactor Authentication (MFA) enabled.

Today, I'm going to shed more light on how you can detect and mitigate these kinds of attacks using Microsoft Defender. Related blogs used for this research are marked down below the page under the resource section, so feel free to check them out.


## Detecting AiTM:
Automated tools used by adversaries: <br>
■ [Evilginx2](https://github.com/kgretzky/evilginx2)<br>
■ [Modlishka](https://github.com/drk1wi/Modlishka)<br>
■ [Muraena](https://github.com/muraenateam/muraena)<br>


### Overview

Some strategies for detecting token theft with Microsoft Defender and Microsoft Entra include monitoring for specific Indicators of Compromise (IOCs), such as impossible travel alerts. 

Detecting token theft can be challenging. However, certain indicators, such as impossible travel alerts, can help. In Entra ID, reviewing sign-in logs can reveal anomalies, although high volumes of log data can make this task difficult. Filtering and analyzing the sign-in logs effectively is key.

**Example:** If a user based in the US successfully signs in from a location in Europe, this could indicate a compromise. Key factors to consider are:
- **Successful login**
- **Location of the attempt**
- **Interval of these attempts**

### Entra-ID Protection and Defender for Cloud Apps

Entra-ID Protection (with P2 capabilities) and Defender for Cloud Apps are configured to raise alerts for specific events by default. These integrations are enabled automatically, so no additional configuration is required if you're using these services. For third-party applications, however, you may need to configure alert settings separately.

### Defender for Endpoints on Windows 10 and 11

Defender for Endpoints detects suspicious access to Primary Refresh Tokens (PRTs) and associated artifacts.

### Defender XDR Detection and Entra-ID Protection Integration

Defender XDR detection and Entra-ID Protection are integrated by default. The automatic attack disruption feature in Microsoft's XDR requires no pre-configuration by the SOC team. The following detections are enabled for automatic attack disruptions:

- User compromised via a known AiTM phishing kit
- User compromised in an AiTM phishing attack
- Stolen session cookie used
- Possible AiTM phishing attempt in Okta


**Demo Introduction**:
![image](https://github.com/user-attachments/assets/4798c256-d28f-427c-be35-b5258cd40568)
<br>
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

















---
Cooking ***

# Resources
■ [Detecting and mitigating a multi-stage AiTM phishing and BEC campaign](https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/?msockid=19dba958fccb6dd6182dbd54fd836cb6)<br>
■ [Configure automatic attack disruption capabilities in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption?view=o365-worldwide)<br>
■ [Automatically disrupt adversary-in-the-middle (AiTM) attacks with XDR](https://techcommunity.microsoft.com/t5/microsoft-defender-xdr-blog/automatically-disrupt-adversary-in-the-middle-aitm-attacks-with/ba-p/3821751)<br>
■ [From cookie theft to BEC: Attackers use AiTM phishing sites as an entry point to further financial fraud](https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/) <br>
■ [Identifying Adversary-in-the-Middle (AiTM) Phishing Attacks through 3rd-Party Network Detection](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/identifying-adversary-in-the-middle-aitm-phishing-attacks/ba-p/3991358)<br>
■ [DEV-1101 enables high-volume AiTM campaigns with open-source phishing kit](https://www.microsoft.com/en-us/security/blog/2023/03/13/dev-1101-enables-high-volume-aitm-campaigns-with-open-source-phishing-kit/)<br>
■ [Alert grading for session cookie theft alert](https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert?view=o365-worldwide) <br>

