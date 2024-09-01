# Day 6: How to prevent token theft and AiTM using Microsoft Defender
In my last post, I elaborately described the vast information related to AiTM and how advanced these attacks have become. These incredibly sophisticated tactics included building fraudulent sites that captured users' login credentials, allowing attackers to take over sign-in sessions and bypass authentication protections—even with Multifactor Authentication (MFA) enabled.

Today, I'm going to shed more light on how you can detect and mitigate these kinds of attacks using Microsoft Defender. Related blogs used for this research are marked down below the page under the resource section, so feel free to check them out.


## Detecting AiTM:
Automated tools of the adversaries: <br>
■ [Evilginx2](https://github.com/kgretzky/evilginx2)<br>
■ [Modlishka](https://github.com/drk1wi/Modlishka)<br>
■ [Muraena](https://github.com/muraenateam/muraena)<br>

### Overview:
Some strategies for detecting token theft with Microsoft Defender and Microsoft Entra. 

> Token reply will trigger specefiec IOCs such as impossible travel alerts. 

In genral token theft is difficult to detect but there are certian indicator of compermise that will be triggerd such as impossble travel alerts, so whitin the Entra id just by take a look at the sign-in logs, of course an enviroment has a lot of high volume and it could be difficult, but there are ways to filter that and look through the sing-in logs. 

Example: Imagine a user is succesfuly sign-in from location in the europ but they are us-based and they are not in the europ, so this is a clear indicator of compromise. Key-note here is the **succesfull loggin** and **location of the attemp** and **interval of these attemps**.

> Entra-ID protection and Defender for Cloud Apps are tuned to raise alerts:
Entra-ID protection (P2-capabilities) and Defender for Cloud apps are tuned to raise alerts whit these type pof events, by default are these capabilities and integration turned on so you dont ineed to do anything extra if you are using Entra-ID protection and Defender for cloud apps but if you have third-party apps you might need to be looking those type of alerts. 

> Defender for endpoints on windows 10 and 11 detects suspicious access to PRT(primary refresh token) and associated artifacts

> Defender XDR detection and Enra-ID Protection are integerated by defualt 
The automatic attack disruption feature in Microsoft's XDR does not necessitate pre-configuration by the SOC team, it is inherently integrated. The following detections are enabled for automatic attack disruptions:

- User compromised via a known AiTM phishing kit
- User compromised in an AiTM phishing attack
- Stolen session cookie used
- Possible AiTM phishing attempt in Okta

**Demo**:























# Resources
■ [Detecting and mitigating a multi-stage AiTM phishing and BEC campaign](https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/?msockid=19dba958fccb6dd6182dbd54fd836cb6)<br>
■ [Configure automatic attack disruption capabilities in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption?view=o365-worldwide)<br>
■ [Automatically disrupt adversary-in-the-middle (AiTM) attacks with XDR](https://techcommunity.microsoft.com/t5/microsoft-defender-xdr-blog/automatically-disrupt-adversary-in-the-middle-aitm-attacks-with/ba-p/3821751)<br>
■ [From cookie theft to BEC: Attackers use AiTM phishing sites as an entry point to further financial fraud](https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/) <br>
■ [Identifying Adversary-in-the-Middle (AiTM) Phishing Attacks through 3rd-Party Network Detection](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/identifying-adversary-in-the-middle-aitm-phishing-attacks/ba-p/3991358)<br>
■ [DEV-1101 enables high-volume AiTM campaigns with open-source phishing kit](https://www.microsoft.com/en-us/security/blog/2023/03/13/dev-1101-enables-high-volume-aitm-campaigns-with-open-source-phishing-kit/)<br>
■ [Alert grading for session cookie theft alert](https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert?view=o365-worldwide) <br>

