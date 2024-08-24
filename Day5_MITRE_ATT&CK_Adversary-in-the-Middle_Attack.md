# Day 5: Adversary-in-the-Middle attack
## Overview:
Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as ***Network Sniffing***, ***Transmitted Data Manipulation***, or ***replay attacks (Exploitation for Credential Access)***. By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary-controlled system so they can collect information or perform additional actions.

## Attack detail:
| ID | ATT&CK Reference| Sub-techniques | Tactic | 
| :------------- | ------------- | ------------- | ------------- |
| T1557  | [Adversary-in-the-Middle](https://attack.mitre.org/versions/v15/techniques/T1557/)|  [T1557.001](https://attack.mitre.org/versions/v15/techniques/T1557/001/) <br> [T1557.002](https://attack.mitre.org/versions/v15/techniques/T1557/002/) <br> [T1557.003](https://attack.mitre.org/versions/v15/techniques/T1557/003/) | [Credential Access](https://attack.mitre.org/versions/v15/tactics/TA0006/) <br> [Collection](https://attack.mitre.org/versions/v15/tactics/TA0009/) |

## Identity is the security control plane 
As organizations increasingly adopt cloud SaaS apps and single sign-on, modern authentication protocols like OAuth and SAML have become essential. These protocols rely on tokens with claims to grant access to resources. Protecting these tokens is crucial to ensure they don't fall into the wrong hands, as they effectively serve as credentials in the digital environment. 


When an identity provider like Entra ID issues a token, it includes details such as the username, user title, and group memberships. In a typical flow, a user opens a browser and navigates to an application. They sign in through their identity provider, which then issues the token. The user is redirected back to the application with this valid token, and if the application accepts it, access is granted. If the user holds a privileged role, such as a global administrator, the token will reflect their elevated status, granting them the appropriate level of access.

![image](https://github.com/user-attachments/assets/7dc9777e-11a5-426e-9301-0a26aef1e761)

> Tokens are central to OAuth 2.0 identity platforms.  


## What is token theft? 
In a traditional credential theft scenario, an attacker sends a phishing email to a user, who then clicks the link and enters their username and password on a fake but convincing website. This compromises their credentials. However, if the organization had multi-factor authentication (MFA) in place, the attacker would be blocked from gaining access, as MFA would prevent unauthorized access even if the credentials were compromised.

![image](https://github.com/user-attachments/assets/6205aca5-967c-4e0e-aae8-c308e1a2fa71)

In an Adversary-in-the-Middle phishing attack, an attacker sends a phishing email to a user and places malicious infrastructure between the user and the legitimate site. This infrastructure mimics a Microsoft login page to capture credentials. Tools like OTP and EvilginX2 can be used in this attack to steal both credentials and tokens. Once the attacker obtains the token, they can replay it. If MFA is used, the attacker captures the MFA response as well, allowing them to complete the authentication process and gain access.

![image](https://github.com/user-attachments/assets/6be67ef5-2012-4305-b7d1-867de23e7dba)

In a pass-the-cookie attack, similar to a pass-the-hash attack, an attacker uses infrastructure like a reverse proxy to intercept and steal session cookies. This typically involves installing malware on the user's personal device, which may be used to access both personal and corporate resources. For instance, if a user is logged into Gmail and also accessing corporate applications through Entra ID, the attacker can capture the session cookie from the browser. This stolen cookie can then be exploited to gain unauthorized access to corporate resources.

Such attacks are challenging to detect, especially since they often occur on personal devices that may not be joined to or registered with Entra ID. This lack of integration makes  security policies and prevention measures less effective, requiring alternative mitigation strategies to address these types of threats.

![image](https://github.com/user-attachments/assets/32580058-0745-4ec0-ba40-4568a355c0ba)



