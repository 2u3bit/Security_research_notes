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


## Enforce restrictions on critical resources (managed devices)
| **Security Measure**                        | **Description**                                                                                   |
|---------------------------------------------|---------------------------------------------------------------------------------------------------|
| **Access to critical applications**         | Restrict access to critical applications to devices that are recognized and managed by the organization. This ensures that only secure, approved devices can connect. |
| **Utilize compliance tools**                | Implement tools such as Mobile Device Management (MDM) and enforce device-based conditional or contextual access policies to manage and monitor device compliance. |
| **Require compliant devices**               | Enforce the use of devices that meet the organization's security standards as an additional access control, ensuring that only compliant devices can access critical resources. |
| **Keep devices patched and up-to-date**     | Regularly update devices with the latest security patches to protect against vulnerabilities and ensure they meet compliance standards. |
| **Use phishing-resistant MFA solutions**    | Implement multi-factor authentication (MFA) solutions that are resistant (WfH, FIDO) to phishing attempts, enhancing the security of the authentication process. |

> While passwordless authentication effectively mitigates the risk of credential theft, it doesn't fully address the threat of token theft. However, it does offer a significant security improvement. In a phishing scenario, if a user is targeted but doesn't know their password—because they are using passwordless authentication—the attacker can't easily proceed. This reduces the likelihood of the phishing attempt succeeding, as the user can't provide a password that they don't have. Therefore, while it doesn't eliminate all risks, passwordless authentication is a valuable step toward strengthening security and minimizing potential damage. 

## Enforce restrictions on critical resources (unmanaged devices)

| **Recommendation**                          | **Action**                                                                                                                 |
|---------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| **Reduce the lifetime of the session**      | Shorten the duration of user sessions to minimize the window of opportunity for token exploitation.                        |
| **Implement Conditional Access App Control**| Configure Microsoft Defender for Cloud Apps to restrict access from unmanaged devices, mitigating the risk of unauthorized access through compromised devices. |


>It's great to have managed devices with Windows 11, and Entra ID joined and protected by conditional access policies. However, there will always be cases where users access resources from unmanaged devices. In such situations, one effective measure is to use conditional access policies to reduce the session lifetime. By default, a primary refresh token can remain valid for a long period, which can be risky if passwords are not frequently rotated. However, frequent password rotation is no longer recommended by NIST and has been adopted by Microsoft. The focus should instead be on transitioning to a passwordless environment using phishing-resistant MFA solutions, which offer stronger security and reduce the reliance on passwords.

## Showcasing the session lifetime configuration using conditional access 
![msedge_ogll4pDuo5](https://github.com/user-attachments/assets/1bbcfe5c-155b-425a-80c0-f1b3c8f5c48d)

![image](https://github.com/user-attachments/assets/b7b0c7b5-3931-46a3-abc9-3c01b0df30c9)

> One idea to configure the policy. So devices that meet this criteria will be excluded from this policy.

# Entra Token Protection (Preview) (aka Token Binding)

**What is Entra Token Protection?**

Entra Token Protection, also known as token binding, establishes a cryptographic link between a token and the device it is issued to, providing enhanced security.

**How does it work?**

When a user registers a Windows 10 or newer device with Microsoft Entra ID, their primary identity is linked to the device. Upon signing in to an application using Microsoft Entra ID credentials, a sign-in session token (or refresh token) is issued. Entra Token Protection ensures that only tokens bound to the device, known as Primary Refresh Tokens (PRTs), can be used by applications to access resources.

**Benefits of Entra Token Protection**

Entra Token Protection offers enhanced security by preventing the use of stolen or compromised tokens. It also reduces the risk of credential theft by restricting the use of compromised tokens, thereby limiting potential damage. Additionally, it helps organizations improve compliance by providing a stronger layer of protection for user identities.

### **Entra Token Protection** supports the following devices and applications:

- **Devices:**
  - Windows 10 or newer devices that are Microsoft Entra joined
  - Microsoft Entra Hybrid joined
  - Microsoft Entra registered

- **Applications:**
  - **OneDrive Sync Client:** Version 22.217 or later
  - **Teams Native Client:** Version 1.6.00.1331 or later
  - **Visual Studio 2022 (May 2023 or later):** When using the "Windows Authentication Broker" sign-in option

### Entra Token Protection Current Limitations

**Entra Token Protection** has the following limitations:

- **External Users:** Microsoft Entra B2B users are not supported and should not be included in your conditional access policies.

- **Unsupported Applications:** The following applications do not support signing in using protected token flows and users will be blocked when accessing Exchange and SharePoint:
  - PowerShell modules accessing Exchange, SharePoint, or Microsoft Graph scopes served by Exchange or SharePoint.
  - Power Query extension for Excel.
  - Extensions to Visual Studio Code that access Exchange or SharePoint.
  - The new Teams 2.1 preview client, which is blocked after signing out due to a bug. This issue has been fixed in recent service updates.

- **Unsupported Windows Client Devices:** The following Windows client devices are not supported:
  - Windows Server
  - Surface Hub
  - Windows-based Microsoft Teams Rooms (MTR) systems

- **License Requirements:** Token protection is a feature of Entra ID Protection and requires Entra ID P2 licenses at general availability.
 
### Protect Privileged Accounts

- Use distinct identities for users with privileged accounts to minimize the attack surface from on-premises environments.
- Privileged accounts should not have mailboxes attached to them.
-  Adopt the use of Secure Access Workstations for accessing administrative portals.
-  Implement Just-In-Time (JIT) access and adhere to the principle of least privilege to enhance security.


# Resources

■ [What's in a Downgrade?](https://arxiv.org/abs/1809.05681)<br>
■ [Token tactics: How to prevent, detect, and respond to cloud token theft](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/) <br>
■ [Token tactics: How to prevent, detect, and respond to cloud token theft](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/) <br>
