# Day 5: Adversary-in-the-Middle
## Overview:
Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as ***Network Sniffing***, ***Transmitted Data Manipulation***, or ***replay attacks (Exploitation for Credential Access)***. By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary-controlled system so they can collect information or perform additional actions.

![image](https://github.com/user-attachments/assets/e5dcd483-3394-4088-91f0-758da1a8e9ab)

### What is Network Sniffing? 
Network sniffing involves an adversary passively monitoring network traffic to capture sensitive information like authentication details. By placing a network interface in promiscuous mode or using span ports, attackers can access data in transit, potentially capturing unencrypted credentials. Techniques like name service resolution poisoning such as [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/) can further redirect traffic to the adversary, compromising websites, proxies, and internal systems.

Network sniffing can also reveal critical configuration details such as running services, version numbers, IP addresses, and hostnames, which can aid in lateral movement and defense evasion. In cloud environments, adversaries might exploit traffic mirroring services like AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap to capture network traffic from virtual machines. This traffic is often unencrypted due to TLS termination at load balancers, allowing adversaries to exfiltrate the captured data for further exploitation.

### Transmitted Data Manipulation?
Adversaries may alter data during transmission to manipulate outcomes or conceal their activities, threatening data integrity. By intercepting and modifying data, they can influence business processes, organizational understanding, and decision-making. Such manipulation can occur over network connections or between system processes, depending on the adversary's objectives and the transmission mechanism.

For more complex systems, adversaries likely require specialized knowledge and software, often obtained through extensive information gathering, to effectively achieve their goals.

### Exploitation for Credential Access? 
Adversaries may exploit software vulnerabilities to gain access to credentials. This involves taking advantage of programming errors in applications, services, or operating systems to execute malicious code. By targeting credentialing and authentication mechanisms, adversaries can obtain valuable credentials or bypass authentication processes to access systems.

Examples include exploiting vulnerabilities like MS14-068 to forge Kerberos tickets or conducting replay attacks to impersonate users by replaying intercepted data packets. In cloud environments, vulnerabilities can be exploited to create or renew authentication tokens unintentionally. Such exploitation can also lead to privilege escalation if the obtained credentials allow higher-level access.

## Attack detail:
| ID | ATT&CK Reference| Sub-techniques | Tactic | 
| :------------- | ------------- | ------------- | ------------- |
| T1557  | [Adversary-in-the-Middle](https://attack.mitre.org/versions/v15/techniques/T1557/)|  [T1557.001](https://attack.mitre.org/versions/v15/techniques/T1557/001/) <br> [T1557.002](https://attack.mitre.org/versions/v15/techniques/T1557/002/) <br> [T1557.003](https://attack.mitre.org/versions/v15/techniques/T1557/003/) | [Credential Access](https://attack.mitre.org/versions/v15/tactics/TA0006/) <br> [Collection](https://attack.mitre.org/versions/v15/tactics/TA0009/) |

--- 




