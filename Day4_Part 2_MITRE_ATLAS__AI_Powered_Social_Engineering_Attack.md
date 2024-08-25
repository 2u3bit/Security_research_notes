# Day 4: AI_Powered Social Engineering Attack
Imagine receiving a phone or video call from your CEO, urgently instructing you to transfer funds to a new account to finalize a crucial business deal. Everything appears entirely genuine, from the voice and mannerisms to the background. In reality, this is not your CEO but a highly sophisticated deepfake created by cyber criminals using artificial intelligence. This scenario exemplifies a rising threat in cybersecurity: AI-driven social engineering attacks.

These attacks leverage artificial intelligence to enhance traditional social engineering techniques, making them more effective and harder to identify. AI enables cybercriminals to create highly realistic and personalized deceptions, blurring the distinction between legitimate and fraudulent communications.

While traditional social engineering relies on exploiting human psychology by imitating trusted figures or organizations, AI introduces unprecedented realism. Advances in machine learning and deep learning allow for the creation of convincing fake content, such as deepfake videos and voice imitations, which significantly heightens the effectiveness of these attacks.

## Attack detail:

| ID | ATT&CK Reference| Sub-techniques | Tactic | 
| :------------- | ------------- | ------------- | ------------- |
| AML.T0052  |[Phishing](https://attack.mitre.org/versions/v15/techniques/T1566/)  | [Spearphishing via Social Engineering LLM](https://atlas.mitre.org/techniques/AML.T0052.000)| [Initial Access](https://attack.mitre.org/versions/v15/tactics/TA0001/) |

--- 

## Top phishing trends
- Phishing attacks surged by 58.2% in 2023 compared to the previous year, reflecting the growing sophistication and reach of threat actors.

- Voice phishing (vishing) and deepfake phishing attacks are on the rise as attackers harness generative AI tools to amplify their social engineering tactics.

- Adversary-in-the-middle (AiTM) phishing attacks persist and browser-in-the-browser (BiTB) attacks are emerging as a growing threat

## Top phishing targets

The US, UK, India, Canada, and Germany were the top five countries targeted by phishing attacks.

> ![image](https://github.com/user-attachments/assets/493d21e5-745f-4ea5-b617-e614e084816d)

## Spotlight on AI-Enabled Phishing Threats

**GenAI** has significantly boosted productivity across various industries, but it also brings a serious downside: it empowers even novice cybercriminals to become skilled social engineers and sophisticated phishing attackers.

By automating and customizing different stages of the attack process, AI enhances phishing tactics, making them faster, more refined, and increasingly difficult to detect.

GenAI can rapidly analyze publicly available data, including information about organizations and their leadership, reducing the time required for reconnaissance and enabling highly targeted attacks. **LLM chatbots** create precise and convincing phishing messages, eliminating the usual telltale signs like spelling and grammar errors. Additionally, GenAI can quickly generate realistic phishing websites. 

AI has blurred the boundaries between genuine and fraudulent content, making it even harder to distinguish between legitimate communications and phishing schemes.

### Mitigating Phishing Risks with Zero Trust

In response to the growing threat landscape, organizations must adapt their security strategies to defend against the latest phishing tactics. One highly effective approach is to establish a foundation based on **Zero Trust Architecture**. This method has proven successful in addressing both traditional and AI-enhanced phishing attacks.

The following insights and strategies are recommended for mitigating these risks:

| **Mitigation Strategy**                                       | **Description**                                                                                                                                                                  |
|---------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Fighting AI with AI**                                        | Utilize AI-powered phishing prevention tools that are specifically designed to counter AI-driven threats. This includes features like browser isolation to prevent phishing page exploitation. |
| **Zero Trust Architecture Advantages**                        | Implement a Zero Trust Architecture to safeguard against phishing at various stages of the attack chain.                                                                         |
| **Prevent Compromise**                                       | Employ TLS/SSL inspection at scale, AI-powered browser isolation, and policy-driven access controls to block access to suspicious websites.                                      |
| **Eliminate Lateral Movement**                               | Ensure users connect directly to applications instead of the network and use AI-driven app segmentation to minimize the impact of any potential security breaches.               |
| **Shut Down Compromised Users and Insider Threats**          | Leverage inline inspection to prevent exploitation of private applications and deploy integrated deception capabilities to detect even the most sophisticated attackers.          |
| **Stop Data Loss**                                           | Conduct a thorough inspection of data in motion and at rest to prevent theft by active attackers.                                                                                  |
| **Foundational Security Best Practices**                      | Adopt fundamental security practices to strengthen overall resilience against phishing attacks.                                                                                 |
---
# Resources

■ [Deepfakes Rank as the Second Most Common Cybersecurity Incident for US Businesses](https://www.darkreading.com/cyberattacks-data-breaches/deepfakes-rank-as-the-second-most-common-cybersecurity-incident-for-us-businesses)<br>
■ [Learning a URL Representation with Deep Learning for Malicious URL Detection](https://arxiv.org/abs/1802.03162)

