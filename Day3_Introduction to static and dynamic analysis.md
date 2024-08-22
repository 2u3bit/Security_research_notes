# Static Analysis of Malware: 
**Overview**: <br>
Static analysis involves examining malware without executing it. This method focuses on extracting useful information directly from the malware file, which helps in forming an initial understanding of the malware's type and potential capabilities. The insights gained from static analysis are invaluable for guiding further, more detailed analysis.

**Objective**: <br>
The primary goal is to gather preliminary information that gives us an idea of the type of malware and its potential functions. This information is crucial for streamlining future analysis, making the process more efficient and targeted.<br>

## Steps Involved in Static Malware Analysis

Static malware analysis involves several steps aimed at understanding the characteristics and behavior of malware without executing it. Below are the key steps in this process:

**a) Obtain a Malware Sample**: This can be done through various methods, such as downloading it from a website, accessing a public repository, or extracting it from an infected machine.

**b) File Analysis**: This step involves examining the file’s attributes, including its type, size, creation date, and other metadata to gather preliminary information about the malware.

**c) Disassembly**: Disassembling the binary code reveals the underlying machine code and assembly language instructions. This process helps to uncover the malware's capabilities and behavior.

**d) Strings Extraction**: Extract readable strings from the binary code to identify crucial information such as file paths, network addresses, and API calls. These strings can provide insights into the malware’s operations.

**e) Signature Analysis** Compare the program’s code against known malware signatures. This can help identify the malware’s family and predict its behavior based on existing knowledge.

**f) Decompilation**: Convert the machine code back into a higher-level programming language like Python or C. This step aids in understanding the malware’s functionality and code structure.

**g) Reverse Engineering**: This involves a deeper analysis of the malware’s code to determine its payload, potential harmful behavior, and overall functionality. Reverse engineering can reveal the actions the malware is designed to perform.<br>

These steps form a comprehensive approach to static malware analysis, allowing analysts to extract as much information as possible without executing the malware. This method is crucial for understanding the virus’s potential impact and preparing defenses against it.

## Static analysis flow

**Identifying the File Type**:<br>
- Determine the target operating system (OS), architecture (e.g., x86, x64), and format (e.g., .dll, .exe) of the malware. This helps in understanding the environment in which the malware operates.

**Identifying the Malware**: <br>
- Generate a hash of the malware (e.g., MD5, SHA-256) to create a unique identifier. This hash can be used to check if the malware has been previously analyzed, which can provide additional context or insights.

**Strings Analysis**:<br>
- Extract and analyze strings within the malware file. Strings can provide a glimpse into the malware's functionality, such as potential commands, URLs, file paths, or error messages.

**Packing & Obfuscation Detection**: <br>
- Identify if the malware uses packing or obfuscation techniques, which are methods to conceal its true nature and evade detection. If packing or obfuscation is detected, attempt to unpack or deobfuscate the malware to reveal hidden information.

**PE Headers Analysis**: <br>
- Examine the Portable Executable (PE) headers containing metadata about the file. This information can reveal a lot about the malware's capabilities, such as entry points, imported libraries, and resources.

### Sections of a PE File

The following are the most typical and important sections of a PE file:

| **Sr. No.** | **Executable** | **Function**                                                                                                 |
|-------------|----------------|-------------------------------------------------------------------------------------------------------------|
| 1           | **.text**       | This is where the executable code is stored.                                                                |
| 2           | **.rdata**      | This section contains globally accessible read-only data.                                                   |
| 3           | **.data**       | Stores global information accessed by the software.                                                         |
| 4           | **.rsrc**       | This section comprises the resources that the executable needs.                                             |
| 5           | **.idata**      | Stores information about import functions and, if not found in this section, will be found in the `.rdata` section. |
| 6           | **.reloc**      | Gathers data for the relocation of library files.                                                           |
| 7           | **.edata**      | Stores information about export functions and, if not found in this section, will be found in the `.rdata` section. |

---

If an analyst determines through static analysis that the executable will launch a process, and if the following `exec` and `sleep` commands are discovered, but no information regarding the corresponding DLL—which includes a function to connect with another server—is found, the executable and the resource are both hidden. To learn more about the malware, use a program like Resource Hacker to open the `—src` part of the PE file.


<br>

![Static-malware-analysis-workflow_W640](https://github.com/user-attachments/assets/67b36b7c-4252-4be3-b13f-e7884d5b9d37)
>  Content was uploaded by Aaron Zimba on Research Gate.


## Static Analysis Techniques


| **Static Analysis**       | **Comment**                                                                                   |
| ------------------------- | -------------------------------------------------------------------------------------------------- |
| **File Type**             | Determine the file format by checking its magic number. For instance, "MZ" indicates a .exe file. |
| **Packers**               | Identify if the file uses packing techniques like UPX or MEW. These methods hide the true nature of the file. |
| **Timestamps**            | Examine the file's timestamps to find out when it was compiled or modified.                      |
| **Hash Value**            | Compute MD5, SHA1, or SHA256 hashes to uniquely identify the file. These hashes are useful for tracking and comparing malware samples. |
| **DLLs (Libraries)**      | Review the DLLs and their functions to understand the features and operations the malware may perform. |
| **Function (Imports/Exports)** | Investigate imported and exported functions to gain insights into the malware's potential actions and interactions. |
| **Strings**               | Extract and analyze embedded strings to uncover clues such as IP addresses, URLs, file paths, and function names. |

---

# Dynamic Analysis of Malware
Dynamic malware analysis is a pivotal technique in modern cybersecurity. Unlike static analysis, which examines the content of files and programs for potentially malicious content, dynamic analysis involves executing the potentially malicious code in a controlled environment. This allows security analysts to observe and understand the malware’s behavior in real-time, providing deeper insights into threats that static analysis might miss.

Dynamic analysis provides valuable insights into the behavior of the malware and its impact on the system, which can be used to develop defenses. By combining static and dynamic analysis, researchers can gain a comprehensive understanding of the malware's behavior and its potential impact.

## How dynamic malware analysis works
After a suspicious file is flagged and the threat is sequestered in a sandbox, the code is detonated and dynamic malware analysis begins. Dynamic malware analysis uses a behavior-based approach to understand potential threats, so making observations and logging any actions the program makes both inside and outside the sandbox environment is essential.

Malware detonated in a sandbox environment is kept safely away from mission-critical storage and systems, while also remaining active in the analysis system environment. This is important because the program can run its course in the analysis environment, allowing analysts to gain as much information as possible about the purpose and actions of the malware.

Some of the information that dynamic malware analysis can reveal include:

- File system changes
- Registry changes
- Application security changes
- Network settigns changes
- Firewall changes
- Writes to memory
- Process creation / termination / injection
- SSDT, IDT, IRP hooks
- Executed API instructions
- Network connections
- Detection evasion attempts

Context, intent and behaviors are all features unique to different types of malware. Seeing the program execute its functions in real time helps teams understand the kind of threats they are up against and how they can protect their systems from similar attacks.

## Benefits of Dynamic Malware Analysis
Dynamic malware analysis offers threat hunters deeper visibility into potential malware threats than static analysis alone. Static analysis is good for discovering known code injections, but fails to provide insights into more sophisticated malware threats. Dynamic analysis helps teams uncover the true nature of threats and can be automated for speedy discovery.

A recent report states that 62% of organizations have understaffed cybersecurity teams, putting a strain on incident responders and investigators. With less staff, there is more pressure to act quickly when it comes to understanding and patching new threats. However, this often leads to costly mistakes and a more superficial understanding of system vulnerabilities.

Here are some of the benefits of using dynamic malware analysis to uncover malware threats:

- Identifies threats in a secure environment
- Automated tools can be programmed to scan for specific events and behaviors
- Analyze applications without access to code
- Identify false negatives left by static analysis
- Validates static analysis reports
- Detects known and unknown threats
- Detects persistent malware threats
- Aids in the understanding of program capabilities
- Identifies malware intent
- Helps teams understand unique TTPs of attackers
- Identifies both IOCs and IoAs
- Avoid future breaches and security incidents

## Challenges and Limitation
Dynamic malware analysis is an extremely helpful tool for SOC analysts, threat hunters and security teams, but there are a few challenges and limitations to understand before deploying a dynamic malware analysis tool.

Threat actors are typically very tech-savvy. They know what sandboxes are and they sometimes detect a sandbox environment within a target system. Armed with this knowledge, adversaries can work to deceive the sandbox technology by planting code inside that remains dormant until certain conditions are met. They can then mess with reports, further infect the system, and carry out advanced attacks.

Some examples of advanced attacks that may overcome dynamic analysis include:

- Context-aware malware
- Malware that detects sandboxes
- Malware that exploits sandboxes
- Delayed-attack malware
- Dynamic malware analysis is still recommended over static analysis since it 

results in a higher detection rate for sophisticated malware threats. However, teams must consider that some threat actors have developed programs meant to overcome dynamic analysis methods.
As you can see, sandboxing is not a foolproof solution to malware threats. Knowing when and how to use a sandbox under certain conditions is crucial to the effectiveness of dynamic malware analysis. Be sure to scan files individually to avoid contamination, and create processes to avoid security bottlenecks.

## Toolkits
Here are some essential tools for conducting static malware analysis:

## Toolkits for Static Malware Analysis

Here are some essential tools for conducting static malware analysis:

| Tool’s Name                                                                     | Functionality of the Tools                                                                                         |
|---------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| [Exeinfo PE](http://www.exeinfo.xn.pl/)                                         | Retrieves information from Windows PE headers. Determines if the executable is packed and indicates how to unpack it. |
| [HashMyFiles](https://www.nirsoft.net/utils/hash_my_files.html) / [HashCalc](https://www.slavasoft.com/hashcalc/index.htm) | Generates various hashes such as MD5, SHA-1, SHA-256, RIPEMD, CRC32, TIGER, PANAMA, etc.                           |
| [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)     | Extracts all strings in ASCII and UNICODE from PowerShell or CMD.                                                   |
| [UPX](https://upx.github.io/)                                                   | Packs and unpacks EXE files. Helps identify if the malware is packed with UPX.                                      |
| [Pestudio](https://www.winitor.com/)                                            | Provides comprehensive information extraction tools, including file type, PE headers, strings, and hashes.          |
| [DIE (Detect It Easy)](https://github.com/horsicq/Detect-It-Easy)               | Identifies packers and defines file types.                                                                         |
| [Resource Hacker](http://www.angusj.com/resourcehacker/)                        | Resource compiler and decompiler, allowing viewing and modification of resources in executables and compiled libraries. |
| [Wireshark](https://www.wireshark.org/)                                         | Detailed packet examination of numerous protocols at various layers.                                                 |
| [PEiD](https://www.aldeid.com/wiki/PEiD)                                        | Finds malware that is packed or encrypted.                                                                         |
| [PEview](https://wjradburn.com/software/)                                       | Provides details on Portable Executable (PE) file headers and sections.                                              |
| [PE Explorer](https://www.heaventools.com/overview.htm)                         | Displays PE content and structure. Can also be used as a file unpacker for packed files.                            |
| [CFF Explorer](https://ntcore.com/?page_id=388)                                 | Simplifies PE editing while maintaining awareness of the portable executable's internal organization.              |
| [Yara Rules](https://virustotal.github.io/yara/)                                | Records malware issue categories based on patterns.                                                                 |
| [Dependency Walker](http://www.dependencywalker.com/)                           | Detects missing files, invalid files, mismatched CPU types of modules, and circular dependency errors.              |
| [HxD Hex Editor](https://mh-nexus.de/en/hxd/)                                   | Displays both ASCII interpretation and the file's raw hexadecimal format.                                           |
| [BinText](https://www.mcafee.com/enterprise/en-us/downloads/free-tools/bintext.html) | Searches and displays character strings in a binary file.                                                           |
| [IDA - The Interactive Disassembler](https://hex-rays.com/products/ida/support/idadoc/index.shtml) | Disassembles machine-executable code into assembly language source code. Supports various executable formats.       |
| [x32dbg & x64dbg](https://x64dbg.com/)                                          | Open-source binary debuggers for Windows, aimed at malware analysis and reverse engineering of executables.         |
| [ProcDot](https://github.com/mwrlabs/ProcDot)                                  | Generates visual representations of process and API call relationships.                                              |
| [ProcMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)     | Monitors and logs system activity including file system, registry, and process/thread activity.                     |
| [Ghidra](https://ghidra-sre.org/)                                               | Software reverse engineering suite developed by NSA, used for analyzing executable files.                           |
| [APIMonitor](https://www.rohitab.com/apimonitor)                                | Monitors API calls made by a process.                                                                               |
| [Regshot](https://sourceforge.net/projects/regshot/)                            | Takes snapshots of the Windows registry and compares them to detect changes.                                        |

---

## References: 
■ [Best Practices for Using Static Analysis Tools](https://www.parasoft.com/blog/best-practices-for-using-static-analysis-tools/)
<br>
■ [A Static Approach for Malware Analysis: A Guide to Analysis Tools and Techniques](https://www.researchgate.net/publication/377011413_A_Static_Approach_for_Malware_Analysis_A_Guide_to_Analysis_Tools_and_Techniques)
<br>
■ [How You Can Start Learning Malware Analysis | SANS Institute!](https://www.sans.org/blog/how-you-can-start-learning-malware-analysis/)
