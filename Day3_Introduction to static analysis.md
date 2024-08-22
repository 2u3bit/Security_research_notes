# Static Analysis: 
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

## Toolkits
Here are some essential tools for conducting static malware analysis:

| **Toolkit**       | **Comment**                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------------------- |
| **[VirusTotal](https://www.virustotal.com/gui/home/upload)** | Online tool to scan files and URLs with multiple antivirus engines. Useful for initial detection and analysis. |
| **[PEstudio](https://www.varonis.com/blog/pestudio)**      | A tool for analyzing PE files. It provides detailed information about PE headers, imports/exports, and other critical metadata. |
| **[HxD](https://mh-nexus.de/en/downloads.php?product=HxD20)** | A powerful hex editor for examining the raw contents of binary files. |
| **[Floss](https://github.com/mandiant/flare-floss/releases)** | A tool from Mandiant for extracting obfuscated strings from malware. Useful for revealing hidden strings. |
| **[MalAPI.io](https://malapi.io/)** | An online resource for exploring Windows API functions. Useful for understanding the capabilities of the malware. |

---

## References: 
■ [Best Practices for Using Static Analysis Tools](https://www.parasoft.com/blog/best-practices-for-using-static-analysis-tools/)
<br>
■ [A Static Approach for Malware Analysis: A Guide to Analysis Tools and Techniques](https://www.researchgate.net/publication/377011413_A_Static_Approach_for_Malware_Analysis_A_Guide_to_Analysis_Tools_and_Techniques)
<br>
