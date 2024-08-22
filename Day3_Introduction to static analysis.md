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

### Table 3.2 Tools Used for Static Analysis of Malware

### Table 3.2 Tools Used for Static Analysis of Malware

| Tool’s Name                                                                  | Functionality of the Tools                                                                                     |
|------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| [Exeinfo PE](http://www.exeinfo.xn.pl/)                                      | Retrieves information from Windows PE headers. The file signature also determines if the executable has been packed and indicates how to unpack it. |
| [HashMyFiles](https://www.nirsoft.net/utils/hash_my_files.html) / [HashCalc](https://www.slavasoft.com/hashcalc/index.htm) | Generates various hashes such as MD5, SHA-1, SHA-256, RIPEMD 560, CRC32, TIGER, SHA-256, PANAMA, etc. |
| [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)  | PowerShell or CMD strings can extract all strings in ASCII and UNICODE.                                       |
| [UPX](https://upx.github.io/)                                                | UPX tool can pack and unpack an EXE file using CFF Explorer or PEstudio. One can identify if the malware is packed with UPX or not. |
| [Pestudio](https://www.winitor.com/)                                         | Provides a comprehensive amount of information extraction tools, file type, arch, PE headers, strings, hashes. |
| [DIE (Detect It Easy)](https://github.com/horsicq/Detect-It-Easy)            | Detect It Easy is a packer identifier that helps in defining file types.                                       |
| [Resource Hacker](http://www.angusj.com/resourcehacker/)                     | Functions as a resource compiler and decompiler, allowing viewing and modifying of resources in executables and compiled resource libraries. |
| [Wireshark](https://www.wireshark.org/)                                      | Enables detailed packet examination of numerous protocols at various layers.                                   |
| [PEiD](https://www.aldeid.com/wiki/PEiD)                                     | An application used to find malware that is packed or encrypted.                                               |
| [PEview](https://wjradburn.com/software/)                                    | Provides details on Portable Executable (PE) file headers and their sections.                                  |
| [PE Explorer](https://www.heaventools.com/overview.htm)                      | Displays the PE's content and organizational structure. It can also be used as a file unpacker for packed files. |
| [CFF Explorer](https://ntcore.com/?page_id=388)                              | Developed to make PE editing as simple as possible while maintaining awareness of the internal organization of the portable executable. |
| [Yara Rules](https://virustotal.github.io/yara/)                             | Records malware issue categories based only on patterns.                                                       |
| [Dependency Walker](http://www.dependencywalker.com/)                        | Detects missing files, invalid files, mismatched CPU types of modules, and circular dependency errors.         |
| [HxD Hex Editor](https://mh-nexus.de/en/hxd/)                                | Designed to display both the ASCII interpretation and the file's raw hexadecimal format.                       |
| [BinText](https://www.mcafee.com/enterprise/en-us/downloads/free-tools/bintext.html) | A tool that can search through and display character strings in a binary file.                                 |


---

## References: 
■ [Best Practices for Using Static Analysis Tools](https://www.parasoft.com/blog/best-practices-for-using-static-analysis-tools/)
<br>
■ [A Static Approach for Malware Analysis: A Guide to Analysis Tools and Techniques](https://www.researchgate.net/publication/377011413_A_Static_Approach_for_Malware_Analysis_A_Guide_to_Analysis_Tools_and_Techniques)
<br>
■ [PeStudio Overview: Setup, Tutorial and Tips](https://www.varonis.com/blog/pestudio)
<br>
