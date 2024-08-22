# Static Analysis: 
**Overview**: <br>
Static analysis involves examining malware without executing it. This method focuses on extracting useful information directly from the malware file, which helps in forming an initial understanding of the malware's type and potential capabilities. The insights gained from static analysis are invaluable for guiding further, more detailed analysis.


**Objective**: <br>
The primary goal is to gather preliminary information that gives us an idea of the type of malware and its potential functions. This information is crucial for streamlining future analysis, making the process more efficient and targeted.

<br>

# Static analysis flow

**Identifying the File Type**:<br>
- Determine the target operating system (OS), architecture (e.g., x86, x64), and format (e.g., .dll, .exe) of the malware. This helps in understanding the environment in which the malware operates.

**Identifying the Malware**: <br>
- Generate a hash of the malware (e.g., MD5, SHA-256) to create a unique identifier. This hash can be used to check if the malware has been previously analyzed, which can provide additional context or insights.

**Strings Analysis**:<br>
- Extract and analyze strings within the malware file. Strings can provide a glimpse into the malware's functionality, such as potential commands, URLs, file paths, or error messages.
**Packing & Obfuscation Detection**: <br>
- Identify if the malware uses packing or obfuscation techniques, which are methods to conceal its true nature and evade detection. If packing or obfuscation is detected, attempt to unpack or deobfuscate the malware to reveal hidden information.

**PE Headers Analysis**: <br>
- Examine the Portable Executable (PE) headers, which contain metadata about the file. This information can reveal a lot about the malware's capabilities, such as entry points, imported libraries, and resources.

# Analysis tools 
When conducting static analysis, there are several tools and techniques an analyst should consider. These tools assist in extracting valuable information from malware, helping analysts understand its structure and potential functionality.

**Static Analysis Techniques**: <br>

| **Static Analysis**       | **Comment**                                                                                   |
| ------------------------- | -------------------------------------------------------------------------------------------------- |
| **File Type**             | Determine the file format by checking its magic number. For instance, "MZ" indicates a .exe file. |
| **Packers**               | Identify if the file uses packing techniques like UPX or MEW. These methods hide the true nature of the file. |
| **Timestamps**            | Examine the file's timestamps to find out when it was compiled or modified.                      |
| **Hash Value**            | Compute MD5, SHA1, or SHA256 hashes to uniquely identify the file. These hashes are useful for tracking and comparing malware samples. |
| **DLLs (Libraries)**      | Review the DLLs and their functions to understand the features and operations the malware may perform. |
| **Function (Imports/Exports)** | Investigate imported and exported functions to gain insights into the malware's potential actions and interactions. |
| **Strings**               | Extract and analyze embedded strings to uncover clues such as IP addresses, URLs, file paths, and function names. |


**Toolkits**: <br>

Here are some essential tools for conducting static malware analysis:

| **Toolkit**       | **Comment**                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------------------- |
| **[VirusTotal](https://www.virustotal.com/gui/home/upload)** | Online tool to scan files and URLs with multiple antivirus engines. Useful for initial detection and analysis. |
| **[PEstudio](https://www.varonis.com/blog/pestudio)**      | A tool for analyzing PE files. It provides detailed information about PE headers, imports/exports, and other critical metadata. |
| **[HxD](https://mh-nexus.de/en/downloads.php?product=HxD20)** | A powerful hex editor for examining the raw contents of binary files. |
| **[Floss](https://github.com/mandiant/flare-floss/releases)** | A tool from Mandiant for extracting obfuscated strings from malware. Useful for revealing hidden strings. |
| **[MalAPI.io](https://malapi.io/)** | An online resource for exploring Windows API functions. Useful for understanding the capabilities of the malware. |






# References: 

■ [Best Practices for Using Static Analysis Tools](https://www.parasoft.com/blog/best-practices-for-using-static-analysis-tools/)
<br>
■ [Best Practices for Using Static Analysis Tools](https://www.parasoft.com/blog/best-practices-for-using-static-analysis-tools/)
<br>