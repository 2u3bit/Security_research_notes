# Day 2: Setting up the environment
**Tools we will be using**:
- Hypervisor - VirtualBox or VMware
- Windows 10/11 VM 64-bit preferable.
- FLARE VM - Windows malware analysis distribution >>  Comes prepackaged with all the tools we need for malware analysis.


> Note: Ensure you disable Windows Update and Windows Defender on your analysis VM.


**Security considiration**:

- Keep your Hypervisor updated.
- When executing malware ensure your network configuration is set to host-only.
- Do not plug any USB devices in to the VM.
- Make sure you download compressed and password protected samples to avoid accidental execution. 
- Take snapshots!
- Do not store any valuable data on your analysis VM.
- Disable shared folders, before execution or analysis.



**Windows 11 development environment**:

- Download Windows 11 development environment VM from microsoft
- Unzip the file and double clink on .ova file
- Customize to preferable applicance setting (Disk-size etc)
> Note: default is sufficient
- Creat a host-only adaptor. you will need it after FLARE-VM isntallation.
- Download the FLARE-VM on win 11
> Note: Take the snapshot of you VM and then install the FLARE-VM 

> Note: Disbale Windows firewall | services.msc > search for windows update service and windows defender and disaable these servcices so that it does'nt interfere with the FLARE-VM installation.

- Unzip the file and use the installation guide to install the FLARE-VM machine.
- After installation connect the machine to the host-only adaptor.

# Analysis-tools on FLARE-VM

| Toolkit | Memo |
| :------------- | ------------- |
| Utilities      | PEstuido, PEid, CFF Explorer, ProccesHacker, ProcDOT, Wireshark
| Debuggers      | OnlyDbg, x64Dbg
| Pentest        | Cachedump, vncviewer, exe2bat


# References: 

■ [How You Can Start Learning Malware Analysis | SANS Institute!](https://www.sans.org/blog/how-you-can-start-learning-malware-analysis/)
<br>
■ [Practical Malware Analysis Essentials for Incident Responders](https://www.youtube.com/watch?v=20xYpxe8mBg&feature=emb_title)
<br>
■ [Windows 11 development environment](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)
<br>
■ [Download FLARE-VM from this repository](https://github.com/mandiant/flare-vm)
<br>
■ [Flare-VM installation guide](https://cloud.google.com/blog/topics/threat-intelligence/flare-vm-update/)