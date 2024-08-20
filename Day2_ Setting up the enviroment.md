# Day 2: Setting up the environment
**Tools we will be using**:
- Hypervisor - VirtualBox or VMware
- Windows 10/11 VM 64-bit preferable.
- FLARE VM - Windows malware analysis distribution >>  Comes prepackaged with all the tools we need for malware analysis.


> Note: Ensure you disable Windows Update and Windows Defender on your analysis VM.


**Security consideration**:

- Keep your Hypervisor updated.
- When executing malware ensure your network configuration is set to host-only.
- Do not plug any USB devices into the VM.
- Make sure you download compressed and password-protected samples to avoid accidental execution. 
- Take snapshots!
- Do not store any valuable data on your analysis VM.
- Disable shared folders, before execution or analysis.



**Windows 11 development environment**:

- Download the Windows 11 development environment VM from Microsoft
- Unzip the file and double-click on the .ova file
- Customize to preferable appliance setting (Disk-size, etc)
> Note: default is sufficient
- Create a host-only adaptor (you will need it after the FLARE-VM installation)
- Download the FLARE-VM on Win 11
> Note: Take the snapshot of your VM and then install the FLARE-VM 

> Note: Disable Windows firewall | services.msc > Search for windows update service and Windows Defender and disable these services so that it doesn't interfere with the FLARE-VM installation.

- Unzip the file and use the installation guide to install the FLARE-VM machine.
- After installation connect the machine to the host-only adaptor.

# Analysis tools on FLARE-VM

| Toolkit | Memo |
| :------------- | ------------- |
| Utilities      | PEstuido, PEid, CFF Explorer, ProccesHacker, ProcDOT, Wireshark
| Debuggers      | OnlyDbg, x64Dbg
| Pentest        | Cachedump, VNCviewer, exe2bat


# References: 

■ [Windows 11 development environment](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)
<br>
■ [Download FLARE-VM from the official Repository](https://github.com/mandiant/flare-vm)
<br>
■ [Flare-VM installation guide](https://cloud.google.com/blog/topics/threat-intelligence/flare-vm-update/)
