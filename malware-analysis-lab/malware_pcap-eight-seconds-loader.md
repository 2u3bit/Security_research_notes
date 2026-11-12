# Day 15 — Eight Seconds

A Windows workstation downloads an executable with curl. Eight seconds later it opens a single connection to a server in Germany, keeps it open for 37 minutes and receives almost 13 MB through it. This writeup follows that infection from the packet capture down to the code that made it happen. The network side is analysed in Security Onion, and the file side in FLARE-VM with DIE, FLOSS, capa and Ghidra.

## The exercise

The traffic comes from the malware-traffic-analysis.net exercise of 1 October 2026, called Natureforce. These exercises give you a pcap of a real infection and a short SOC scenario, and ask you to answer a set of questions the way you would for an incident report.

The scenario is that you work in a SOC and two alerts come in. One is a Windows executable sent from an IP address over an unusual TCP port. The other is command and control traffic from a remote access trojan. You pull the pcap for the Windows host involved and verify what happened.

![Exercise background with the two SOC alerts](https://github.com/user-attachments/assets/b4b970dd-886a-4759-95a6-cfe4533839cf)

The environment in the pcap looks like this.

| Item | Value |
|---|---|
| LAN segment | 10.10.1.0/24 |
| Domain | natureforce.com |
| Domain controller | 10.10.1.10, WIN-LEKBU2OY51N |
| Gateway | 10.10.1.1 |

The questions to answer.

1. What is the IP address of the infected Windows client?
2. What is its MAC address?
3. What is its hostname?
4. What is the user account name?
5. What is the SHA256 hash of the EXE sent from 107.175.82[.]242 on port 9000?

All analysis was done in an isolated lab. The sample never touched the host machine.

## Tools and approach

| Tool | Used for |
|---|---|
| Security Onion | Replaying the pcap through Suricata (alerts) and Zeek, called Bro in this version (connection, DNS, HTTP, TLS, DHCP, Kerberos and file logs), searched through Kibana |
| tcpdump and capinfos | Checking the raw pcap directly, independent of Kibana |
| FLARE-VM | Windows analysis machine for the sample |
| Detect It Easy (DIE) | File type, compiler, packer and entropy per section |
| FLOSS | Strings, including strings that malware builds or decodes at runtime |
| capa | Mapping code features to capabilities and MITRE ATT&CK |
| Ghidra | Disassembling and decompiling the loader |

The workflow was simple. Answer the questions from the network logs first, get the EXE out of the traffic, prove with hashes that the file in FLARE is the exact file from the pcap, and then find out what that file does.

## Part 1 — Network analysis

### Importing the pcap

Before importing, I recorded size and hash of the pcap so the evidence is fixed.

```
2026-10-01-traffic-analysis-exercise.pcap
36838132 bytes
sha256 287d6dee90cfef71f98a97c42e30444608de2cf59d2f7392a0a6df8dbbc8274b
```

Security Onion ships a script that replays a pcap through all its sensors.

```bash
sudo so-import-pcap ~/Downloads/2026-10-01-traffic-analysis-exercise.pcap
```

![so-import-pcap finished](https://github.com/user-attachments/assets/653f3f18-f5d8-46e3-886e-eb2d36ceb7a0)

The import keeps the original timestamps. Kibana has to be set to 1 October 2026, with the default time range of the last 24 hours nothing shows up.

### Suricata alerts

![NIDS alert summary](https://github.com/user-attachments/assets/54674651-f185-4c4f-99e5-0209e77cec3e)

| Alert | Source | Destination | Count |
|---|---|---|---|
| ET INFO Packed Executable Download | 107.175.82[.]242 | 10.10.1.128 | 13 |
| ET POLICY PE EXE or DLL Windows file download HTTP | 107.175.82[.]242 | 10.10.1.128 | 13 |
| ET POLICY curl User-Agent Outbound | 10.10.1.128 | 35.170.55[.]9 | 2 |
| ET POLICY curl User-Agent Outbound | 10.10.1.128 | 107.175.82[.]242 | 1 |
| ET INFO Executable Download from dotted-quad Host | 10.10.1.128 | 107.175.82[.]242 | 1 |
| ET POLICY DNS Update From External net | 10.10.1.128 | 10.10.1.10 | 1 |

Every alert involves 10.10.1.128, which makes it the obvious candidate for the infected client. Three details are worth a closer look.

**13 alerts, one download.** Zeek later logs a single HTTP request for the EXE. Suricata fires per matching packet or stream segment, Zeek logs per request. When counting events, the two numbers mean different things.

**curl on a Windows desktop.** Regular users don't use curl. Seeing its user agent from a workstation means a command or script was running, and it went to the EXE server and to a second address, 35.170.55[.]9.

**"DNS Update From External net".** This one fires on traffic from the client to its own domain controller, inside the same subnet. HOME_NET on this sensor includes 10.0.0.0/8, so the client is internal. The cause is EXTERNAL_NET.

![EXTERNAL_NET set to any](https://github.com/user-attachments/assets/1eb0fad0-b6ba-4e27-b2a7-2d847f17cd1a)

EXTERNAL_NET is set to `any` instead of the usual `!$HOME_NET`. Every source counts as external, so a normal dynamic DNS update from a domain member triggers the rule. This is a sensor configuration false positive and has nothing to do with the infection.

### The infected host

10.10.1.128 is the only client making DNS queries in the capture, 172 of them. Zeek's DHCP log shows the lease it received, including hostname and MAC address.

![Zeek DHCP record for DESKTOP-4VGYQX7](https://github.com/user-attachments/assets/0636f628-0349-4fbd-91d0-c4170b719ed2)

The Kerberos log shows which account authenticated from that host against the domain controller.

![Zeek Kerberos record for bdiaz](https://github.com/user-attachments/assets/abe973bd-bf51-4309-b28b-81e76a0baa67)

That answers the first four questions.

| | |
|---|---|
| IP | 10.10.1.128 |
| MAC | `00:22:fb:ec:7e:e7` |
| Hostname | DESKTOP-4VGYQX7 |
| User | bdiaz |

### The download

Filtering the HTTP logs on 107.175.82[.]242 shows exactly one request, made with `curl/8.21.0`.

![HTTP URI /wilow/runner_ilove.exe](https://github.com/user-attachments/assets/95516e2c-6320-4693-9419-dd0523886697)

The file is `/wilow/runner_ilove.exe`, served over plain HTTP on port 9000 from a bare IP address.

### Suspicious domains

Most of the 172 DNS queries are normal Windows and browser traffic, such as Microsoft telemetry, Google services and Active Directory lookups for natureforce.com. Three names stand out, and the DNS answers link them to IP addresses.

![DNS answers for the three suspicious domains](https://github.com/user-attachments/assets/8d04c46d-3c9f-4451-9c5d-1be139bbe386)

| Domain | IP | Seen in |
|---|---|---|
| holtandberyl[.]com | 35.170.55[.]9 | HTTP and TLS, and the curl alert |
| sorrelapse[.]best | 44.203.10[.]190 | TLS |
| www.ars-soar[.]com | 54.201.5[.]185 | TLS |

holtandberyl.com is the address curl contacted before it downloaded the EXE. The role of the other two is not visible from TLS metadata alone.

### The EXE hash

Zeek in Security Onion automatically extracts executables it sees in HTTP traffic to `/nsm/bro/extracted`. The folder contains older files from previous lab work and one file created at the moment of the import.

![Files extracted by Zeek](https://github.com/user-attachments/assets/3e9b0ea5-50ea-4da0-82ff-6c05d0554ca0)

Hashing a file only reads it, so this is safe on the Linux sensor.

```
HTTP-FqoKp1UqzbsaLVtka.exe   1646592 bytes
sha256 b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061
```

`FqoKp1UqzbsaLVtka` is Zeek's file ID, which ties the extracted file to its entry in the files log. That answers the fifth question.

### Finding the C2 server

The scenario names `195.64.128[.]106` on port 443 as the C2 server. A search in Kibana returned nothing. To rule out a problem in the Security Onion pipeline, I checked the raw pcap with tcpdump.

![tcpdump finds zero packets for 195.64.128.106](https://github.com/user-attachments/assets/51bbbb1f-b1bb-47ad-9551-21402447b6ee)

Zero packets. The same command for the EXE server worked right away, so the filter wasn't the problem. The next possibility was that the capture ended before the malware called home.

![capinfos first and last packet time](https://github.com/user-attachments/assets/ccb02c1d-fc88-4e11-bb68-3b036a1546e8)

The capture runs from 19.27 until 20.07, more than half an hour past the download, so that wasn't it either. The next step was listing every outbound connection attempt (TCP SYN) and counting destinations.

```bash
tcpdump -nr 2026*.pcap 'tcp[13]==2 and not dst net 10.0.0.0/8' > syn.txt
awk '{print $5}' syn.txt | sort | uniq -c | sort -rn
```

The capture has 70 unique outbound destinations, nearly all Google, Microsoft and CDN addresses. Further down the list, with a single connection, is the real C2 server.

![Outbound SYN list with 195.63.128.106](https://github.com/user-attachments/assets/e0885faa-8d3c-4947-b124-1f14e5c7784e)

The traffic goes to `195.63.128.106`. The exercise page lists `195.64.128.106`. The two differ by one digit, and only 195.63 exists in the capture. The lesson is to verify an indicator against the data, for example with a partial match, before hunting for it.

Timestamps of the outbound connections to the suspicious addresses give the order of events.

![SYN timestamps for the suspicious IPs](https://github.com/user-attachments/assets/b0e550cc-73dc-4d79-9838-859a8a31c00d)

### The C2 connection

With the correct address, Kibana shows one Zeek connection record.

![C2 connection record, state and duration](https://github.com/user-attachments/assets/ae77abec-82aa-4f4a-aaf9-cae640e674cf)

![C2 connection record, bytes and packets](https://github.com/user-attachments/assets/658c3711-ef7e-4f9d-bcc7-fbd108397372)

| Field | Value |
|---|---|
| Start | `19:30:44.328` |
| Duration | 2233.6 seconds, about 37 minutes |
| conn_state | S1, established and not closed |
| Packets | 5,398 out and 10,197 in, 15,595 in total |
| Bytes | 81.7 KB out, 12.76 MB in |
| history | ShADadtttTTT |
| service | not present |

**Eight seconds.** The connection starts eight seconds after the EXE download finished. The download used source port 63723 and the C2 connection uses 63725, so almost nothing else happened on the host in between.

**One long session.** There is one connection, still open when the capture ends. This is not a beacon that reconnects on a timer, it's a persistent session.

**No protocol on port 443.** Zeek fills the `service` field when it recognises a protocol, such as `ssl` for TLS. For this connection the field is absent. That is why the C2 server never appeared in the TLS logs. The malware uses port 443 to blend in, but doesn't speak HTTPS. Traffic on 443 that Zeek can't identify as TLS is a useful detection signal.

**Data flows inward.** The client sent 81.7 KB and received 12.76 MB, 156 times more in than out. Remote access tools usually send more than they receive, because they upload screenshots and stolen data. This pattern suggests the server delivered additional code or modules to the client. What exactly can't be seen without decrypting the session.

**Retransmissions.** In the history field, lowercase letters are the responder and uppercase the originator, and a repeated letter marks another order of magnitude. `tttTTT` means hundreds of retransmissions in both directions. The cause is unclear.

GeoIP places the server in Germany, but the GeoIP database on this Security Onion version is several years old.

### Timeline

```
19:27:27  DHCP lease, DESKTOP-4VGYQX7 gets 10.10.1.128 (user bdiaz)
19:28:30  TLS to www.ars-soar[.]com      54.201.5[.]185
19:28:31  TLS to sorrelapse[.]best       44.203.10[.]190
19:29:00  curl to holtandberyl[.]com     35.170.55[.]9     port 80 and 443
19:30:36  curl downloads runner_ilove.exe from 107.175.82[.]242:9000
19:30:44  single connection to 195.63.128[.]106:443, no recognised protocol
20:07:58  capture ends, connection still open, 12.76 MB received
```

The visits to ars-soar.com and sorrelapse.best come half a minute before the first curl command. Whether they are the lure that got the user to run a command, or unrelated browsing, can't be determined from TLS metadata.

## Part 2 — File analysis

### Verifying the sample

The EXE was exported from the pcap inside FLARE-VM with Wireshark (File, Export Objects, HTTP) and saved with a `.bin` extension so it can't be started by accident.

![Same SHA256 in FLARE](https://github.com/user-attachments/assets/08a0a172-3668-4874-aaf1-43bc580f5199)

The SHA256 matches the hash from Security Onion. The pcap, Zeek and FLARE all point to the same 1,646,592 bytes.

### File structure

DIE identifies the file as a 64-bit Windows executable with the GUI subsystem, which means no console window appears when it runs. It detects no known packer. The entropy per section tells more.

Entropy measures how random the data is, on a scale from 0 to 8. Normal code and text sit around 5 to 6.5. Compressed or encrypted data comes close to 8.

![DIE section entropy](https://github.com/user-attachments/assets/1e115eb8-4f31-48f3-8fbf-37c6df85b42d)

| Section | Size in bytes | Entropy |
|---|---|---|
| .text (code) | 44,544 | 6.60 |
| .rdata (read-only data) | 1,596,928 | 5.80 |
| other sections | a few KB | low |

The total entropy of 5.83 means the file is not packed, which contradicts Suricata's "Packed Executable" alert. The proportions are the real finding. 97 percent of the file is read-only data, while the actual program code is only 44 KB. A normal program doesn't carry 1.6 MB of constant data. This points to a loader with an embedded payload.

### Capabilities

![capa results](https://github.com/user-attachments/assets/80d9640d-505c-4327-8704-ecb8a3f0f3ac)

```
md5   cb50fe432a302b85845bc7ea98742c11
sha1  425efc5636affb32f4a72f73b5b80c26c54b15bc
```

capa finds thread creation, file writing, process termination and PE parsing. It finds nothing related to networking.

### Strings

FLOSS extracts 31,002 strings. At first, `VirtualProtect failed with code 0x%x` looked like part of the malware's own memory handling. The strings around it show where it really comes from.

![FLOSS strings from the MinGW runtime](https://github.com/user-attachments/assets/8b6d6670-1c11-45f9-921f-1d7f3ea9d83c)

`Mingw-w64 runtime failure` and the pseudo relocation messages belong to the MinGW-w64 C runtime, which adjusts memory protection of its own image at startup. They are part of every MinGW-built program, not code written by the author. capa's PE parsing matches most likely come from the same runtime. A MinGW toolchain with the LLVM linker would also explain why DIE reports "Microsoft Linker 14.0" and why the file has an unusual `.buildid` section.

The version information is more telling.

![Version info claiming Canonical Diagnostics Service](https://github.com/user-attachments/assets/05811344-4316-4b1b-b73b-d50bab19540a)

| Field | Value |
|---|---|
| CompanyName | Canonical Ltd. |
| FileDescription | Diagnostics Service |
| OriginalFilename | service.exe |
| FileVersion | 14.38.16928.6639 |

Canonical publishes Ubuntu. A Windows "Diagnostics Service" from Canonical, compiled with MinGW, is fake metadata meant to look legitimate, a form of masquerading (MITRE ATT&CK T1036).

FLOSS found no stack strings, tight strings or decoded strings, so the code itself hides no text.

### What is in .rdata

Three checks narrow down what the 1.6 MB block is.

**Is it another executable?** Every Windows program contains the text "This program cannot be run in DOS mode" and a PE signature. Both appear only once in the file, belonging to the loader itself. There is no second plain executable inside.

**Is it encoded text?** All 256 possible byte values appear in the block. Hex or Base64 text would use only 16 or 64. It's binary data.

**What does it look like?** A hexdump from the middle of the block answers it.

![Hexdump of the blob at offset 800000](https://github.com/user-attachments/assets/f7ddcf6b-120f-4a1e-bb04-c72c570da10a)

```
48 89 4C 24 08     mov [rsp+8], rcx      start of a function
48 83 EC 38        sub rsp, 38h
48 8B 44 24 40     mov rax, [rsp+40h]
E8 xx xx xx xx     call ...
48 83 C4 38        add rsp, 38h
C3                 ret                   end of a function
CC CC CC           int3 padding
```

This is plain, unencrypted x64 machine code. It consists of many small functions padded with `CC` bytes, a pattern typical of Microsoft's compiler. The loader is built with MinGW and the payload with Microsoft's compiler. Two separate pieces were combined into one file.

The loader's imports show how little it does itself. Besides runtime functions, it only uses `VirtualAlloc`, `VirtualProtect`, `CreateThread`, `WaitForSingleObject` and `Sleep`. There is no networking library, no `LoadLibrary` and no `GetProcAddress`, and the payload contains no readable DLL or API names at all. Yet the host connected to the C2 server eight seconds after the download.

This is the signature of shellcode with API hashing. Instead of importing functions by name, the code walks the list of DLLs already loaded in the process, computes a hash for each exported function name and compares it against stored values. The names never appear in the file, so string tools and import analysis see nothing.

### Decompiling the loader

Ghidra decompiles the loader's main function at address 140001000.

![Ghidra decompiled loader](https://github.com/user-attachments/assets/e13e19f1-2d9a-4534-825c-678c640e9e3f)

Cleaned up, the logic is this.

```c
buf = VirtualAlloc(NULL, 0x182156, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (buf) {
    memcpy(buf, &DAT_14000c1e8, 0x182156);                  // copy 1,581,398 bytes, no decoding
    if (VirtualProtect(buf, 0x182156, PAGE_EXECUTE_READ, &old)) {
        h = CreateThread(NULL, 0, buf, NULL, 0, &tid);      // execute from the first byte
        if (h) WaitForSingleObject(h, INFINITE);
    }
}
return 0;
```

The function also walks through the environment variables before this, but never uses the result.

**No decryption.** The payload is copied byte for byte. This explains the normal entropy and the readable machine code in the hexdump. The only thing hidden is the API names, and the shellcode takes care of that itself.

**RW then RX.** Memory is allocated as read-write, filled, and then switched to read-execute. The loader never requests memory that is writable and executable at the same time (RWX), which many security products look for specifically.

**Execution starts at byte 0.** The thread begins at the first byte of the copied block, so the shellcode's entry point is at its very start.

**The process stays alive.** `WaitForSingleObject` with INFINITE makes the loader wait for as long as the shellcode thread runs. This matches the network side, a single connection that was still open 37 minutes later.

The TLS callbacks in the file were checked as well. They contain the standard MinGW runtime initialisation and no anti-debugging code.

The memory map shows why the loader is built this way.

![Ghidra memory map](https://github.com/user-attachments/assets/0ce073e0-8d67-473d-9a0f-1dcb40677040)

Only the `.text` section is executable. The shellcode sits in `.rdata`, which is read-only, so it can't run in place. It has to be copied to new memory and made executable first.

```
.rdata   virtual address 14000c000, size 0x185e00, read only
payload  virtual address 14000c1e8 (.rdata + 0x1e8)
         file offset 46056, length 0x182156 (1,581,398 bytes)
```

## How the pieces fit together

1. The user visits two websites and half a minute later a curl command runs on the workstation. curl contacts holtandberyl.com.
2. curl downloads `runner_ilove.exe` over plain HTTP on port 9000 from 107.175.82[.]242.
3. The file poses as a "Diagnostics Service" from Canonical. It is a small MinGW loader carrying 1.58 MB of unencrypted x64 shellcode.
4. The loader copies the shellcode to new memory, makes it executable and starts it in a new thread.
5. The shellcode resolves its own Windows APIs through hashing and, eight seconds after the download, connects to 195.63.128.106 on port 443 with a protocol that isn't TLS.
6. Over that single connection it receives 12.76 MB, which stays open until the end of the capture.

## Answers

| Question | Answer |
|---|---|
| IP address of the infected client | 10.10.1.128 |
| MAC address | `00:22:fb:ec:7e:e7` |
| Hostname | DESKTOP-4VGYQX7 |
| User account | bdiaz |
| SHA256 of the EXE | b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061 |

## Detection opportunities

Based on what this infection actually showed.

- **curl user agent from a Windows workstation**, especially when followed by an EXE download.
- **Executable downloads from a bare IP address on a non-standard port**, here HTTP on 9000.
- **Port 443 without TLS.** A Zeek connection on 443 with no `service` value.
- **Long-lived sessions with heavy inbound traffic** shortly after a new executable appears on a host.
- **Memory behaviour on the endpoint.** A process allocating a large region, switching it from RW to RX and starting a thread in memory that isn't backed by a file on disk.
- **Version information that doesn't fit**, such as a Canonical-branded Windows service.

And one tuning note. With EXTERNAL_NET set to `any`, the "DNS Update From External net" rule fires on normal Active Directory behaviour.

## Open questions

- What triggered the curl command, and what the two TLS sites had to do with it.
- What the 12.76 MB received from the C2 server contained.
- Why there are so many retransmissions on the C2 connection.
- Why the exercise lists 195.64.128.106 while the traffic goes to 195.63.128.106.

The next step is analysing the shellcode itself. That means carving it out at file offset 46056, loading it into Ghidra as raw x64 code and looking for the API hashing routine and the C2 configuration.

## Indicators

```
10.10.1.128       DESKTOP-4VGYQX7   00:22:fb:ec:7e:e7   bdiaz

holtandberyl[.]com      35.170.55[.]9
sorrelapse[.]best       44.203.10[.]190
www.ars-soar[.]com      54.201.5[.]185
hxxp://107.175.82[.]242:9000/wilow/runner_ilove.exe
195.63.128[.]106:443    C2, non-TLS protocol on port 443

runner_ilove.exe  1646592 bytes
  sha256  b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061
  sha1    425efc5636affb32f4a72f73b5b80c26c54b15bc
  md5     cb50fe432a302b85845bc7ea98742c11

pcap  sha256  287d6dee90cfef71f98a97c42e30444608de2cf59d2f7392a0a6df8dbbc8274b
```

## Source

■ [malware-traffic-analysis.net, 2026-10-01 traffic analysis exercise](https://www.malware-traffic-analysis.net/)
