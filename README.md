# Linux System Compromise Investigation

JahMari Harrigan | CSCI 4344 Digital Forensics | Albany State University

This capstone examines a simulated compromised Linux CI/CD worker using Hal Pomeranz's [Righteous IT forensic scenario](https://righteousit.com/2026/03/27/linux-forensic-scenario/). The investigation follows activity involving the `worker` account, SSH connections, a Python shell, high CPU usage, and concealed processes.

## What the evidence shows

The strongest finding is a cryptocurrency miner running under the name `top`. A terminal remnant recovered from memory shows `xmrig` renamed to `top`, launched against `127.0.0.1:3333`, and followed by removal of its staging directory. The same sequence includes an `id` result showing UID 0.

Other artifacts connect that activity to an SSH forwarding endpoint and a suspicious preloaded library:

- SSH PID 975 listens on loopback port 3333 and connects to `192.168.5.95:22`. The disguised miner, PID 977, connects to that listener.
- The collector records `libymv.so.3` in the global preload configuration. The SSH daemon also maps a library with that name.
- Five processes missing from the ordinary process listing appear in the supplied memory socket output. Along with the library evidence, this supports concealment by a user-space rootkit.

The shared jump host, `192.168.4.35`, requires careful interpretation. Its traffic includes the evidence collector's own login on source port 58910. The suspicious shell connection uses port 48411. Treating every connection from that address as an attack would mix collection activity with the incident.

The first unauthorized entry remains unresolved. The evidence also does not establish the rootkit's exact implementation, an ultimate mining pool, mining revenue, or exfiltration.

## Investigation files

| Folder | Contents |
| --- | --- |
| [Documentation](Documentation/Investigation.md) | Findings, methods, competing explanations, and limitations |
| [Screenshots](Screenshots/Captions.md) | 16 evidence screenshots with captions and source paths |
| [Timeline](Timeline/Timeline.csv) | 28 dated events and a separate file for untimed commands |
| [IOC](IOC/Indicators.csv) | 11 assessed indicators and contextual leads; ATT&CK mappings |
| [Scripts](Scripts/README.md) | Analysis scripts, dependency list, and reproduction instructions |
| [Commands](Commands/README.md) | Commands for reviewing selected artifacts |

Start with the [investigation](Documentation/Investigation.md), then compare the [timeline](Timeline/Timeline.csv) with the cited artifacts. The [final scope review](Documentation/Final_Scope_Review.md) covers SUID/SGID utilities, startup profiles, and DNS configuration.

## Evidence and verification

Archive: `uac-vbox-linux-20260324234043.tar.gz`  
Downloaded: October 30, 2026  
Size: 6,205,082,254 bytes

SHA-256:

```text
81664ab2337f3d319cfeaf0d96e6ae982b4b8ec383341a69a026cb016d4e443e
```

The download digest matched a second full-file calculation. This verifies consistency of the acquired copy; no publisher-signed checksum was available for comparison. The original archive and raw memory are excluded from this repository. Obtain them from the official scenario page to reproduce the analysis.

## Methods and limits

Analysis used Python, Dissect, and ripgrep on Windows. Selected memory strings were checked against the raw capture at their recorded offsets: all 102 checks matched. The supplied Volatility socket output was examined but not independently regenerated. An attempt to recover the complete suspicious library from contiguous memory regions was unsuccessful.

The screenshots show local evidence-review pages, not a live compromised desktop. No recovered executable was run and no scenario host was contacted. Automated assistance was used for parsing, correlation, and drafting; methods and source locators are included for review.

The recorded presentation is still in preparation. Its YouTube link will be added after upload.

See [references](Documentation/References.md) for the scenario, tools, and MITRE ATT&CK technique definitions.
