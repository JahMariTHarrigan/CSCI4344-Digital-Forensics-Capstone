# Executive summary

## Assessment

The collected evidence strongly supports compromise of the simulated Linux host vbox (192.168.4.22), including a privileged interactive shell, a cryptocurrency miner disguised as top, and concealment consistent with a user-space rootkit. This assessment rests on independent examination of the downloaded archive, not on a copied scenario solution. The most persuasive evidence is the agreement between raw memory remnants, the supplied memory-derived socket table, the global preload observation, and the SSH daemon memory map.

## What happened

A root-context terminal remnant lists config, rk.so, and xmrig in /dev/shm/kit. It shows xmrig renamed to top, PATH changed to prioritize the current directory, an SSH connection launched with a configuration alias, and top started with a loopback endpoint on port 3333. The same remnant shows removal of kit. The supplied socket table associates top PID 977 with an SSH-owned loopback listener and an outbound connection to 192.168.5.95:22. These observations explain the reported CPU utilization more convincingly than an ordinary system-monitoring process.

## What is established

The worker account has unrestricted passwordless sudo rights. Actual worker-to-root sessions are logged. A separate recovered shell reports uid=0 and gid=7823. Five suspicious PIDs appear in supplied memory socket output while being omitted from ordinary ps output. The SSH daemon maps libymv.so.3, matching a recorded global preload path. These observations support administrative access, execution, concealment, and a persistence mechanism.

## What remains uncertain

The evidence does not establish how the first unauthorized operator obtained access or a password. Shared jump-host traffic includes the UAC collection session, so neither every worker login nor every use of 192.168.4.35 is malicious. There is no independently reconstructed packet capture, complete deleted-file recovery, verified mining payout, or proven exfiltration. The supplied Volatility socket output was inspected, not independently regenerated. Conclusions are limited accordingly.

## Immediate response

For a real incident with these findings, preserve memory and disk evidence, isolate the worker while retaining an authorized investigation channel, rotate exposed credentials, and rebuild from a known-good image. Review SSH forwarding and privileged access. Treat local process listings as potentially incomplete until checked against trusted external or offline evidence.

# Acquisition, preservation, and chain of custody

## Authority and scope

This is the instructor-authorized Righteous IT educational scenario. The original file is uac-vbox-linux-20260324234043.tar.gz. The task did not authorize testing the dataset addresses, logging in to remote systems, or running recovered programs. All examination used local copies and passive parsing. The existing Ubuntu VM is an available workstation, but this run performed file analysis on the Windows host; it did not recreate an incident in Ubuntu.

## Acquisition record

Automated collection for JahMari Harrigan began October 30, 2026 at 15:45:23.097028 UTC and completed at 16:03:20.757009 UTC through the sharing link on the official scenario page. The received file is 6,205,082,254 bytes. A second full-file SHA-256 calculation at 21:22:22.206653 UTC matched the download hash. Figure 1 shows the actual verification record. This is a locally verified equality check, not a comparison with an independently published source checksum.

## Working evidence

The original archive was retained. An initial archive inventory counted 5,496 members before targeted searching. Extraction completed at 21:25:08.665091 UTC: 3,516 regular files totaling 11,180,188,785 logical bytes. Each extracted stream received a SHA-256 hash. Numbered local filenames preserve Linux paths in a manifest without Windows case collisions, path traversal, or accidentally materialized links. No evidence executable was launched. The original plus extracted working set avoids a redundant 6.2 GB compressed working copy.

## Custody and integrity limits

Case JH-CAPSTONE-2026-001 uses EV-001 for the original archive and EV-002 for the extracted working collection. Individual relevant artifacts have EV-003 onward identifiers in the inventory. Custody records document automation for the student rather than claiming the student personally performed each action. No hand-signed transfer is invented. A cryptographic hash protects byte identity, but it cannot establish truthfulness of the compromised source host, its clock, or collector commands. The retained original remains the reference for repeatable extraction.

## Why custody matters

A defensible chain of custody connects every examined copy to an identified source and records who or what handled it, when, why, and where it was retained. Missing custody details can prevent a reviewer from distinguishing source evidence from later edits or generated analysis. The separate custody PDF records actual acquisition, verification, extraction, and retention events and explicitly separates the author-provided pre-download history from the local handling history.

# Evidence inventory and examination method

## Evidence coverage

The archive contains a UAC live collection, copied Linux configuration and log files, a filesystem bodyfile, an 8,589,467,742-byte AVML memory capture, a 2,310,807,163-byte offset-bearing strings file, and supplied socket output labeled Volatility 3 Framework 2.27.1. The memory-derived text files are evidence supplied with the package. They are not presented as results of a new Volatility run. Figure 2 shows the inventory scope.

## Collector provenance

uac.log identifies a DEVELOPMENT VERSION, hostname vbox, x86_64 Linux, and root collection using ir_triage plus memory_dump/avml.yaml. Its first entry is March 24 at 23:38:07 UTC and its completion entry is 23:40:43 UTC. The log reports 155 seconds. The archive filename and individual member timestamps are separate provenance fields; none replaces the recorded collector interval. A development label prevents exact release attribution from the supplied log alone.

## Examination sequence

After preservation and inventory, the examination parsed account and privilege files, correlated journal events, compared process views, reviewed loader and startup configuration, and searched memory-derived strings for case-specific commands. Seven systemd journal files yielded 13,705 records using Dissect target 3.25.1. Each exported event retains its source archive path and ordinal record number. The timeline uses those record locators, not invented journal line numbers.

## Systematic searching

The initial text pass searched worker, 192.168.4.35, ssh, sudo, root, python, curl, wget, chmod, base64, cron, systemctl, and authorized_keys. It covered readable regular artifacts up to 30 MB, excluding NUL-containing files, gzip streams, and memory. Binary journals and memory received separate parsing/searches. New leads included libymv, xmrig, pty.spawn, /dev/shm/kit, port 3333, and gid=7823. Matches in documentation or program help were not treated as execution evidence.

## Memory and timing controls

Selected strings were checked against the raw memory capture at their reported file offsets: 102 of 102 selected checks matched. These offsets are file positions, not asserted process virtual addresses. A targeted contiguous carving attempt tested 9,346 ELF candidates for the known library size and collected SHA-1; none matched. That failure is retained as a limitation. UTC is used throughout; the host clock record reports EDT, UTC-04:00. Metadata ctime is inode/status change time, not creation time.

# User, account, and privilege analysis

## Account inventory

The passwd file contains 38 entries. Root has UID/GID 0 and /bin/bash; worker has UID/GID 1000, home /home/worker, and /bin/bash. The remaining entries largely describe service accounts with noninteractive shells. The account inventory alone does not identify a newly created malicious account. Worker is an account of interest because of the scenario and its observed sessions, not because its name is inherently suspicious.

## Password and group state

The shadow examination found password hashes for root and worker and locked password fields for the other listed accounts. Hash contents are excluded from the report and public materials. The recorded last-change day is not an account-creation timestamp. The group file places worker in users; the sudo group entry has no listed members. No group named for GID 7823 appears. Numeric credentials can exist without a matching group-file name, so the recovered GID does not itself prove an account was created.

## Administrative rights

The separate rule in /etc/sudoers.d/10-workers-rule reads worker ALL=(ALL) NOPASSWD:ALL. This direct grant provides broad administrative authority even though worker is not listed in the sudo group. Figure 3 shows the relevant account and policy lines. The bodyfile records the rule with root ownership, mode -rw-rw-r--, and matching mtime/ctime/birthtime at 16:01:44 UTC on March 24. The unusually permissive mode warrants review; the logs independently show sudo succeeded.

## Changes and alternatives

An earlier journal record at 15:57:28 UTC says worker was not in sudoers; a later record at 16:02:14 records root bash through sudo. This agrees with a policy change between those observations. Because the dataset includes system setup and investigation activity, this sequence is not automatically an attacker-created privilege grant. A passwordless configuration can enable compromise without being created by the attacker.

## Was root obtained?

Yes, the examined evidence supports root-context activity. Journals show worker-to-root transitions, and the recovered terminal remnant reports uid=0(root), gid=7823. The latter appears in the same command sequence as the disguised miner. These support a privileged suspicious session. They do not identify the human operator or conclusively show that the suspicious session reached root by the particular sudo event near 23:23:34. The collection session itself also used sudo and must remain separate.

# Authentication, SSH, and initial access

## Recorded authentication

The parsed journals show several successful worker password logins from 192.168.4.35 across the scenario day. In the final boot, source ports 48364 and 55504 appear before the library change; a failed password on source port 55662 occurs at 23:33:44.773100 UTC; a successful password on 58910 follows at 23:34:32.435430 UTC. The failed record and disconnect message do not establish a large password-guessing campaign. Figure 4 separates the sessions.

## Collector-associated login

The captured process tree connects sshd-session PID 1005, worker PID 1047, bash PID 1064, sudo PIDs 1076/1078, root bash PID 1079, and UAC PID 1096. This tree links the .35:58910 session to evidence collection. The matching sudo journal event occurs at 23:34:57 UTC. Treating this session as confirmed attacker privilege escalation would misread investigator activity as compromise. Figure 5 preserves the ancestry.

## Suspicious socket is different

The supplied memory socket table instead associates .35:48411 to .22:22 with listener PID 937 and sh PID 939, python3 PID 940, and bash PID 941. Shared file descriptors point to the same kernel socket object. Raw memory includes a Python PTY command and PPID=937 in nearby shell-state strings. These observations support an unusual shell channel through the listener. They are not proof of a normal, authenticated SSH session; a TCP port label is not an application-protocol validation.

## Configuration and keys

The collected sshd_config includes /etc/ssh/sshd_config.d/*.conf, but no regular include files were present in the archive inventory. It explicitly enables PAM, disables keyboard-interactive authentication, and includes commented examples for PasswordAuthentication and PermitRootLogin. Commented lines are not active settings. The successful Accepted password records prove password authentication was actually used. No authorized_keys member was collected, and key-based persistence is therefore not established.

## Initial-access conclusion

Valid-account access existed and worker had powerful privileges. A plausible sequence is administrative access followed by preload installation and a concealed shell mechanism. However, password theft, the initial attacker login, the exact triggering mechanism, and the identity behind the jump host cannot be proven from these artifacts. The assessment records initial access as unresolved, while assessing the later root-shell and mining activity as strongly supported. Obtain jump-host audit records, connection capture, and full disk evidence to resolve the gap.

# Command history and Python shell analysis

## History availability

No .bash_history or .zsh_history member was present for the examined archive, and authorized_keys was also absent from the member inventory. Missing history does not prove a history-clearing command was executed. Shell histories may be disabled, unflushed, excluded, hidden, or otherwise uncollected. No specific history-clearing event is asserted. Command analysis instead uses raw-memory terminal remnants and corroborating process/socket records.

## Recovered sequence

At raw-memory file offset 3858882749, a 1,070-byte excerpt retains a terminal sequence beginning with shell/terminal adjustments and id. It then changes to /dev/shm/kit, lists config, rk.so, and xmrig, renames xmrig to top, prepends the current directory to PATH, invokes ssh -F config ymv, backgrounds that job, and launches top -o 127.0.0.1:3333 -B. It changes to the parent directory, removes kit, and displays a ps result for top. Figure 9 shows the direct extraction. The sequence is not assigned invented per-command timestamps.

## What the commands imply

The rename gives a mining executable the familiar name of a monitoring utility. PATH=.:$PATH allows a command in that staging directory to be selected before standard paths. The SSH invocation uses a local configuration file and alias; the terminal mentions 192.168.5.95 and the remote account pocmp. The launch parameters point the renamed program at a loopback service and request background execution. Removal of kit is consistent with cleanup, supported by the following directory listing, but does not reconstruct the complete deleted directory.

## Python role

The command python3 -c with import pty and pty.spawn("/bin/bash") requests a pseudo-terminal for bash. Selected copies of this string match raw memory bytes at the supplied offsets. Python PID 940 and bash PID 941 share the suspicious port-22 connection in the supplied memory socket output. Together, these support interactive-shell use. The command itself is not a reverse-shell network connector; no Python socket.connect or separate outbound Python connection is established here. Figure 10 shows the offset verification.

## Scope of interpretation

The retained prompt and id output support a root shell context, but prompts alone can be altered. Corroboration comes from privileged configuration changes and the associated process/network evidence. Searches also matched routine package documentation, helper scripts, and library strings for curl, wget, chmod, and base64. Those generic matches were not promoted into attacker commands. There is no supported claim of a specific download URL, encoded payload, or exfiltration command in the examined results.

# Filesystem and deleted or concealed evidence

## Library metadata

The bodyfile lists /usr/lib/x86_64-linux-gnu/libymv.so.3, inode 715378, root UID/GID, executable mode -rwxr-xr-x, and size 24,024 bytes. Its mtime, ctime, and birthtime are 23:24:51 UTC on March 24; its atime is 23:25:19. The latter coincides with an SSH restart, but access time alone does not prove which process read the file. The daemon map supplies stronger evidence of actual mapping. Figure 14 includes the metadata and collected hash.

## Hash limitation

The UAC executable listing records SHA-1 0fd709f09c073df274e272aabcabe3e0f3487f9e for this library. A regular member containing the original library was not present in the extracted collection. A targeted raw-memory carving attempt did not recover a contiguous candidate matching that size and hash. A hash of a string excerpt would not identify the missing complete library, so no full-file SHA-256 is claimed. The archive, extracted artifacts, and derivative excerpt files have their own clearly identified SHA-256 values.

## Staging and deletion

The raw terminal sequence places config, rk.so, and xmrig under /dev/shm/kit and later issues rm -rf kit. /dev/shm is a memory-backed location; the archive does not provide a full disk image with all historical allocation data. The bodyfile records the later state of /dev/shm, including two lttng files, but no kit directory. This agrees with removal or concealment and is stronger when read alongside the actual removal command. It does not independently date deletion.

## Temporary and hidden files

A root-owned 22-byte /tmp/silly.txt appears in metadata at 23:34:32 UTC. Its name and temporary location alone do not establish malicious intent, and its contents are not asserted. Dotfiles such as .bashrc and .profile are normal Linux configuration artifacts; their presence alone is not concealment. The more specific concealment indicators are the preload configuration, process-list discrepancies, miner renaming, and deletion sequence.

## Timestamps and log gaps

The bodyfile contains observed filesystem timestamps, not a complete record of historical actions. ctime is status change, and birthtime is used only where a nonzero value is supplied. No deliberate timestamp modification was demonstrated. Journal rotation and .journal~ files are not by themselves proof of log tampering. The available records contain setup, repeated boots, and collector activity, so a gap or unusual time must be corroborated before being described as anti-forensics.

# Process investigation and high CPU

## Ordinary process view

The ps process tree appears largely ordinary and includes service processes, worker desktop services, the SSH listener, and the UAC collection tree. It does not show the key suspicious sh, python3, bash, ssh, and top PIDs listed in the supplied memory socket table. UAC separately records hidden_pids_for_ps_command.txt with 43168, 939, 940, 941, 975, and 977. Figure 6 shows this discrepancy.

## Corroborated omissions

The supplied memory output lists sh 939, python3 940, bash 941, ssh 975, and top 977 with meaningful sockets. These five overlaps are more informative than an isolated missing PID, since live collection naturally races with process creation and exit. PID 43168 is not independently explained by the socket corroboration and remains unresolved. No claim is made that every missing PID is malicious or that the supplied output is immune to parsing limitations.

## Miner identity

The raw command sequence renames xmrig to top. A verified memory string identifies XMRig/6.24.0 with libuv/1.51.0, and the terminal remnant shows top -o 127.0.0.1:3333 -B with PID 977, parent 1, and CPU value 99. The supplied socket output lists multiple threads for PID 977 and an established connection to the loopback endpoint. These observations strongly support a miner disguised as top rather than a normal top monitor.

## CPU conclusion

The disguised miner is the best-supported explanation for the reported high CPU. The 99 value comes from a recovered ps output remnant, not a fresh measurement of the simulated host. It supports substantial historical CPU use but does not provide continuous utilization, mining shares, a wallet, revenue, or an exact duration. The displayed 19:29 start is minute-level text in an otherwise untimed remnant; it is described as approximate context, not a precise timeline event.

## Trust boundary

The injected library is mapped into the SSH daemon, and ordinary process visibility disagrees with the memory-derived view. This supports user-space concealment. Exact hooks, a kernel rootkit, and a named malware family were not proven by disassembly or complete binary recovery. A trusted live response should use independently validated tools and offline memory analysis, and retain discrepant views rather than discarding one until the mechanism is understood.

# Network analysis and jump-host role

## Host and addresses

The investigated host is vbox at 192.168.4.22. The scenario-designated jump host is 192.168.4.35. Authentication records and sockets confirm traffic from that address, but the address is shared by multiple sessions, including the collector-associated one. It is a private lab address, not a globally attributable attacker location. The remote endpoint 192.168.5.95 appears in a separate outbound SSH connection.

## Suspicious inbound channel

Rows 347-356 of the supplied socket table associate 192.168.4.22:22 and 192.168.4.35:48411 with sshd PID 937, sh 939, python3 940, and bash 941. The shared kernel socket offset is 0x8c7cc4059300. This supports a shell-bearing connection through the daemon. It does not independently identify a password, encryption state, or authentication outcome. The SOC statement about plaintext on port 22 remains scenario context because no packet capture was independently decoded in this examination.

## Forwarding and mining

Rows 357-362 show SSH PID 975 connecting from 192.168.4.22:33440 to 192.168.5.95:22. The same SSH PID owns loopback listeners, including 127.0.0.1:3333, and an established local connection from port 59182. Top PID 977 owns the matching client side. Correlating this with ssh -F config ymv and the miner launch strongly supports an SSH-forwarded mining path. Figure 12 records these relationships.

## Limits on remote claims

The forwarding configuration file was not recovered as a separate complete file. The ultimate forwarded destination, mining pool, wallet, authenticated remote privileges, and traffic content are therefore not established. A successful TCP connection to .5.95:22 does not prove that host was compromised. Default XMRig domain strings in memory are software strings; they are not automatically observed DNS queries or actual outbound destinations.

## Monitoring implications

Monitor process ownership of loopback listeners as well as external flows. A miner can connect only to localhost while another process carries its traffic outward. Investigate unexpected SSH forwarding on CI/CD workers and correlate connection tuples with process identity, user sessions, and timestamps. Preserve jump-host logs before deciding which user or device originated activity. Do not treat all port-22 traffic as trusted administrative SSH solely because of the port number.

# Persistence and concealment assessment

## Global preload mechanism

The collector output records /lib/x86_64-linux-gnu/libymv.so.3 in /etc/ld.so.preload. PID 937 maps the corresponding /usr/lib path, with matching inode 715378 from the bodyfile. The basename agrees across the /lib preload reference and /usr/lib mapping; the mapped inode supplies the direct metadata correlation. A global preload entry can cause a shared object to load into newly launched dynamically linked processes. This is a durable execution mechanism when the file and configuration persist.

## Earlier failure, later active loading

At 23:16:30 UTC, journals contain repeated loader messages saying the referenced library was too short. At 23:24:51 the bodyfile dates a 24,024-byte library; at 23:25:19 the SSH listener restarts; the later process map contains the library. The evidence supports a transition from an earlier failed preload to later active mapping. It does not justify labeling every earlier warning as successful rootkit execution. Figure 13 preserves the failure evidence.

## Other persistence checks

The collected system crontab contains standard hourly, daily, weekly, and monthly maintenance dispatch. Collected cron files and root/worker .bashrc and .profile files were reviewed; no case-specific miner or libymv launch entry was identified there. A targeted service-content scan found no libymv, kit, xmrig, .5.95, or loopback-miner terms. That bounded negative result is not proof that every possible service or task is clean. Figure 15 documents part of the scope.

## SSH keys and accounts

No collected authorized_keys member supports SSH-key persistence. The account list does not establish an added attacker account. The worker sudo rule is a significant privilege weakness, but the available sequence could include legitimate scenario setup. No malicious cron job, startup script, new account, or authorized key was established by these checks.

## Concealment conclusion

The combination of a global preload reference, daemon mapping, five corroborated process omissions, miner masquerading, and working-directory removal strongly supports deliberate concealment. The exact binary implementation and a trigger on source port 48411 remain unproven. A post-reboot test was not performed on the compromised system; persistence is assessed from the surviving loader configuration and observed loading, not from a new execution experiment.

# Attack reconstruction and tested hypotheses

## Reconstruction

The record begins with legitimate-looking setup and administrative access, including a change from denied sudo to a direct passwordless grant. Later, libymv preload failures are logged. In the final boot, a worker-to-root session precedes the library metadata time, followed by an SSH restart and a daemon mapping of that library. This temporal sequence is compatible with privileged installation, but the exact installer is not directly recorded. The suspicious socket connects the listener with sh, Python, and bash. Recovered root-context commands stage and disguise XMRig, establish an SSH-associated local endpoint, run the miner, and remove kit. The collector subsequently logs in through a different source port and runs UAC.

## H1: stolen worker credentials

INCONCLUSIVE. Password-authenticated worker access and excessive sudo rights are demonstrated. Password theft, an attacker-attributed login, and the origin behind the shared jump host are not. A single failed password before the collector login cannot establish credential compromise. Jump-host audit records and independent session attribution would test this hypothesis more directly.

## H2: valid account followed by privilege escalation

PARTIALLY SUPPORTED. Worker can obtain root, and actual sudo transitions occur. A root session precedes the suspicious library timestamp, making this a plausible installation path. However, the evidence does not bind the rootkit installer to that specific session. The later UAC-associated sudo is explicitly collector activity. The suspicious recovered shell already reports UID 0; its exact elevation path remains unresolved.

## H3: ordinary authorized CI/CD activity

REJECTED as a complete explanation of the suspicious cluster. A disguised miner, memory-backed staging, cleanup, global preload injection, and hidden processes collectively differ from ordinary build activity. Some logins and administrative commands are plainly compatible with setup or collection, so the hypothesis is not rejected for every event. This is an educational simulation, and real-world authorization cannot be inferred beyond that scenario framing.

## H4: rootkit-concealed mining through SSH forwarding

SUPPORTED by converging evidence, with mechanism limits. Raw-memory commands, miner identity, CPU remnant, supplied sockets, loader configuration, daemon maps, and process discrepancies agree. The exact rootkit family, internal hooks, upstream mining destination, and successful payouts remain unproven. No exfiltration or additional compromised host is asserted simply to fill an attack-stage model.

# Findings, conclusions, and response recommendations

## Findings

F-01: The host contains a strongly supported compromise pattern involving root-context shell activity and a disguised miner. F-02: Worker has unrestricted passwordless sudo, and actual elevation is logged. F-03: The suspicious library is globally preloaded and mapped into the SSH daemon. F-04: Five process-list omissions are corroborated by supplied memory-derived sockets. F-05: A miner connects to an SSH-owned local forwarding endpoint. F-06: Command remnants support staging, masquerading, and cleanup. F-07: Initial credential theft and the exact first unauthorized access remain unresolved.

## Containment and preservation

In a real environment, isolate the worker from production workloads after preserving volatile evidence and an authorized response channel. Acquire a full disk image and verified memory capture with trusted tools, record hashes and custody, and retain external network/jump-host logs. Do not trust a clean ps output as sufficient containment proof. Quarantine recovered binaries without executing them on the analysis workstation.

## Eradication and recovery

Rebuild from a trusted base image rather than assuming removal of the visible library restores trust. Rotate worker and administrative credentials, SSH keys, CI/CD tokens, and any accessible build secrets after scope assessment. Review the jump host and .5.95 endpoint within authorization. Validate repository/build artifacts and restore from known-good backups. Verify the rebuilt system against a baseline before returning it to service.

## Prevent recurrence

Replace the shared worker identity with individually attributable access or scoped automation identities. Remove unrestricted NOPASSWD rights and grant only required commands. Prefer strong key-based authentication, MFA at the access boundary, and an approved privileged-access workflow. Restrict SSH forwarding and egress for build workers to required peers. Keep operating-system and build-tool patches current, but do not claim a specific unpatched vulnerability caused this case.

## Detection and follow-up

Forward authentication and administrative logs to a protected central collector/SIEM. Alert on preload-file changes, unexpected executable libraries, binaries running from memory-backed directories, misleading utility names, and high CPU without visible corresponding tasks. Correlate endpoint telemetry with network sockets. Establish a response playbook for memory/disk acquisition, custody, recovery testing, and credential rotation. Train administrators to recognize suspicious forwarding and preserve evidence. A validated retest should demonstrate least privilege, external log retention, and absence of the specific indicators.