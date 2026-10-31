from read_evidence import *
from datetime import datetime,timezone
CASE='JH-CAPSTONE-2026-001'
J=json.loads((R/'analysis/journal_events.json').read_text())
timeline=[]
def j(suffix,n,description,user,significance,kind='Recorded event'):
    e=next(e for e in J if Path(e['source']).name==suffix and e['record']==n)
    timeline.append(dict(time=e['ts'],event=description,user=user,source=e['source']+f' record {n}',significance=significance,kind=kind))
U='user-1000@00064dcd5cdd0830-edb9e10e43a7e0a3.journal~'
S='system@00064dcd5758a0f6-bc905051ecbf280b.journal~'
F='system@00064dcd6b0507a3-7a3e1e7e0da0f332.journal~'
j(U,305,'worker denied sudo: user not in sudoers','worker','Earlier baseline differs from the later unrestricted sudo rule; setup activity cannot be assumed malicious.')
j(U,307,'su opens a root session for worker','worker -> root','Administrative access existed before the later incident window; operator intent is not recorded.')
timeline.append(dict(time='2026-03-24T16:01:44+00:00',event='10-workers-rule mtime/ctime/birthtime',user='Unknown; file owner root',source='bodyfile/bodyfile.txt line 160531',significance='Metadata dates the passwordless sudo policy artifact; it does not identify its author.',kind='File metadata'))
j(U,314,'worker invokes /bin/bash through sudo','worker -> root','Recorded successful privilege transition after the sudo-rule timestamp.')
j(S,881,'worker password accepted from 192.168.4.35:49366','worker','Confirms password-based remote access; no individual operator attribution.')
j(U,558,'worker invokes root bash via sudo','worker -> root','Another administrative session; not independently assigned to an attacker.')
j(S,1084,'Connection from 192.168.4.35:48411 closed','Unknown','Same source port later appears with the suspicious socket; an early probe is possible, not proven.')
j(S,1108,'SSH listener restarts as PID 936','root service','Service change precedes the later boot; the cause is not independently identified.')
j(S,6217,'worker password accepted from 192.168.4.35:46862','worker','Additional valid-account access; shared jump-host use limits attribution.')
j(S,6572,'worker password accepted from 192.168.4.35:35586','worker','Additional pre-collection login in the retained journal.')
j(F,939,'sshd logs libymv preload failure: file too short','root service','A preload configuration was present but unsuccessful at this earlier point.')
j(F,990,'Connection from 192.168.4.35:48411 closed','Unknown','Does not record an Accepted password event for this connection.')
j(F,1000,'worker password accepted from 192.168.4.35:38274','worker','Successful remote login during the earlier failed-preload boot.')
j('user-1000@00064dcd6c3b1bfb-6a67f21fb8deed92.journal~',66,'worker runs root bash through sudo','worker -> root','Root access recorded; benign setup/administration remains an alternative for this event.')
j('system.journal',842,'SSH listener available on TCP/22 after reboot','root service','Establishes the current-boot listener before the final library replacement.')
j('system.journal',879,'worker password accepted from 192.168.4.35:48364','worker','Remote login precedes the suspicious library metadata timestamp.')
j('user-1000.journal',39,'worker runs root bash through sudo','worker -> root','Temporal proximity to library change supports a possible installation path; not proof of operator identity.')
j('system.journal',916,'Short worker password session from .35:55504','worker','Separate brief session; do not merge it with the .35:48411 shell channel.')
timeline.append(dict(time='2026-03-24T23:24:51+00:00',event='libymv.so.3 mtime/ctime/birthtime',user='Unknown; file owner root',source='bodyfile/bodyfile.txt line 28956',significance='24,024-byte root-owned executable library appears with matching metadata times; creation is a metadata observation.',kind='File metadata'))
j('system.journal',924,'SSH PID 801 receives termination signal','root service','Listener is replaced soon after the library timestamp.')
j('system.journal',930,'New SSH listener PID 937 starts','root service','PID 937 later maps libymv and shares the suspicious socket with shell processes.')
j('user-1000.journal',43,'Earlier sudo session closes','worker -> root','Separates the earlier administrative session from the subsequent collection session.')
j('system.journal',956,'Failed worker password from .35:55662','worker (attempted)','One logged failed password; not enough to establish a brute-force campaign.')
j('system.journal',959,'worker password accepted from .35:58910','worker','The captured process tree links this login to the UAC collection session.')
j('user-1000.journal',129,'Collector-associated sudo starts root bash','worker -> root','PID 1076 is the ancestor of UAC; avoid labeling this elevation attacker activity.')
timeline.append(dict(time='2026-03-24T23:38:07+00:00',event='UAC ir_triage plus AVML collection starts',user='root collector',source='uac.log lines 1-8',significance='Beginning of documented live evidence collection.',kind='Collector event'))
timeline.append(dict(time='2026-03-24T23:39:23+00:00',event='UAC invokes filesystem statx enumeration',user='root collector',source='uac.log line 2235',significance='Bodyfile is a later live snapshot, not a complete historical audit.',kind='Collector event'))
timeline.append(dict(time='2026-03-24T23:40:43+00:00',event='UAC artifact collection completion logged',user='root collector',source='uac.log line 4139',significance='Log reports completion in 155 seconds; separate memory/member timestamps are not overwritten by this field.',kind='Collector event'))
timeline.sort(key=lambda r:datetime.fromisoformat(r['time']))
for i,e in enumerate(timeline,1):e['id']=f'TL-{i:02d}'
untimed=[
['UT-01','python3 -c with pty.spawn("/bin/bash")','Shell associated with PID 939/940','Raw memory offset 4743251455; supplied socket rows 348-356','Interactive PTY creation. No trustworthy per-command timestamp.'],
['UT-02','id returns uid=0(root), gid=7823','Root shell','Raw memory offset 3858882983','Strong evidence of privileged shell context; not a named human.'],
['UT-03','mv xmrig top; export PATH=.:$PATH','Root shell','Raw memory offset 3858883096 onward','Renames the miner and prioritizes its directory during command lookup.'],
['UT-04','ssh -F config ymv; bg','Root shell','Raw memory offset 3858883179 onward','Starts and backgrounds SSH using a separate configuration. Socket evidence supports forwarding.'],
['UT-05','top -o 127.0.0.1:3333 -B','Root shell','Raw memory offset 3858883445; supplied socket rows 357-362','Miner command uses loopback forwarding. Remnant ps output shows PID 977, 99% CPU and 19:29 start; exact date/time not independently timestamped.'],
['UT-06','rm -rf kit','Root shell','Raw memory offset 3858883558 onward','Removal command and later empty listing support cleanup, without recovering full deleted files.']]
iocs=[
['IOC-01','/usr/lib/x86_64-linux-gnu/libymv.so.3','File path','High-confidence suspicious library','Preload output; PID 937 maps lines 45-49; bodyfile line 28956','Investigate this exact library with preload and hidden-process context; basename alone is not a universal verdict.'],
['IOC-02','0fd709f09c073df274e272aabcabe3e0f3487f9e','SHA-1 (collector recorded)','Library fingerprint; not examiner-computed SHA-256','hash_executables/hash_executables.sha1 line 377','Hunt for matching bytes if a full file is acquired. Original contents not recovered in this examination.'],
['IOC-03','/etc/ld.so.preload -> /lib/x86_64-linux-gnu/libymv.so.3','Configuration','Strong persistence/concealment indicator','chkrootkit/etc_ld_so_preload.txt line 1; mapped library','Global loader hook with correlated process hiding; confirm system baseline before remediation.'],
['IOC-04','top -o 127.0.0.1:3333 -B','Command line','Strong disguised-miner indicator','Raw memory offset 3858883445; xmrig rename; supplied socket row 362','Do not flag ordinary /usr/bin/top alone. Exact arguments and context distinguish the miner.'],
['IOC-05','/dev/shm/kit','Working directory','Suspicious tool staging/cleanup path','Raw memory offsets 3858883017-3858883793','Terminal remnants show config, rk.so, xmrig, subsequent rename and removal.'],
['IOC-06','192.168.5.95:22','Remote endpoint','SSH peer associated with miner forwarding','Supplied memory socket row 357; raw command context','Private lab address; does not establish ownership, ultimate mining pool, or compromise of the peer.'],
['IOC-07','127.0.0.1:3333','Loopback listener','Forwarded miner endpoint in this case','Supplied memory socket rows 359-362','Correlate SSH PID 975 listener with top PID 977 connection; loopback IP alone is not malicious.'],
['IOC-08','192.168.4.35:48411 -> 192.168.4.22:22','Connection tuple','Suspicious shell-bearing connection','Supplied memory socket rows 347-356; Python remnant','Separate this tuple from the collector login on source port 58910.'],
['IOC-09','worker','Account of interest','Legitimate account with excessive privilege; attribution unresolved','passwd line 37; sudo rule; journals','A shared account is not itself a malicious IOC. Investigate credential use and restrict privilege.'],
['IOC-10','192.168.4.35','Context address','Shared jump host; mixed-use indicator','Authentication journals and two distinct socket tuples','Do not blanket-block or identify it as attacker infrastructure solely from its presence.'],
['IOC-11','gid=7823','Runtime attribute','Corroborating shell-context marker','Raw memory offset 3858882983; no matching group entry','A hidden-process grouping mechanism is a hypothesis; rootkit internals were not recovered.']]
attack=[
['T1059.006','Python','Execution','Supported','Python PTY command verified in raw memory and Python PID 940 in supplied socket table.'],
['T1059.004','Unix Shell','Execution','Supported','Raw terminal remnants and sh/bash processes associated with the suspicious socket.'],
['T1036.005','Match Legitimate Resource Name or Location','Stealth','Supported','mv xmrig top and miner arguments impersonate a familiar Linux utility name.'],
['T1496.001','Compute Hijacking','Impact','Strongly supported','XMRig identity strings, launch command, 99% CPU terminal remnant, and connected miner socket. Successful mining revenue is not established.'],
['T1572','Protocol Tunneling','Command and Control','Strongly supported','SSH owns loopback listener 3333 and connects to .5.95:22; miner connects to that listener. Forward target/payload not recovered.'],
['T1574.006','Dynamic Linker Hijacking','Stealth; Execution','Strongly supported','Global preload path, SSH daemon library map and correlated hidden processes. Loader persistence is a case observation; listed tactics follow current MITRE.'],
['T1014','Rootkit','Stealth','Strongly supported inference','Suspicious injected library plus process-list omissions corroborated by memory-derived socket output. Exact hook implementation and malware family not proven.'],
['T1070.004','File Deletion','Stealth','Supported command/remnant evidence','rm -rf kit followed by empty directory listing in raw memory. Full deleted-file recovery was not achieved.'],
['T1548.003','Sudo and Sudo Caching','Privilege Escalation','Conditional attacker mapping','Unrestricted NOPASSWD rule and actual worker-to-root sessions exist, but attribution of the installation to a specific sudo session is unresolved.']]
for row in attack:row.append('https://attack.mitre.org/techniques/'+row[0].replace('.','/')+'/')
evidence_paths=[
('[root]/etc/passwd','Account definitions'),('[root]/etc/group','Group membership'),('[root]/etc/shadow','Credential state; hashes excluded from report'),('[root]/etc/sudoers.d/10-workers-rule','Privilege policy'),('bodyfile/bodyfile.txt','Filesystem metadata'),('chkrootkit/etc_ld_so_preload.txt','Loader configuration observation'),('live_response/process/hidden_pids_for_ps_command.txt','Process discrepancy list'),('live_response/process/ps_auxwwwf.txt','Visible process tree'),('live_response/process/proc/937/maps.txt','SSH daemon memory mappings'),('memory_dump/avml.lime','Raw memory capture'),('memory_dump/memory-strings.ascii','Supplied offset-bearing memory strings'),('memory_dump/output-sockstat','Supplied Volatility 3 2.27.1 socket output; not rerun here'),('hash_executables/hash_executables.sha1','Collector SHA-1 listing'),('uac.log','Collector operations log')]
manifest=json.loads((R/'working_manifest.json').read_text())
by_path={x['path']:x for x in manifest}
for _,x in records():
    if '/var/log/journal/' in x['path']:evidence_paths.append((x['path'],'Systemd journal'))
evidence=[]
for i,(p,d) in enumerate(evidence_paths,3):
    m=by_path[p];evidence.append(dict(id=f'EV-{i:03d}',path=p,description=d,bytes=m['size'],sha256=m['sha256'],local=m['local']))
if __name__=='__main__':
    (R/'analysis/case_data.json').write_text(json.dumps(dict(case=CASE,timeline=timeline,untimed=untimed,iocs=iocs,attack=attack,evidence=evidence),indent=2))
    print('Timeline events',len(timeline),'untimed',len(untimed),'IOCs',len(iocs),'evidence records',len(evidence))

