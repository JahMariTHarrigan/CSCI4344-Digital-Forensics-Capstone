from read_evidence import *
import hashlib
checks=[]
with (R/'working/01931.bin').open('rb') as f:
    for line in (R/'analysis/memory_rg_hits.txt').read_text().splitlines():
        m=re.match(r'(\d+):(\d+) (.*)',line)
        if not m:continue
        ln,off,s=int(m[1]),int(m[2]),m[3]
        if not any(k in s for k in ['mv xmrig top','pty.spawn("/bin/bash")','XMRig/6.24.0','libymv.so.3']):continue
        f.seek(off);actual=f.read(len(s.encode()))
        checks.append({'strings_line':ln,'reported_offset':off,'text':s,'matches_raw_dump_at_reported_offset':actual==s.encode(),'actual_prefix':actual[:70].hex()})
(R/'analysis/memory_offset_verification.json').write_text(json.dumps(checks,indent=2))
print('Verified',sum(c['matches_raw_dump_at_reported_offset'] for c in checks),'of',len(checks))
print(json.dumps(checks[:3],indent=2))
