from read_evidence import *
import collections,datetime,hashlib
O=R/'analysis';O.mkdir(exist_ok=True)
keywords=['worker','192.168.4.35','ssh','sudo','root','python','curl','wget','chmod','base64','cron','systemctl','authorized_keys']
counts=collections.Counter();hits=[]
for i,x in ([] if (O/'keyword_search.json').exists() else records()):
    if int(x['size'])>30000000 or x['path'].startswith('memory_dump/') or x['path'].endswith('.gz'):continue
    p=R/'working'/f'{i:05d}.bin'
    b=p.read_bytes()
    if b'\0' in b[:8192]:continue
    for lineno,line in enumerate(b.decode('utf-8','replace').splitlines(),1):
        found=[k for k in keywords if k in line.lower()]
        for k in found:counts[k]+=1
        if found:hits.append({'path':x['path'],'line':lineno,'keywords':','.join(found),'text':line[:3000]})
if hits:(O/'keyword_search.json').write_text(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'UTF-8-readable regular artifacts <=30MB excluding NUL-containing files, gzip streams and memory; additional targeted searches recorded separately. Matching is case-insensitive substring.','counts':counts,'hits':hits},indent=2))
print('keyword counts',counts,flush=True)
targets=['libymv','pty.spawn','xmrig','stratum+','/dev/shm/','HISTFILE','LD_PRELOAD','nohup','wget http','curl http','chmod +x','bash -i','nc -','ncat ','socat ','192.168.4.35']
pat=re.compile(b'|'.join(re.escape(s.encode()) for s in targets),re.I)
i,x=next((i,x) for i,x in records() if x['path']=='memory_dump/memory-strings.ascii')
counts=collections.Counter();unique={};offset=0
with (R/'working'/f'{i:05d}.bin').open('rb') as f:
    for lineno,b in enumerate(f,1):
        if pat.search(b):
            s=b.decode('utf-8','replace').rstrip()
            counts.update([t for t in targets if t.lower() in s.lower()])
            if s not in unique:unique[s]={'line':lineno,'offset':offset,'text':s[:8000]}
        offset+=len(b)
(O/'memory_hits.json').write_text(json.dumps({'source':x['path'],'patterns':targets,'counts':counts,'unique_hits':list(unique.values())},indent=2))
print('memory counts',counts,'unique',len(unique),flush=True)
