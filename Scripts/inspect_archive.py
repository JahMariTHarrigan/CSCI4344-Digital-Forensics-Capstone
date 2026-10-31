import hashlib,json,tarfile,csv,datetime,collections
from pathlib import Path
R=Path(__file__).resolve().parent
p=R/'evidence/uac-vbox-linux-20260324234043.tar.gz'
h=hashlib.sha256()
with p.open('rb') as f:
    for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
a=json.loads((R/'acquisition.json').read_text())
assert h.hexdigest()==a['sha256'], 'INTEGRITY MISMATCH'
record={'verified_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sha256':h.hexdigest(),'bytes':p.stat().st_size,'matches_download':True}
(R/'integrity_verification.json').write_text(json.dumps(record,indent=2))
print(json.dumps(record),flush=True)
items=[]
with tarfile.open(p,'r|gz') as t:
    for m in t:
        items.append({'path':m.name,'size':m.size,'mtime':m.mtime,'mode':oct(m.mode),'uid':m.uid,'gid':m.gid,'type':m.type.decode('ascii','replace'),'link':m.linkname})
with (R/'archive_inventory.csv').open('w',newline='',encoding='utf-8') as f:
    w=csv.DictWriter(f,fieldnames=items[0].keys());w.writeheader();w.writerows(items)
summary={'members':len(items),'logical_bytes':sum(m['size'] for m in items),'largest':sorted(items,key=lambda x:x['size'],reverse=True)[:30]}
(R/'archive_summary.json').write_text(json.dumps(summary,indent=2))
print(json.dumps(summary,indent=2),flush=True)
