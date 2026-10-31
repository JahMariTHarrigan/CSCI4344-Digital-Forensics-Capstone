import tarfile,hashlib,json,datetime,shutil
from pathlib import Path
R=Path(__file__).resolve().parent
assert json.loads((R/'integrity_verification.json').read_text())['matches_download']
O=R/'working';O.mkdir(exist_ok=True)
manifest=[]
with tarfile.open(R/'evidence/uac-vbox-linux-20260324234043.tar.gz','r|gz') as t:
    for i,m in enumerate(t):
        if not m.isfile():continue
        dest=O/f'{i:05d}.bin'
        assert not dest.exists(),dest
        h=hashlib.sha256();n=0
        with t.extractfile(m) as src,dest.open('wb') as out:
            while b:=src.read(8*1024*1024):out.write(b);h.update(b);n+=len(b)
        assert n==m.size
        manifest.append({'id':i,'path':m.name,'local':dest.name,'size':n,'sha256':h.hexdigest()})
        if n>100000000: print(m.name,n,flush=True)
(R/'working_manifest.json').write_text(json.dumps(manifest,indent=2))
(R/'extraction_record.json').write_text(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':len(manifest),'bytes':sum(x['size'] for x in manifest),'method':'Regular files only; opaque numbered filenames prevent path traversal, Windows case collisions, and execution. Original paths retained in manifest. Links not materialized. SHA256 of each extracted stream.'},indent=2))
print('Extraction complete',len(manifest),flush=True)
