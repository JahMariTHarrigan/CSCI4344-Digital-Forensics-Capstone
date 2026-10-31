import csv,json,sys,gzip,re
from pathlib import Path
R=Path(__file__).resolve().parent
INV=list(csv.DictReader((R/'archive_inventory.csv').open(encoding='utf-8')))
def records():
    for i,x in enumerate(INV):
        if x['type']=='0':yield i,x
def data(path):
    i,x=next((i,x) for i,x in records() if x['path']==path)
    p=R/'working'/f'{i:05d}.bin'
    assert p.stat().st_size==int(x['size']), 'not fully extracted'
    b=p.read_bytes()
    return gzip.decompress(b) if path.endswith('.gz') else b
def read(path):return data(path).decode('utf-8','replace')
if __name__=='__main__':
    if sys.argv[1]=='list':
        for i,x in records():
            if re.search(sys.argv[2],x['path']):print(i,x['size'],x['path'])
    else:
        s=read(sys.argv[1]);pat=sys.argv[2] if len(sys.argv)>2 else None
        for i,l in enumerate(s.splitlines(),1):
            if not pat or re.search(pat,l,re.I):print(f'{i}: {l}')
