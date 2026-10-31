from read_evidence import *
import mmap,hashlib,struct
expected='0fd709f09c073df274e272aabcabe3e0f3487f9e'
matches=[];candidates=0
with (R/'working/01931.bin').open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
    off=0
    while (off:=mm.find(b'\x7fELF\x02\x01',off))>=0:
        candidates+=1
        b=mm[off:off+24024]
        if hashlib.sha1(b).hexdigest()==expected:
            matches.append({'offset':off,'bytes':24024,'sha1':expected,'sha256':hashlib.sha256(b).hexdigest()})
            out=R/'analysis/recovered_libymv.bin';out.write_bytes(b)
        off+=6
(R/'analysis/library_carving.json').write_text(json.dumps({'ELF_candidates':candidates,'criterion':'24,024-byte contiguous ELF region matching UAC executable SHA1 for libymv.so.3','matches':matches},indent=2))
print('Candidates',candidates,'Matches',matches)
