from read_evidence import *
import datetime,hashlib,collections
out={}
out['shadow']=[{'account':a[0],'password_state':('locked' if a[1].startswith(('!','*')) else 'hash present' if a[1] else 'empty'),'last_change_days':a[2]} for l in read('[root]/etc/shadow').splitlines() if len(a:=l.split(':'))>=3]
paths=[x['path'] for _,x in records()]
out['histories']=[p for p in paths if re.search(r'/(\.bash_history|\.zsh_history|authorized_keys)$',p)]
out['ssh_config_includes']=[p for p in paths if '/sshd_config.d/' in p]
out['cron_files']={p:read(p) for p in paths if re.search(r'\[root\]/etc/(cron\.[^/]+/[^/]+|crontab)$',p) and int(next(x['size'] for _,x in records() if x['path']==p))<40000}
out['startup_files']={p:read(p) for p in paths if re.search(r'\[root\]/(root|home/worker)/\.(bashrc|profile)$',p)}
out['suspicious_service_hits']=[]
for p in paths:
    if '/systemd/' not in p:continue
    b=data(p)
    if b'\0' in b:continue
    s=b.decode('utf-8','replace')
    for n,l in enumerate(s.splitlines(),1):
        if re.search(r'libymv|/dev/shm/kit|xmrig|192\.168\.5\.95|127\.0\.0\.1:3333',l,re.I):out['suspicious_service_hits'].append([p,n,l])
out['bodyfile_selected']=[]
for n,l in enumerate(read('bodyfile/bodyfile.txt').splitlines(),1):
    a=l.split('|')
    if len(a)!=11:continue
    if re.search(r'libymv|ld.so.preload|/home/worker/\.bash_history|/etc/sudoers.d/10-workers-rule|/tmp/silly|/dev/shm($|/)|/etc/(passwd|shadow)$',a[1]):
        out['bodyfile_selected'].append({'line':n,'raw':l,'times_utc':{k:datetime.datetime.fromtimestamp(int(a[i]),datetime.timezone.utc).isoformat() if int(a[i]) else None for i,k in [(7,'atime'),(8,'mtime'),(9,'ctime'),(10,'birthtime')]}})
(R/'analysis/persistence_account_checks.json').write_text(json.dumps(out,indent=2))
print(json.dumps({k:v for k,v in out.items() if k not in ['cron_files','startup_files']},indent=2))
