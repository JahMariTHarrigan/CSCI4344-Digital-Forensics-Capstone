from read_evidence import *
import logging,types,datetime
sys.path.insert(0,str(R/'tools'))
from dissect.target.plugins.os.unix.log.journal import JournalFile
target=types.SimpleNamespace(log=logging.getLogger('journal'))
events=[];report=[]
for i,x in records():
    if '/var/log/journal/' not in x['path']:continue
    count=0
    with (R/'working'/f'{i:05d}.bin').open('rb') as f:
        for n,e in enumerate(JournalFile(f,target),1):
            e['source']=x['path'];e['record']=n
            events.append(e);count+=1
    report.append({'path':x['path'],'records':count})
(R/'analysis/journal_events.json').write_text(json.dumps(events,default=str,indent=2))
(R/'analysis/journal_summary.json').write_text(json.dumps(report,indent=2))
interesting=[e for e in events if re.search(r'sshd|sudo|useradd|userdel|passwd|session opened|session closed|libymv',str(e.get('message','')),re.I) or e.get('syslog_identifier') in ['sudo','sshd','sshd-session']]
interesting.sort(key=lambda e:str(e['ts']))
with (R/'analysis/journal_relevant.txt').open('w',encoding='utf-8') as f:
    for e in interesting:f.write(f"{e['ts']} | {e.get('syslog_identifier','')} | {e.get('pid','')} | {e.get('message','')} | {Path(e['source']).name}#{e['record']}\n")
print(json.dumps(report));print('events',len(events),'relevant',len(interesting))
