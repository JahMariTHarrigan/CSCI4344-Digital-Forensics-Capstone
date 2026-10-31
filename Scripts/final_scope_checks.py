from read_evidence import *
out={'examined_on':'2026-10-31','setid_metadata':[],'profile_files':{},'network_artifacts':[]}
for n,l in enumerate(read('bodyfile/bodyfile.txt').splitlines(),1):
 a=l.split('|')
 if len(a)==11 and len(a[3])>=10 and (a[3][3] in 'sS' or a[3][6] in 'sS'):
  out['setid_metadata'].append({'line':n,'path':a[1],'mode':a[3],'uid':a[4],'gid':a[5],'size':a[6]})
for _,x in records():
 p=x['path']
 if re.search(r'^\[root\]/etc/(profile|profile\.d/[^/]+|rc\.local)$',p) and int(x['size'])<30000:out['profile_files'][p]=read(p)
 if re.search(r'resolv|hosts$|dns|suid|sgid',p,re.I):out['network_artifacts'].append(p)
(R/'analysis/final_scope_checks.json').write_text(json.dumps(out,indent=2))
print(json.dumps(out,indent=2))
