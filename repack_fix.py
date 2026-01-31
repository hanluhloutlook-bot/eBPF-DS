import tarfile, json, io, os
src='build0129-docker-tagged.tar'
dst='build0129-docker-fixed.tar'
repo_tag='registry.example.com/myproject/build0129:latest'
# Read members
with tarfile.open(src,'r') as tf:
    members = tf.getmembers()
    contents = {}
    for m in members:
        f = tf.extractfile(m)
        if f is None:
            contents[m.name]=None
        else:
            contents[m.name]=f.read()
# Parse and modify manifest.json
if 'manifest.json' not in contents:
    print('manifest.json not found in archive')
    raise SystemExit(1)
man = json.loads(contents['manifest.json'].decode('utf-8'))
# man is a list; modify first entry RepoTags
if isinstance(man, list) and len(man)>0:
    man[0]['RepoTags']=[repo_tag]
else:
    print('unexpected manifest format')
    raise SystemExit(1)
contents['manifest.json']=json.dumps(man,separators=(',',':')).encode('utf-8')
# Update repositories file if present
if 'repositories' in contents and contents['repositories'] is not None:
    repos = json.loads(contents['repositories'].decode('utf-8'))
    # Use config filename to determine image id
    configname = man[0].get('Config','')
    iid = configname.rsplit('.',1)[0] if '.' in configname else configname
    repo,tag = repo_tag.rsplit(':',1)
    repos[repo]={}
    repos[repo][tag]=iid
    contents['repositories']=json.dumps(repos,separators=(',',':')).encode('utf-8')
# Write new tar
with tarfile.open(dst,'w') as out:
    for m in members:
        data = contents.get(m.name,None)
        ti = tarfile.TarInfo(name=m.name)
        if data is None:
            ti.size = 0
            out.addfile(ti)
        else:
            ti.size = len(data)
            out.addfile(ti, io.BytesIO(data))
print('wrote',dst, 'size', os.path.getsize(dst))
print('manifest preview:', json.dumps(man,indent=2)[:500])
