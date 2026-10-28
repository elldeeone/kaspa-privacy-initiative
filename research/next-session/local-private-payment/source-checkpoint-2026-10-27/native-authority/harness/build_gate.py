"""SOURCE ONLY: prospective one-identity offline build. Not executed/imported.
Requires Root-selected source freeze/resource scope and a separate execution GO.
Never starts a run, proof, setup or financial operation; never repairs a failure.
"""
import argparse,hashlib,json,os,resource,runpy,stat,subprocess,time
from pathlib import Path
BASE=Path('/var/tmp/kpi-nativeauthspend-preparation-vyqdmzti')
BUILD=Path('/var/tmp/kpi-nativeauthspend-work-01/build-01')
H=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
def need(v,c):
    if not v:raise ValueError(c)
def read(p,sha=None):return H['read'](str(p),sha)
def enc(v):return (json.dumps(v,indent=2)+'\n').encode()
def save(name,raw):
    p=BUILD/name
    with p.open('xb')as f:f.write(raw)
    b=read(p);return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--freeze',required=True);ap.add_argument('--freeze-sha256',required=True);a=ap.parse_args()
    freeze=json.loads(read(a.freeze,a.freeze_sha256));need(freeze['status']=='SOURCE_ONLY_UNCOMPILED_UNEXECUTED','SOURCE_STATUS')
    for x in freeze['files']:
        p=Path(x['path']);need(not p.is_absolute()and '..'not in p.parts,'SOURCE_PATH');b=read(BASE/p,x['sha256']);need(len(b)==x['bytes'],'SOURCE_LENGTH')
    tool=json.loads(read(BASE/'TOOL-SELECTION-02.json'))
    for x in tool['public_tools']:
        b=read(x['path'],x['sha256']);need(len(b)==x['bytes'],'TOOL_LENGTH')
    c=json.loads(read(BASE/'COMMANDS-02.json'));need(c['build_root']==str(BUILD),'BUILD_ROOT');need(not BUILD.exists(),'FRESH_BUILD_ID_REQUIRED')
    parent=BUILD.parent
    if not parent.exists():parent.mkdir(mode=0o700)
    st=parent.stat();need(st.st_uid==os.getuid()and stat.S_IMODE(st.st_mode)==0o700,'PARENT_OWNER_MODE');BUILD.mkdir(mode=0o700)
    for n in ['cargo','ordinary','cpp0']:(BUILD/n).mkdir(mode=0o700)
    save('BUILD-START-01.json',enc({'schema':'kpi-nativeauth-build-start/v1','sourceFreezeSha256':a.freeze_sha256,'startedUnixSeconds':time.time(),'status':'USED_IDENTITY_DO_NOT_RETRY'}));events=[]
    try:
        for label in ['native','ordinary','cpp0','make']:
            argv=c['build'][label];start=time.time();r=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            event={'label':label,'argv':argv,'returncode':r.returncode,'elapsedSeconds':time.time()-start,'stdout':save(label+'.stdout',r.stdout),'stderr':save(label+'.stderr',r.stderr)};events.append(event);need(r.returncode==0,'FIRST_BUILD_FAILURE:'+label)
        artifacts={};held=[]
        for label,rel in {'nativeBinary':'target/release/kpi-nativeauthspend-seam','cppBinary':'cpp0/private_authorization_cpp/private_authorization','cppDat':'cpp0/private_authorization_cpp/private_authorization.dat','ordinaryR1cs':'ordinary/private_authorization.r1cs','cpp0R1cs':'cpp0/private_authorization.r1cs','sym':'ordinary/private_authorization.sym'}.items():
            p=BUILD/rel;st=p.lstat();need(stat.S_ISREG(st.st_mode)and st.st_uid==os.getuid(),'ARTIFACT_TYPE_OWNER');v={'path':str(p),'bytes':st.st_size,'dev':st.st_dev,'inode':st.st_ino,'nlink':st.st_nlink,'mode':oct(stat.S_IMODE(st.st_mode)),'uid':st.st_uid}
            if st.st_nlink!=1:held.append(v)
            else:b=read(p);v['sha256']=hashlib.sha256(b).hexdigest()
            artifacts[label]=v
        if held:
            aliases=[]
            for entry in os.scandir(BUILD/'target/release/deps'):
                st=entry.stat(follow_symlinks=False)
                if any(st.st_dev==x['dev']and st.st_ino==x['inode']for x in held):aliases.append({'path':entry.path,'dev':st.st_dev,'inode':st.st_ino,'nlink':st.st_nlink,'uid':st.st_uid,'bytes':st.st_size,'mode':oct(stat.S_IMODE(st.st_mode))})
            save('BINARY-ADMISSION-HELD-01.json',enc({'status':'NO_HARDLINK_BODY_READ_NO_RUN','held':held,'ownedCargoAliasesMetadataOnly':aliases}))
        save('BUILD-RESULT-01.json',enc({'schema':'kpi-nativeauth-build-result/v1','status':'BUILT_PENDING_ROOT_POSTBUILD_SELECTION'if not held else 'BUILT_BINARY_ADMISSION_HELD','sourceFreezeSha256':a.freeze_sha256,'events':events,'artifacts':artifacts,'childMaxRssKiB':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'runtimeExecuted':False,'noSetupProofPkMpcNativeFinancialJobs':True}))
    except BaseException as e:save('FIRST-BUILD-FAILURE-01.json',enc({'status':'STOP_FIRST_FAILURE','type':type(e).__name__,'message':str(e),'events':events}));raise
if __name__=='__main__':main()
