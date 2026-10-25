// Whole-byte public admission through the root's metadata-only private exclusions.
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import crypto from 'node:crypto';
export function guardedRead(file, expected) {
  if(!fs.existsSync('/var/tmp/kpi-root-guard-helper-09.py')) {
    // This branch is for finite, network-disabled owner sandboxes only.
    const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
    try {
      const before=fs.fstatSync(fd,{bigint:true});
      if(!before.isFile()||before.nlink!==1n)throw new Error('finite public file type');
      const raw=fs.readFileSync(fd),after=fs.fstatSync(fd,{bigint:true});
      if(!['dev','ino','size','mtimeNs','ctimeNs'].every(key=>before[key]===after[key])
          ||BigInt(raw.length)!==before.size)throw new Error('finite public file changed');
      if(expected&&crypto.createHash('sha256').update(raw).digest('hex')!==expected)
        throw new Error('finite public file pin');
      return raw;
    }finally{fs.closeSync(fd);}
  }
  const args=['-B','-c',"import runpy,sys;sys.stdout.buffer.write(runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](sys.argv[1],sys.argv[2] or None))",file,expected??''];
  const result=spawnSync('/usr/bin/python3',args,{env:{PATH:'/usr/bin:/bin'},maxBuffer:512*1024*1024});
  if(result.error||result.status!==0)throw new Error('selected public read refused');
  return result.stdout;
}
