#!/usr/bin/env python3
"""Build a NEW bank's programs; compute its real authorization image first."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[2];PACKAGE=pathlib.Path(__file__).resolve().parent
def main():
 p=argparse.ArgumentParser();p.add_argument('profile',choices=['offline','testnet']);p.add_argument('new_output',type=pathlib.Path);a=p.parse_args();out=a.new_output.resolve();out.mkdir();(out/'programs').mkdir()
 target=ROOT/'.local/ci-target';env=dict(os.environ,CARGO_TARGET_DIR=str(target),RAYON_NUM_THREADS='4',OMP_NUM_THREADS='4');features=['--no-default-features','--features',a.profile]
 def build(component,guest=False):
  e=env.copy();args=['cargo','+1.97.1','build','--locked','--release','--manifest-path',str(PACKAGE/component/'Cargo.toml'),*features]
  if guest:
   e.update(RISC0_FEATURE_bigint2='1',RUSTC='/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools/risc0-rust/bin/rustc',RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"');args+=['--target','riscv32im-risc0-zkvm-elf']
  subprocess.run(args,env=e,check=True)
 build('host');host=out/'host';shutil.copy2(target/'release/kpi-cached-approval-verification',host)
 build('authorization-guest',True)
 image=subprocess.check_output([str(host),'wrap',str(target/'riscv32im-risc0-zkvm-elf/release/kpi-cached-authorization-guest'),str(out/'programs/authorization.bin')],text=True).strip()
 pin=PACKAGE/('pins' if a.profile=='offline' else 'testnet-pins')/'authorization-image.bin';pin.write_bytes(bytes.fromhex(image))
 build('settlement-guest',True)
 settlement=subprocess.check_output([str(host),'wrap',str(target/'riscv32im-risc0-zkvm-elf/release/kpi-cached-settlement-guest'),str(out/'programs/settlement.bin')],text=True).strip()
 files={str(f.relative_to(PACKAGE)):hashlib.sha256(f.read_bytes()).hexdigest() for f in PACKAGE.rglob('*') if f.is_file() and '__pycache__' not in f.parts}
 (out/'BUILD.json').write_text(json.dumps({'profile':a.profile,'authorizationImage':image,'settlementImage':settlement,'sourceSha256':files,'newBankRequired':True},indent=2)+'\n');print('New bank programs:',out)
if __name__=='__main__':main()
