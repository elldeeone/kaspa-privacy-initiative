import pathlib,hashlib,json,subprocess,sys
old=["/var/tmp/kpi-capacity-public-parameters-a5ce95a4-01","/home/luke/projects/kpi-intensive-2026-10-22/capacity-exit-selected-prover-01","/home/luke/projects/kpi-intensive-2026-10-22/continuation","/home/luke/projects/kpi-intensive-2026-10-22/current-profile-public-distribution-01","/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-public-parameters-01","/home/luke/projects/kpi-intensive-2026-10-22/independent-payment-coldbuild-bundle-03"]
assert all(not pathlib.Path(p).exists() for p in old)
print("SOURCE_ABSENCE "+json.dumps({"probes":len(old),"all_absent":True,"backup_original_PK_selected_prover_or_old_profile_mounted":False}),flush=True)
base=sys.argv[1].rstrip("/")
hosts=["github.com","release-assets.githubusercontent.com","objects.githubusercontent.com","api.github.com"]
flags=[v for h in hosts for v in ("--allowed-host",h)]
command=["/usr/bin/python3","-B","/work/transport/public_fetch.py","--url",base+"/PUBLICATION.json","--expected-bytes","7165","--expected-sha256","95d1168fabcaa2dc7d4dbd3753ed6ced020e5296193a852e6d3fa8aa4ed0f94b","--output","/out/PUBLICATION.json",*flags]
z=subprocess.run(command,capture_output=True,text=True);assert z.returncode==0,"root-pinned-publication-download-incomplete"
print("PUBLICATION_RECEIPT "+z.stdout.strip(),flush=True)
command=["/usr/bin/python3","-B","/work/download.py","--publication","/out/PUBLICATION.json","--expected-publication-sha256","95d1168fabcaa2dc7d4dbd3753ed6ced020e5296193a852e6d3fa8aa4ed0f94b","--release-base",base,"--transport-directory","/work/transport","--output","/out/current-profile",*flags]
z=subprocess.run(command,capture_output=True,text=True);print(z.stdout,flush=True);assert z.returncode==0,"current-profile-byte-retrieval-incomplete"
