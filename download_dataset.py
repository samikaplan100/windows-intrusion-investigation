#!/usr/bin/env python3
"""Download and SHA-256 verify the public, authorised OTRF lab dataset."""
from pathlib import Path
import hashlib,os,tempfile,urllib.request
SOURCE='https://raw.githubusercontent.com/OTRF/Security-Datasets/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip'
EXPECTED='96f1dbd9c5b077c8951b6e1f43b7fe01a2620c649889262481f15139a1746d88'
DEST=Path(__file__).resolve().parent/'samples'/'mordor_empire_wmi.zip'
def verified(p):
 h=hashlib.sha256()
 with p.open('rb') as fh:
  for chunk in iter(lambda:fh.read(65536),b''):h.update(chunk)
 return h.hexdigest()==EXPECTED
if __name__=='__main__':
 if DEST.is_file() and verified(DEST):print('Dataset already present and SHA-256 verified');raise SystemExit(0)
 DEST.parent.mkdir(parents=True,exist_ok=True)
 fd,temp=tempfile.mkstemp(prefix='otrf-',suffix='.zip',dir=str(DEST.parent))
 try:
  with os.fdopen(fd,'wb') as fh,urllib.request.urlopen(SOURCE,timeout=40) as res:
   while True:
    chunk=res.read(65536)
    if not chunk:break
    fh.write(chunk)
  staged=Path(temp)
  if not verified(staged):raise RuntimeError('Refused unverified lab dataset: SHA-256 mismatch')
  staged.replace(DEST)
  print('Downloaded and verified',DEST,'bytes',DEST.stat().st_size)
 finally:
  if Path(temp).exists():Path(temp).unlink()
