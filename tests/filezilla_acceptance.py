#!/usr/bin/env python3
"""Unmodified FileZilla GUI, native queue, pinned fixture certificate, FTPS roundtrip.

All configuration, credentials, queue and files live in the disposable fixture.
Linux needs Xvfb/xdotool; Windows needs pywinauto and an interactive runner desktop.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import subprocess
import time
import traceback
import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from m4_integration import Fixture

SCHEMA='''
PRAGMA user_version=8;
CREATE TABLE servers (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, host TEXT NOT NULL, port INTEGER, user TEXT, password TEXT, account TEXT, keyfile TEXT, protocol INTEGER, type INTEGER, logontype INTEGER, timezone_offset INTEGER, transfer_mode TEXT, max_connections INTEGER, encoding TEXT, bypass_proxy INTEGER, post_login_commands TEXT, name TEXT, parameters TEXT, site_path TEXT DEFAULT NULL);
CREATE TABLE files (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, server INTEGER NOT NULL, source_file TEXT, target_file TEXT, local_path INTEGER, remote_path INTEGER, size INTEGER, error_count INTEGER, priority INTEGER, flags INTEGER, default_exists_action INTEGER, extra_flags TEXT, persistent_state BLOB);
CREATE TABLE local_paths (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, path TEXT NOT NULL);
CREATE TABLE remote_paths (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, path TEXT NOT NULL);
'''

def xmlfile(path,root):
    ET.ElementTree(root).write(path,encoding='utf-8',xml_declaration=True)

def prepare(f,config,local,download,version):
    config.mkdir(parents=True)
    root=ET.Element('FileZilla3');settings=ET.SubElement(root,'Settings')
    for name,value in {'Greeting version':version,'Prompt password save':1,'Number of Transfers':1,
                       'Ascii Binary mode':2,'Update Check':0,'Logging Debug Level':3,
                       'Logging file':str(f.base/'filezilla.log'),'Language Code':'en_US',
                       'Queue completion action':1}.items():
        ET.SubElement(settings,'Setting',name=name).text=str(value)
    xmlfile(config/'filezilla.xml',root)
    cert=x509.load_pem_x509_certificate((f.state/'tls-cert.pem').read_bytes())
    root=ET.Element('FileZilla3');entry=ET.SubElement(ET.SubElement(root,'TrustedCerts'),'Certificate')
    for name,value in {'Data':cert.public_bytes(serialization.Encoding.DER).hex(),
                       'ActivationTime':int(cert.not_valid_before_utc.timestamp()),
                       'ExpirationTime':int(cert.not_valid_after_utc.timestamp()),
                       'Host':'127.0.0.1','Port':f.ftpport,'TrustSANs':0}.items():ET.SubElement(entry,name).text=str(value)
    xmlfile(config/'trustedcerts.xml',root)
    db=sqlite3.connect(config/'queue.sqlite3');db.executescript(SCHEMA)
    db.execute('INSERT INTO servers(id,host,port,user,password,protocol,type,logontype,transfer_mode,max_connections,encoding,bypass_proxy) VALUES(1,?,?,?,?,4,1,1,?,1,?,1)',('127.0.0.1',f.ftpport,'alice',f.password,'passive','UTF-8'))
    db.executemany('INSERT INTO local_paths VALUES(?,?)',[(1,str(local)+os.sep),(2,str(download)+os.sep)])
    db.execute("INSERT INTO remote_paths VALUES(1,'1 0 3 ftp')")
    for ident,lp,flags in [(1,1,0),(2,2,16)]:
        db.execute('INSERT INTO files(id,server,source_file,local_path,remote_path,size,priority,flags) VALUES(?,1,?, ?,1,?,2,?)',(ident,'payload.bin',lp,(local/'payload.bin').stat().st_size,flags))
    db.commit();db.close()
    return cert.fingerprint(hashes.SHA256()).hex()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--filezilla',default=shutil.which('filezilla'))
    p.add_argument('--xvfb',default='Xvfb');p.add_argument('--xdotool',default='xdotool')
    p.add_argument('--display',type=int,help='Explicit isolated X display for WSL with a read-only X11 socket directory')
    a=p.parse_args();assert a.filezilla,'FileZilla executable not found'
    f=Fixture(a.bin);report=dict(status='failed',host=platform.platform());processes=[]
    env=os.environ.copy();env.update(XDG_CONFIG_HOME=str(f.base/'config'),APPDATA=str(f.base/'config'),GDK_BACKEND='x11')
    config=f.base/'config'/('FileZilla' if os.name=='nt' else 'filezilla')
    local=f.base/'upload';download=f.base/'download';local.mkdir();download.mkdir()
    data=bytes(range(251))*4096;(local/'payload.bin').write_bytes(data)
    log=(f.base/'filezilla-stdout.log').open('w')
    try:
        if os.name=='nt':
            # Windows uses the Known Folder API, not the APPDATA environment
            # variable. Keep the installed client and the user's profile intact:
            # run an unchanged copy with FileZilla's documented defaults file.
            installed=Path(a.filezilla).resolve();portable=f.base/'filezilla-client'
            shutil.copytree(installed.parent,portable)
            a.filezilla=str(portable/installed.name)
            defaults=ET.Element('FileZilla3');settings=ET.SubElement(defaults,'Settings')
            ET.SubElement(settings,'Setting',name='Config Location').text=str(config)
            ET.SubElement(settings,'Setting',name='Disable update check').text='1'
            xmlfile(portable/'fzdefaults.xml',defaults)
        if os.name!='nt':
            # Xvfb chooses an unused display and reports it on a private pipe.
            rd,wr=os.pipe()
            selection=[':'+str(a.display)] if a.display is not None else ['-displayfd',str(wr)]
            xvfb=subprocess.Popen([a.xvfb]+selection+['-screen','0','1280x900x24','-nolisten','tcp','-ac'],pass_fds=(wr,),env=env,stdout=log,stderr=log)
            processes.append(xvfb);os.close(wr)
            import select
            if a.display is None:
                assert select.select([rd],[],[],15)[0],'Xvfb did not start'
                display=os.read(rd,64).decode().strip();assert display.isdigit(),'Invalid Xvfb display'
            else:
                display=str(a.display);time.sleep(1);assert xvfb.poll() is None,'Xvfb exited'
            os.close(rd)
            env['DISPLAY']=':'+display
        result=subprocess.run([a.filezilla,'--version'],env=env,capture_output=True,text=True,timeout=20)
        version=re.search(r'FileZilla\s+(\d+\.\d+\.\d+(?:\.\d+)?)',result.stdout+'\n'+result.stderr)
        assert version,'Could not identify FileZilla version'
        report['client']='FileZilla '+version[1]
        report['certificate_sha256']=prepare(f,config,local,download,version[1])
        proc=subprocess.Popen([a.filezilla],env=env,stdout=log,stderr=log);processes.append(proc)
        if os.name=='nt':
            from pywinauto import Application
            app=Application(backend='win32').connect(process=proc.pid,timeout=30)
            window=app.window(title='FileZilla');window.wait('ready',timeout=30)
            window.set_focus();window.type_keys('^p')
        else:
            deadline=time.monotonic()+30
            while True:
                result=subprocess.run([a.xdotool,'search','--onlyvisible','--pid',str(proc.pid),'--name','FileZilla'],env=env,capture_output=True,text=True,timeout=5)
                if result.returncode==0:break
                assert proc.poll() is None,'FileZilla exited before GUI ready'
                if time.monotonic()>deadline:raise RuntimeError('FileZilla window did not appear')
                time.sleep(.2)
            wid=result.stdout.splitlines()[0]
            subprocess.run([a.xdotool,'windowfocus','--sync',wid,'key','ctrl+p'],env=env,check=True,timeout=10)
        deadline=time.monotonic()+90
        while not (download/'payload.bin').exists() or (download/'payload.bin').stat().st_size!=len(data):
            assert proc.poll() is None,'FileZilla exited before transfer completed'
            if time.monotonic()>deadline:raise RuntimeError('FileZilla FTPS queue timed out')
            time.sleep(.2)
        assert (download/'payload.bin').read_bytes()==data
        assert (f.root/'transfer/payload.bin').read_bytes()==data
        report.update(status='passed',protocol='explicit FTPS',payload_bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
                      checks=['pinned disposable server certificate','native GUI queue upload and download','binary source/server/download match'])
    except Exception:report['error']=traceback.format_exc()
    finally:
        # Screenshots and logs are evidence; private client configuration is never published.
        try:
            from PIL import ImageGrab
            a.output.parent.mkdir(parents=True,exist_ok=True)
            ImageGrab.grab(**({'xdisplay':env['DISPLAY']} if os.name!='nt' else {})).save(a.output.with_suffix('.png'))
        except Exception:pass
        for proc in reversed(processes):
            proc.terminate()
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        log.close();f.log.flush()
        for key,name in [('client_log','filezilla.log'),('gui_log','filezilla-stdout.log'),('server_log','supervisor.log')]:
            path=f.base/name
            if path.exists():report[key]=path.read_text(errors='replace')[-32768:].replace(f.password,'<fixture-password>')
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');f.close()
    print(json.dumps({k:v for k,v in report.items() if not k.endswith('_log')},indent=2))
    return int(report['status']!='passed')

if __name__=='__main__':raise SystemExit(main())
