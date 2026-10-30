#!/usr/bin/env python3
"""Disposable loopback Linux server fixture for a macOS client over SSH tunnels."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import threading
from m3_integration import Fixture

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--uid',type=int,required=True);p.add_argument('--groups',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();f=Fixture(Path('bin'));stop=threading.Event()
    signal.signal(signal.SIGTERM,lambda *_:stop.set())
    signal.signal(signal.SIGINT,lambda *_:stop.set())
    try:
        f.stop();ports=[]
        for _ in range(2):
            with socket.socket() as s:s.bind(('127.0.0.1',0));ports.append(s.getsockname()[1])
        cfg=json.loads((f.state/'config.json').read_text());cfg.update(smb_port=ports[0],nfs_port=ports[1])
        (f.state/'config.json').write_text(json.dumps(cfg));f.start()
        for protocol in ('smb','nfs'):
            f.api('spaces',f.admin,dict(id=protocol+'data',root='data',path=protocol+'data',owner='alice',quota=2**31))
            f.api('shares',f.admin,dict(id=protocol,space=protocol+'data',exposures={protocol:'rw'}))
        f.api('smb/credentials',f.admin,dict(username='alice',password=f.password))
        f.api('groups',f.admin,dict(name='unix'))
        f.api('memberships',f.admin,dict(username='alice',group='unix'))
        f.api('grants',f.admin,dict(space='nfsdata',subject_type='user',subject='bob',rights='rw'))
        f.api('nfs-exports',f.admin,dict(id='nfs',trust='loopback-auth-sys',anonymous='bob',
                 uids={str(a.uid):'alice'},gids={str(g):'unix' for g in json.loads(a.groups)}))
        a.output.write_text(json.dumps(dict(pid=os.getpid(),smb_port=ports[0],nfs_port=ports[1])))
        stop.wait(1200)
    finally:
        f.log.flush();Path('server.log').write_text((f.base/'supervisor.log').read_text()[-65536:]);f.close()

if __name__=='__main__':main()
