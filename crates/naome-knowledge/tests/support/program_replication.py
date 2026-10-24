#!/usr/bin/env python3
"""Autonomous generation, authenticated transfer, receiver crash and replay.

Two ordinary nodes use separate OS sessions, identities, directories and ports.
Only lifecycle/status operations drive them. The deterministic provider uses
the same supervised candidate stream and mathematical checker as other providers.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import time
from autonomous_lifecycle import Node, Trial, process_group, process_identity, write_receipt
from proof_network import stored_objects


class AutonomousNode(Node):
    def start(self, strict_startup=False):
        # Exercise the ordinary dynamic default; no operator profile is needed.
        self.event_offset=len(self.logs())
        self.release_port()
        result=self.trial.start(self,strict_startup=strict_startup)
        self.capture_process()
        event=self.trial.wait(lambda:next((event for event in self.logs()[self.event_offset:]
            if event.get('event')=='starting'),None))
        if self.peer is not None:assert self.peer==event['peer_id']
        self.peer=event['peer_id']
        return result


def program_rows(node):
    path=node.directory/'proof-corpus.sqlite3'
    if not path.exists():return []
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=1) as connection:
        return [{'id':identity.hex(),'manifest':json.loads(manifest),'received':received,
            'published':bool(published)} for identity,manifest,received,published in connection.execute(
            'SELECT id,manifest,received,EXISTS(SELECT 1 FROM proofs WHERE proofs.id=programs.id) FROM programs ORDER BY id')]


def resources(trial,node):
    result=subprocess.run([str(trial.binary),'--json','resources'],capture_output=True,text=True,
        env={**os.environ,'NAOME_NODE_DIR':str(node.directory)},timeout=trial.remaining())
    assert result.returncode==0,result.stderr
    value=json.loads(result.stdout)
    assert value['configured']['profile']=='dynamic'
    return value


def run(trial,units):
    donor,receiver=AutonomousNode(trial,0),AutonomousNode(trial,1)
    donor.config['runtime']['jobs']={'solving':{'limits':{'horizon_ms':max(120000,units*1000),'work_units':units+16},
        'mock':{'program_units':units}}}
    for node in (donor,receiver):node.write_config();node.start();node.stop()
    assert donor.peer!=receiver.peer and donor.port!=receiver.port
    assert donor.directory.resolve()!=receiver.directory.resolve()
    for node,other in ((donor,receiver),(receiver,donor)):
        node.config['peers']=[{'id':other.peer,'address':f'/ip4/127.0.0.1/tcp/{other.port}'}]
    donor.config['runtime']['question_interval_ms']=100
    donor.write_config();receiver.write_config();donor.start()
    published=trial.wait(lambda:next((row for row in program_rows(donor) if row['published']),None),maximum=trial.remaining(600))
    identity=published['id'];manifest=published['manifest']
    assert manifest['commands']==units*128 and manifest['input_bytes']>65536
    trial.wait(lambda:any(event.get('event')=='accepted' and event.get('id')==identity
        and event.get('source')=='mock_producer' for event in donor.logs()))
    receiver.start()
    prefix=trial.wait(lambda:next((row for row in program_rows(receiver)
        if row['id']==identity and 0<row['received']<manifest['commands']),None),maximum=trial.remaining(60))
    assert process_identity(receiver.process['pid'])==receiver.process
    os.kill(receiver.process['pid'],signal.SIGKILL)
    trial.wait(lambda:not process_group(receiver.process),maximum=10)
    after=next(row for row in program_rows(receiver) if row['id']==identity)
    assert prefix['received']<=after['received']<manifest['commands'] and not after['published']
    assert (donor.directory/'proof-corpus.sqlite3').stat().st_ino!=(receiver.directory/'proof-corpus.sqlite3').stat().st_ino
    write_receipt(trial.output/'interrupted-prefix.json',{'before_kill':prefix,'after_kill':after})
    receiver.start()
    event_start=len(receiver.logs())
    trial.wait(lambda:next((row for row in program_rows(receiver) if row['id']==identity and row['published']),None),maximum=trial.remaining(600))
    trial.wait(lambda:any(event.get('event')=='accepted' and event.get('id')==identity
        and event.get('source')=='fetch' for event in receiver.logs()[event_start:]))
    resumed=[event for event in receiver.logs()[receiver.event_offset:]
        if event.get('event')=='exchange_response' and event.get('kind')=='program_data' and event.get('object_id')==identity]
    assert resumed and resumed[0]['position']==after['received'],resumed[:1]
    source_objects=stored_objects(donor);received_objects=stored_objects(receiver)
    assert next(value for value in source_objects if value['proof_id']==identity)==next(value for value in received_objects if value['proof_id']==identity)
    snapshot=resources(trial,receiver)
    receiver.stop();before=set(receiver.ids())
    work=(receiver.directory/'.program-work'/f'{identity}.sqlite3').resolve()
    with sqlite3.connect(work.as_uri()+'?mode=ro&immutable=1',uri=True) as connection:
        commands,committed,sealed=connection.execute('SELECT commands,committed,sealed FROM state WHERE id=1').fetchone()
        assert commands==committed==manifest['commands'] and sealed
        assert connection.execute('SELECT count(*) FROM node').fetchone()[0]>256
    receiver.start()
    assert receiver.ids()==before and identity in before
    assert trial.call(receiver,'status')['accepted_proofs']==len(before)
    trial.summary.update(result='pass',fixture='autonomous_program_replication',program=published,
        receiver_prefix_at_restart=after['received'],receiver_first_resumed_position=resumed[0]['position'],
        receiver_work_database_bytes=work.stat().st_size,receiver_resources=snapshot,
        source='autonomous supervised deterministic provider',
        claim='two isolated ordinary node processes on one host, real loopback libp2p transfer, independent complete receiver checking and restart replay; no physical multi-host or NAT claim')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--units',type=int,default=64)
    parser.add_argument('--timeout',type=float,default=240)
    parser.add_argument('--profile',default='test')
    args=parser.parse_args()
    assert 8<args.units<4096
    trial=Trial(args.binary,args.output,args.timeout,args.profile,'program-replication')
    trial.cleanup_timeout=20
    try:
        run(trial,args.units)
    except BaseException as error:
        trial.summary.update(result='fail',error=f'{type(error).__name__}: {error}')
        raise
    finally:
        trial.close()
        write_receipt(trial.output/'result.json',trial.summary)
    assert trial.summary['result']=='pass',trial.summary


if __name__=='__main__':main()
