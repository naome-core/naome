#!/usr/bin/env python3
"""Finite ordinary-node jobs, control, peer admission and restart qualification."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

from autonomous_lifecycle import (Node,Trial,digest,process_identity,process_group,
    process_cpu_sample,retain_evidence,write_receipt,wait_until)


def journal(node):
    path=node.directory/'research/jobs.json'
    return json.loads(path.read_text())['payload'] if path.exists() else None


def lane(record):
    kind=record['input']['role']
    return 0 if kind=='find' else 1 if kind=='solve' else 3 if record['input'].get('root') else 2


def job_settings(**roles):
    result={}
    for name,values in roles.items():
        result[name]={'limits':{'horizon_ms':values.pop('horizon_ms',60000),
            'work_units':values.pop('work_units',64)},'mock':values}
    return result


class Probe:
    def __init__(self,trial):
        self.trial=trial
        self.started=time.monotonic()
        self.identities={}
        self.seen=set()
        self.samples=[]
        write_receipt(self.trial.output/'research-processes.json',[])
        self.peaks={'processes':0,'rss_kib':0,'cpu_percent':0.0,'journal_bytes':0,'records':0,'accounts':0}

    def observe(self,node):
        for event in node.logs():
            if event.get('event') not in {'research_started','research_worker','research_descendant'}:
                continue
            key=(node.index,event['event'],event['job'],event['pid'])
            if key in self.seen:continue
            self.seen.add(key)
            identity=process_identity(event['pid'])
            if identity is not None and str(self.trial.binary) in identity['command'] and '--research-' in identity['command']:
                assert len(self.identities)<256,'finite process receipt capacity'
                self.identities[tuple(identity['kernel_birth'])+(identity['pid'],)]=identity
        write_receipt(self.trial.output/'research-processes.json',list(self.identities.values()))
        state=journal(node)
        if state:
            assert len(state['records'])<=96 and len(state['accounts'])<=256
            self.peaks['records']=max(self.peaks['records'],len(state['records']))
            self.peaks['accounts']=max(self.peaks['accounts'],len(state['accounts']))
            size=(node.directory/'research/jobs.json').stat().st_size
            assert size<=64*1024*1024
            self.peaks['journal_bytes']=max(self.peaks['journal_bytes'],size)
        pids={identity['pid'] for identity in self.identities.values()}
        pids.update(n.process['pid'] for n in self.trial.nodes if n.process)
        result=subprocess.run(['ps','-A','-o','pid=,rss=,%cpu='],capture_output=True,text=True,timeout=2,check=True)
        rows=[line.split() for line in result.stdout.splitlines()]
        selected=[row for row in rows if len(row)==3 and int(row[0]) in pids]
        self.peaks['processes']=max(self.peaks['processes'],len(selected))
        self.peaks['rss_kib']=max(self.peaks['rss_kib'],sum(int(row[1]) for row in selected))
        self.peaks['cpu_percent']=max(self.peaks['cpu_percent'],sum(float(row[2]) for row in selected))
        sample={'elapsed_seconds':time.monotonic()-self.started if hasattr(self,'started') else 0,
            'node':node.index,'rows':[{'pid':int(row[0]),'rss_kib':int(row[1]),'cpu_percent':float(row[2])} for row in selected],
            'record_count':len(state['records']) if state else 0,'account_count':len(state['accounts']) if state else 0,
            'journal_bytes':size if state else 0}
        assert len(self.samples)<512,'finite resource sample capacity'
        self.samples.append(sample);write_receipt(self.trial.output/'resource-samples.json',self.samples)
        return state

    def cpu_active(self,node):
        active={}
        for event in node.logs():
            if event.get('event')=='research_working':active[event['job']]=event['phase']
        return {job for job,phase in active.items() if phase=='cpu_active'
            and str(job) in journal(node)['records'] and journal(node)['records'][str(job)]['state']=='running'}

    def witness_cpu(self,node):
        jobs=self.trial.wait(lambda:self.cpu_active(node),maximum=5)
        workers={event['pid'] for event in node.logs() if event.get('event')=='research_worker' and event['job'] in jobs}
        identities={pid:process_identity(pid) for pid in workers}
        assert identities and all(identities.values()),'CPU witness requires live worker identities'
        def samples():
            return {pid:process_cpu_sample(identity) for pid,identity in identities.items()}
        before=samples()
        receipt={'jobs':sorted(jobs),'worker_identities':list(identities.values()),'before_samples':before,
            'before_cpu_seconds':{pid:sample['cpu_seconds'] for pid,sample in before.items()}}
        path=self.trial.output/f'cpu-witness-node-{node.index}.json'
        write_receipt(path,receipt)
        latencies=self.statuses(node,2);time.sleep(.15);after=samples()
        receipt.update(after_samples=after,status_seconds=latencies,
            after_cpu_seconds={pid:sample['cpu_seconds'] for pid,sample in after.items()},
            measurement_source='linux_proc_stat_ticks' if sys.platform=='linux' else 'darwin_ps_time_fractional')
        write_receipt(path,receipt)
        assert any(after[pid]['cpu_seconds']>sample['cpu_seconds'] for pid,sample in before.items()),'no positive worker CPU-time delta'
        self.observe(node)
        return jobs

    def remaining(self,identities=None):
        groups={value['group'] for value in (identities or self.identities.values())}
        result=subprocess.run(['ps','-A','-o','pid=,pgid=,command='],capture_output=True,text=True,timeout=2,check=True)
        return [line.strip() for line in result.stdout.splitlines()
            if len(line.split(None,2))==3 and int(line.split(None,2)[1]) in groups]

    def ended(self,identities=None):
        wait_until(lambda:not self.remaining(identities),time.monotonic()+self.trial.remaining(5))

    def statuses(self,node,count):
        def one(_):
            started=time.monotonic();status=self.trial.call(node,'status')
            assert status['running'];return time.monotonic()-started
        with ThreadPoolExecutor(max_workers=count) as pool:
            values=list(pool.map(one,range(count)))
        assert max(values)<2.5,values
        return values

    def crash(self,node):
        self.observe(node)
        retained=list(self.identities.values())
        assert process_identity(node.process['pid'])==node.process
        os.kill(node.process['pid'],signal.SIGKILL)
        self.trial.wait(lambda:not process_group(node.process),maximum=5)
        self.ended(retained)
        return retained


def roles(trial,probe):
    receiver,donor=Node(trial,0),Node(trial,1)
    receiver.config['runtime'].update(jobs=job_settings(
        finding={'step_ms':300},interest={'step_ms':400},solving={'cpu_ms':20000,'descendant':True}))
    # Establish ordinary identities with the same persisted job settings, then
    # configure both static peer policies before admitting any research work.
    for node in [receiver,donor]:node.write_config();node.start();node.stop()
    receiver.config['peers']=[{'id':donor.peer,'address':f'/ip4/127.0.0.1/tcp/{donor.port}'}]
    receiver.config['runtime']['question_interval_ms']=100
    receiver.write_config();receiver.start()
    def overlapping():
        state=journal(receiver)
        running={lane(record) for record in state['records'].values() if record['state']=='running'}
        return state if {0,1,2}.issubset(running) else None
    overlap=trial.wait(overlapping,maximum=15)
    probe.witness_cpu(receiver)
    trial.summary['overlap']={'running_lanes':sorted({lane(r) for r in overlap['records'].values() if r['state']=='running'}),
        'journal_sha256':digest(receiver.directory/'research/jobs.json')}
    trial.summary['pending_status_seconds']=probe.statuses(receiver,4)
    # Wait for stable admitted obligations before introducing peer graph changes.
    trial.wait(lambda:sum(event.get('event')=='question_assessed' and event.get('formal_pass')
        and event.get('interest')=='Assessed(true)' for event in receiver.logs())>=3,maximum=12)
    donor.config['runtime']['question_interval_ms']=100
    donor.config['peers']=[{'id':receiver.peer,'address':f'/ip4/127.0.0.1/tcp/{receiver.port}'}]
    donor.write_config();donor.start()
    def all_peer_answers():
        stored=receiver.ids()
        accepted={event['id'] for event in receiver.logs() if event.get('event')=='accepted' and event.get('source')=='fetch'}
        return len(stored)==3 and stored==donor.ids() and accepted==stored
    trial.wait(all_peer_answers,maximum=20)
    assert any(event.get('event')=='solve_cancelled_by_answer' for event in receiver.logs())
    accepted={event['id'] for event in receiver.logs() if event.get('event')=='accepted' and event.get('source')=='fetch'}
    assert accepted==receiver.ids(),'peer answers must arrive during pending local solving'
    probe.observe(receiver);probe.observe(donor)
    endpoint=json.loads((receiver.directory/'control.json').read_text())
    slow=[]
    try:
        for _ in range(8):
            client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(2)
            client.connect(endpoint['socket']);client.sendall(b'{');slow.append(client)
        trial.summary['slow_control_status_seconds']=probe.statuses(receiver,1)
        started=time.monotonic();receiver.stop();elapsed=time.monotonic()-started
        assert elapsed<5,elapsed
        trial.summary['stop_seconds']=elapsed
    finally:
        for client in slow:client.close()
    donor.stop();probe.ended()
    busy=Node(trial,2)
    busy.config['runtime'].update(question_interval_ms=100,jobs=job_settings(finding={'steps':0,'cpu_ms':20000,'descendant':True}))
    busy.write_config();busy.start();probe.witness_cpu(busy)
    assert probe.cpu_active(busy)
    started=time.monotonic();busy.stop();assert time.monotonic()-started<5
    probe.ended()
    trial.summary['scenarios']['independent_roles_real_peer_answers_slow_controls_and_group_cleanup']={'result':'pass'}


def recovery(trial,probe):
    node=Node(trial,0)
    node.config['runtime'].update(question_interval_ms=100,jobs=job_settings(finding={'step_ms':800,'steps':4,'descendant':True,'work_units':6}))
    node.write_config();node.start()
    first=trial.wait(lambda:next((r for r in journal(node)['records'].values() if r['input']['role']=='find' and r['checkpoint']>=1),None),maximum=8)
    probe.crash(node)
    node.start()
    restored=trial.wait(lambda:next((r for r in journal(node)['records'].values() if r['id']==first['id'] and r['checkpoint']>=2),None),maximum=8)
    assert restored['created_ms']==first['created_ms'] and restored['expires_ms']==first['expires_ms']
    assert restored['reserved_units']>=first['reserved_units'] and restored['spent_ms']>=first['spent_ms']
    assert restored['configuration']==first['configuration'] and restored['binding']==first['binding']
    probe.observe(node);node.stop();probe.ended()
    trial.summary['resumed_job']={'id':restored['id'],'before_checkpoint':first['checkpoint'],'after_checkpoint':restored['checkpoint'],
        'reserved_before':first['reserved_units'],'reserved_after':restored['reserved_units'],'original_expires_ms':first['expires_ms']}
    # An independently CPU-blocked provider and TERM-ignoring descendant must
    # terminate through lifelines after abrupt loss of only the daemon process.
    cpu=Node(trial,1)
    cpu.config['runtime'].update(question_interval_ms=100,jobs=job_settings(finding={'steps':0,'cpu_ms':15000,'descendant':True}))
    cpu.write_config();cpu.start()
    trial.wait(lambda:any(event.get('event')=='research_descendant' for event in cpu.logs()),maximum=5)
    trial.wait(lambda:any(r['reserved_units']==1 and r['state']=='running' for r in journal(cpu)['records'].values()),maximum=5)
    probe.crash(cpu);cpu.start();probe.observe(cpu);cpu.stop();probe.ended()
    trial.summary['scenarios']['crash_resume_preserves_identity_progress_budgets_and_kills_cpu_descendants']={'result':'pass'}


def limits(trial,probe):
    for index,outcome in enumerate(['failed','malformed','wrong_target']):
        node=Node(trial,index)
        node.config['runtime'].update(question_interval_ms=100,jobs=job_settings(solving={'outcome':outcome,'work_units':2}))
        node.write_config();node.start()
        expected='proof_candidate_rejected' if outcome!='failed' else 'solve_obligation_held_or_expired'
        trial.wait(lambda:any(event.get('event')==expected for event in node.logs()),maximum=12)
        assert not node.ids()
        probe.observe(node);assert trial.call(node,'status')['accepted_proofs']==0
        node.stop();probe.ended()
    node=Node(trial,3)
    node.config['runtime'].update(question_interval_ms=100,jobs=job_settings(finding={'steps':3,'work_units':2}))
    node.write_config();node.start()
    expired=trial.wait(lambda:next((r for r in journal(node)['records'].values() if r['state']=='expired'),None),maximum=5)
    assert expired['reserved_units']==2 and expired['checkpoint']==2
    assert not node.ids();probe.observe(node);node.stop();probe.ended()
    def rejected_start(case,expected):
        # A stopped Node reserves its former listen port. Release our fixture
        # socket so the intended research-state rejection cannot be masked by
        # an earlier transport bind failure.
        offset=len(node.logs());node.release_port()
        try:
            trial.call(node,'start',success=False)
            events=node.logs()[offset:]
            failures=[e for e in events if e.get('event')=='fatal_error']
            assert len(failures)==1 and expected in failures[0].get('error',''),(case,failures)
            assert not any(e.get('event') in {'research_started','research_worker','research_descendant'} for e in events)
            assert not trial.call(node,'status')['running']
            trial.summary.setdefault('startup_rejections',[]).append({'case':case,
                'expected_error':expected,'fatal_error':failures[0]['error'],'research_process_started':False})
        finally:
            endpoint=node.directory/'control.json'
            if endpoint.exists():
                identity=process_identity(json.loads(endpoint.read_text())['pid'])
                if identity and str(trial.binary) in identity['command'] and '--research-' not in identity['command']:
                    # Preserve ownership if a regression unexpectedly admitted
                    # the failed-start candidate; stop it before restoring state.
                    node.event_offset=offset;node.capture_process()
                    try:node.stop(cleanup=True)
                    except BaseException:
                        node.emergency_cleanup()
                        raise
            node.reserve_port()
    def restore_state(action):
        assert not process_group(node.process),'refusing state restoration while the recorded daemon group remains'
        action()
    path=node.directory/'research/jobs.json';original=path.read_bytes()
    path.write_bytes(b'{corrupt')
    try:rejected_start('corrupt_journal','research checkpoint corruption:')
    finally:restore_state(lambda:path.write_bytes(original))
    saved_journal=node.directory/'saved-journal';path.rename(saved_journal)
    try:rejected_start('missing_journal','research journal is missing; refusing a fresh allowance')
    finally:restore_state(lambda:saved_journal.rename(path))
    slot=node.directory/'research/slot-0.lock';saved=node.directory/'saved-slot'
    slot.rename(saved)
    try:rejected_start('missing_slot','research slot-0 unavailable:')
    finally:restore_state(lambda:saved.rename(slot))
    research=node.directory/'research';backup=node.directory/'saved-research';research.rename(backup)
    try:rejected_start('missing_research_directory','established research directory is missing; no fresh allowance')
    finally:restore_state(lambda:backup.rename(research))
    write_receipt(trial.output/'research-startup-rejection-witness.json',trial.summary['startup_rejections'])
    trial.summary['scenarios']['malformed_failed_wrong_target_budget_and_corrupt_missing_recovery']={'result':'pass'}


def faults(trial,probe):
    # This process regression belongs beside the serialized native consumers.
    # ProviderClosed is EOF after the ordinary worker has exited; the supervisor
    # must reap that completed leader and confirm cleanup before delivering it.
    completed=Node(trial,3)
    completed.config['runtime'].update(question_interval_ms=100,jobs=job_settings(finding={'step_ms':500}))
    completed.write_config();completed.start()
    launched=trial.wait(lambda:next((e for e in completed.logs() if e.get('event')=='research_worker'),None),maximum=5)
    probe.observe(completed)
    job=launched['job']
    ids={e['pid'] for e in completed.logs() if e.get('job')==job and e.get('event') in {'research_started','research_worker'}}
    retained=[identity for identity in probe.identities.values() if identity['pid'] in ids]
    assert len(retained)==2,'completed provider identities missing'
    finished=trial.wait(lambda:next((r for r in journal(completed)['records'].values() if r['id']==job and r['state']=='complete'),None),maximum=5)
    reaped=next(e for e in completed.logs() if e.get('event')=='research_reaped' and e['job']==job)
    assert reaped['exit']==0 and finished['checkpoint']==finished['reserved_units']==1
    probe.ended(retained)
    write_receipt(trial.output/'completed-provider-cleanup-witness.json',{'job':job,
        'checkpoint':finished['checkpoint'],'reserved_units':finished['reserved_units'],'state':finished['state'],
        'supervisor_reaped_exit':reaped['exit'],'processes':retained,'remaining_groups':probe.remaining(retained)})
    completed.stop();probe.ended()
    trial.summary['scenarios']['completed_provider_is_reaped_before_result_delivery']={'result':'pass'}
    trial.summary['node_count']=4
    # Lose only a currently identified supervisor while its owned CPU worker
    # and TERM-ignoring child are alive. EOF must end their separate group.
    node=Node(trial,0)
    node.config['runtime'].update(question_interval_ms=100,jobs=job_settings(finding={'steps':0,'cpu_ms':20000,'descendant':True}))
    node.write_config();node.start();probe.witness_cpu(node)
    event=next(e for e in reversed(node.logs()) if e.get('event')=='research_started')
    identity=process_identity(event['pid']);assert identity and identity['pid']==identity['group']==identity['session']
    assert str(trial.binary) in identity['command'] and '--research-supervisor-v1' in identity['command']
    assert process_identity(identity['pid'])==identity
    os.kill(identity['pid'],signal.SIGKILL)
    trial.wait(lambda:not process_group(node.process),maximum=8);probe.ended()
    state=journal(node);assert any(r['state']=='in_doubt' and not r['acknowledged'] for r in state['records'].values())
    assert any(e.get('event')=='fatal_error' and 'cleanup' in e.get('error','') for e in node.logs())
    node.process=None  # expected fatal exit, not a claimed graceful stop
    node.start();probe.observe(node)
    assert any(r['state']=='in_doubt' for r in journal(node)['records'].values())
    node.stop();probe.ended()

    # A small server send buffer forces an actual response writer to wait for
    # the deliberately unread maximum escaped owner text. Authenticated stop
    # must initiate role teardown before the response write timeout.
    slow=Node(trial,1)
    slow.config['runtime'].update(question_interval_ms=100,jobs=job_settings(finding={'steps':0,'cpu_ms':20000,'descendant':True}))
    slow.write_config();trial.call(slow,'interest',text='\x01'*1024)
    os.environ['NAOME_DEV_CONTROL_SENDBUF_BYTES']='1024'
    try:slow.start()
    finally:os.environ.pop('NAOME_DEV_CONTROL_SENDBUF_BYTES',None)
    probe.witness_cpu(slow)
    endpoint=json.loads((slow.directory/'control.json').read_text())
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(2);client.connect(endpoint['socket'])
    client.sendall((json.dumps({'version':1,'token':endpoint['token'],'operation':'stop'})+'\n').encode())
    started=time.monotonic()
    try:
        trial.wait(lambda:not process_group(slow.process),maximum=5);probe.ended()
        elapsed=time.monotonic()-started;assert elapsed<5
        assert any(e.get('event')=='control_rejected' and 'write timeout' in e.get('error','') for e in slow.logs()),'slow writer was not exercised'
        received=b''
        while block:=client.recv(8192):received+=block
        assert 0<len(received)<8192 and not received.endswith(b'\n'),'partial response write was not observed'
        write_receipt(trial.output/'unread-stop-witness.json',{'partial_response_bytes':len(received),
            'complete_response':False,'write_timeout_observed':True,'stop_seconds':elapsed})
        trial.summary['slow_writer_stop_seconds']=elapsed
    finally:client.close()
    slow.stop()

    # Hold the daemon reader while a valid maximum-sized result exceeds the
    # pipe capacity, then lose only that daemon. Lifelines must clear all groups.
    output=Node(trial,2)
    output.config['runtime'].update(question_interval_ms=100,jobs=job_settings(solving={'proof_padding_bytes':65536,'result_delay_ms':1500,'descendant':True}))
    output.write_config();output.start()
    ready=trial.wait(lambda:next((e for e in reversed(output.logs()) if e.get('event')=='research_working' and e.get('phase')=='result_ready'),None),maximum=10)
    probe.observe(output);original=output.process;assert process_identity(original['pid'])==original
    os.kill(original['pid'],signal.SIGSTOP)
    try:
        time.sleep(2)
        supplier=next(e for e in output.logs() if e.get('event')=='research_started' and e['job']==ready['job'])
        assert process_identity(supplier['pid']) is not None,'result supplier exited instead of facing unread pipe backpressure'
        os.kill(original['pid'],signal.SIGKILL)
        trial.wait(lambda:not process_group(original),maximum=5);probe.ended()
    finally:
        if process_identity(original['pid'])==original:os.kill(original['pid'],signal.SIGCONT)
    output.start();probe.observe(output);output.stop();probe.ended()
    trial.summary['scenarios']['supervisor_loss_unread_response_and_result_pipe_cleanup']={'result':'pass'}


def basic(trial,probe):
    first,second=Node(trial,0),Node(trial,1)
    for node in [first,second]:node.start();node.stop()
    first.config['peers']=[{'id':second.peer,'address':f'/ip4/127.0.0.1/tcp/{second.port}'}]
    first.config['runtime']['question_interval_ms']=100;first.write_config();first.start()
    second.config['peers']=[{'id':first.peer,'address':f'/ip4/127.0.0.1/tcp/{first.port}'}];second.write_config();second.start()
    started=time.monotonic()
    trial.wait(lambda:len(first.ids())==3 and first.ids()==second.ids(),maximum=20)
    trial.summary['convergence_seconds']=time.monotonic()-started
    trial.summary['status_seconds']={str(count):probe.statuses(first,count) for count in [2,8]}
    probe.observe(first);probe.observe(second);first.stop();second.stop();probe.ended()
    trial.summary['scenarios']['matched_default_mock_workload_two_and_eight_control_clients']={'result':'pass'}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--profile',required=True)
    parser.add_argument('--mode',choices=['roles','recovery','limits','faults','basic'],required=True)
    parser.add_argument('--timeout',type=float,default=90);args=parser.parse_args()
    trial=Trial(args.binary,args.output,args.timeout,args.profile,'long-jobs-'+args.mode);probe=Probe(trial)
    trial.summary.update(fixture='ordinary_long_jobs',driver_sha256=digest(__file__),
        claim='finite deterministic providers, native checking and local real transport; no model or multi-day uptime claim')
    started=time.monotonic()
    try:
        globals()[args.mode](trial,probe);trial.summary['result']='pass'
    except Exception as error:
        trial.summary.update(result='fail',error=str(error))
    finally:
        for node in trial.nodes:
            try:probe.observe(node)
            except Exception as error:trial.summary.setdefault('observation_errors',[]).append(str(error));trial.summary['result']='fail'
        trial.summary['resource_peaks']=probe.peaks
        trial.summary['measurement_scope']='retained finite milestone samples, not complete lifetime maxima'
        trial.close()
        trial.summary['execution_seconds']=time.monotonic()-started
        retain_evidence(trial.output,trial.summary,'long-jobs-'+args.mode,args.profile)
    print(json.dumps({'result':trial.summary['result'],'output':str(trial.output)}),flush=True)
    return 0 if trial.summary['result']=='pass' else 1

if __name__=='__main__':raise SystemExit(main())
