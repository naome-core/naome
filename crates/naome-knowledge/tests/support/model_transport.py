#!/usr/bin/env python3
"""Weightless native Supervisor/Worker/Proxy/Parent and live-reader regression.

Historical logits are replayed only as transport fixtures. No Torch, weights,
MPS forward, model fit or semantic effectiveness is measured by this driver.
"""
import argparse
import array
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

from autonomous_lifecycle import kernel_birth, process_identity, process_group
from proof_network import stored_objects, proof_id
from types import SimpleNamespace

LIMIT = 128 * 1024
PROVIDER = 'naome-qwen3-4b-owner-interest-v1'
CLOCK = 'clock_gettime(CLOCK_MONOTONIC)'


def now():
    # Unlike Python 3.9/macOS time.monotonic(), this has a shared OS origin.
    return time.clock_gettime(time.CLOCK_MONOTONIC)


def guardian_binding(identity):
    executable, separator, arguments = identity['command'].partition(' ')
    assert executable and separator and arguments,'guardian command lacks complete script arguments'
    # Apple's launcher can exec Framework Python under the same kernel birth.
    # Script and every argument remain exact; argv[0] is retained as telemetry.
    return {key:identity[key] for key in ['pid','group','session','kernel_birth']} | {'script_arguments':arguments}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with path.open('x') as output:
        json.dump(value, output, indent=2)
        output.write('\n')


def frame(value):
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    assert 0 < len(data) <= LIMIT
    return struct.pack('>I', len(data)) + data


def receive(channel):
    fds, raw = [], bytearray()
    try:
        size = 4
        while len(raw) < size:
            data, controls, flags, _ = channel.recvmsg(size-len(raw), socket.CMSG_SPACE(512*4))
            assert data and not flags & socket.MSG_CTRUNC
            for level, kind, payload in controls:
                assert level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS
                values = array.array('i')
                values.frombytes(payload[:len(payload)-len(payload)%values.itemsize])
                fds.extend(values)
            raw.extend(data)
            if size == 4 and len(raw) == 4:
                size += struct.unpack('>I', raw)[0]
                assert 4 < size <= LIMIT+4
        return json.loads(raw[4:]), fds
    except BaseException:
        for fd in fds: os.close(fd)
        raise


class Host:
    def __init__(self, binary, output):
        self.output, self.clients, self.events = output, {}, []
        self.client_locks, self.client_paused = {}, {}
        self.lock, self.closed, self.threads = threading.Lock(), threading.Event(), []
        self.choice = 0
        self.root = Path('/tmp') / f'naome-interest-uid-{os.geteuid()}'
        self.root.mkdir(mode=0o700, exist_ok=True)
        meta = self.root.lstat()
        assert stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode) == 0o700
        lease_path = self.root/'model.lock'
        self.lease = os.open(lease_path, os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
        meta=os.fstat(self.lease)
        assert stat.S_ISREG(meta.st_mode) and meta.st_uid==os.geteuid() and meta.st_nlink==1
        fcntl.flock(self.lease, fcntl.LOCK_EX|fcntl.LOCK_NB)
        original=os.read(self.lease,4096)
        if not original:
            os.write(self.lease,b'naome-interest-host-lease-v1\n');os.fsync(self.lease)
        else: assert original==b'naome-interest-host-lease-v1\n'
        self.support={'python':str(Path(sys.executable).resolve()),'model':str(output/'unused-model')}
        (binary.parent/'.naome-interest.json').write_text(json.dumps(self.support)+'\n')
        owner=Path(__file__).resolve().parents[2]/'src/interest'
        self.rows=json.loads((owner/'fixtures/v7-decisions.json').read_bytes())
        self.contract=hashlib.sha256(json.dumps([PROVIDER,self.support,digest(owner/'qwen.py'),digest(owner/'worker.py')],separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        self.nonce=hashlib.sha256(os.urandom(32)).hexdigest()
        self.ready={'kind':'ready','schema':1,'model_revision':'1cfa9a7208912126459214e8b04321603b3df60c',
            'manifest_hash':'b7d4ab43f8cfc348ff7195e64a5e23fb65ceb0eec55a1761030ac1e9478b018b',
            'prompt_version':'naome:owner-interest:prompt:v1','prompt_hash':'69afc1b7c184eeb83ed7faa55d7fdcfbc67949f0ed10b0c138eaaf0ff5403f98',
            'template_hash':'a55ee1b1660128b7098723e0abcd92caa0788061051c62d51cbe87d9cf1974d8',
            'device':'mps','load_strategy':'cpu-staged-mps-v1','parameter_bytes':8044936192,'labels':{'true':1866,'false':3849},
            'inventory_hash':self.rows[0]['inventory_hash'],'model_instance':self.rows[0]['model_instance'],
            'generation':self.nonce,'contract':self.contract,'pid':os.getpid()}
        for name in ['host.sock','endpoint.json']:
            path=self.root/name
            if path.exists():
                meta=path.lstat();assert meta.st_uid==os.geteuid() and not stat.S_ISLNK(meta.st_mode)
                path.unlink()
        endpoint=self.root/'endpoint.json'
        fd=os.open(endpoint,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        os.write(fd,json.dumps({'version':1,'nonce':self.nonce,'contract':self.contract}).encode());os.close(fd)
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.listener.bind(str(self.root/'host.sock'));os.chmod(self.root/'host.sock',0o600)
        self.listener.listen(16);self.listener.settimeout(.1)
        thread=threading.Thread(target=self.accept,daemon=True);thread.start();self.threads.append(thread)

    def accept(self):
        while not self.closed.is_set():
            try: channel,_=self.listener.accept()
            except socket.timeout: continue
            except OSError: return
            thread=threading.Thread(target=self.handle,args=(channel,),daemon=True)
            thread.start();self.threads.append(thread)

    def handle(self,channel):
        channel.settimeout(.5)
        fds=[];client=None
        try:
            value,fds=receive(channel)
            assert value['nonce']==self.nonce and value['contract']==self.contract
            if value['kind']=='attach':
                assert not fds
                client=value['client']
                with self.lock:
                    self.clients[client]=channel
                    self.client_locks[client]=threading.Lock()
                    self.client_paused[client]=threading.Event()
                channel.sendall(frame({'kind':'attached'}));channel.sendall(frame(self.ready))
                while not self.closed.is_set():
                    try:
                        if not channel.recv(1):break
                    except socket.timeout:
                        with self.client_locks[client]:
                            if not self.client_paused[client].is_set():
                                channel.sendall(frame({'kind':'telemetry','generation':self.nonce,'fixture':'weightless_transport'}))
            else:
                assert value['kind']=='query' and len(fds)==1
                req=value['request'];result=dict(self.rows[self.choice])
                for key in ['transport_id','request_id']:
                    result[key]=value['transport_id'] if key=='transport_id' else req['request_id']
                result.update(owner=value['owner'],generation=self.nonce,
                    profile_revision=req['profile']['revision'],profile_hash=req['profile']['hash'],
                    source_hash=req['question']['source_hash'],resolution_id=req['question']['resolution_id'],
                    snapshot=req['snapshot'],policy=req['policy'])
                with self.lock:self.events.append({'kind':'query','request':value,'selected':result['selected'],'fixture_only':True})
                channel.sendall(frame(result))
        except (EOFError,OSError,AssertionError,KeyError,ValueError):
            pass
        finally:
            for fd in fds:os.close(fd)
            if client:
                with self.lock:
                    if self.clients.get(client) is channel:
                        self.clients.pop(client,None)
            channel.close()

    def rights(self,client,where,count,tag):
        with self.lock: channel=self.clients[client]
        path=self.output/f'rights-{tag}.lock'
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        data=frame({'kind':'telemetry','generation':self.nonce,'probe':tag})
        with self.client_locks[client]:
            if where=='body':channel.sendall(data[:4]);data=data[4:]
            sent=channel.sendmsg([data],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]*count))])
            assert sent==len(data)
        os.close(fd)
        return path,channel

    def marker(self,client,tag):
        with self.lock:channel=self.clients[client]
        with self.client_locks[client]:channel.sendall(frame({'kind':'telemetry','generation':self.nonce,'probe':tag}))

    def partial(self,client):
        with self.lock:channel=self.clients[client]
        with self.client_locks[client]:
            self.client_paused[client].set()
            channel.sendall(b'\0')

    def close(self):
        self.closed.set();self.listener.close()
        with self.lock:
            for channel in self.clients.values():
                try:channel.shutdown(socket.SHUT_RDWR)
                except OSError:pass
        for thread in self.threads:thread.join(timeout=.6)
        assert not any(thread.is_alive() for thread in self.threads)
        for name in ['host.sock','endpoint.json']:
            path=self.root/name
            if path.exists():path.unlink()
        os.close(self.lease)


def logs(directory):
    result=[]
    for name in ['node.log.previous','node.log']:
        path=directory/name
        if path.exists():
            for line in path.read_text().splitlines():
                try:result.append(json.loads(line))
                except ValueError:pass
    return result


def journal(directory):
    path=directory/'research/jobs.json'
    if not path.exists():return None
    envelope=json.loads(path.read_text());assert envelope['version']==1
    payload=envelope['payload']
    encoded=json.dumps(payload,separators=(',',':'),ensure_ascii=False).encode()
    assert hashlib.sha256(encoded).hexdigest()==envelope['sha256']
    return payload


def live_readers(directory,node_identity):
    pids={e['pid'] for e in logs(directory) if e.get('event')=='interest_client_started'}
    result=[]
    for pid in pids:
        identity=process_identity(pid)
        if identity and identity['group']==node_identity['group'] and '--interest-client-v1' in identity['command']:
            result.append(identity)
    assert len(result)<=1,'at most one actual live reader per ordinary node'
    return result


def fd_names(pid):
    if sys.platform=='linux':
        result=[]
        for entry in Path(f'/proc/{pid}/fd').iterdir():
            try:result.append(os.readlink(entry))
            except FileNotFoundError:pass
        return result
    result=subprocess.run(['/usr/sbin/lsof','-n','-P','-a','-p',str(pid),'-Ffn'],capture_output=True,text=True,timeout=2)
    assert result.returncode in [0,1]
    return [line[1:] for line in result.stdout.splitlines() if line.startswith('n')]


def wait(predicate,end):
    while now()<end:
        result=predicate()
        if result:return result
        time.sleep(.01)
    raise AssertionError('original transport phase deadline')


def cli(binary,directory,verb,*args,timeout=2):
    value=subprocess.run([str(binary),'--json',verb,*args],env={**os.environ,'NAOME_NODE_DIR':str(directory)},
        stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout)
    assert value.returncode==0,(verb,value.stdout,value.stderr)
    return json.loads(value.stdout)


def bounded_identity(pid,end):
    assert now()<end
    born=kernel_birth(pid)
    if born is None:return None
    query=subprocess.run(['/bin/ps','-p',str(pid),'-o','pid=,pgid=,stat=,command='],
        capture_output=True,text=True,timeout=max(.001,min(.2,end-now())))
    assert len(query.stdout.encode())<=65536 and now()<end
    if query.returncode or not query.stdout.strip():return None
    parts=query.stdout.strip().split(None,3);assert len(parts)==4
    try:session=os.getsid(pid)
    except ProcessLookupError:return None
    if kernel_birth(pid)!=born:return None
    return {'pid':int(parts[0]),'group':int(parts[1]),'session':session,
        'state':parts[2],'kernel_birth':born,'command':parts[3]}


def guardian_startup_identity(child,command,output,end):
    started=now();samples=[];anchor=None;accepted=None;error=None;persist_error=None
    save(output/'guardian-start.json',{'pid':child.pid,'launch_command':command,
        'expected_group':child.pid,'expected_session':child.pid,'clock':CLOCK,
        'started':started,'original_phase_deadline':end,'maximum_samples':64})
    try:
        anchor=kernel_birth(child.pid)
        save(output/'guardian-start-kernel.json',{'pid':child.pid,'kernel_birth':anchor,
            'scope':'actual early sample; null is unconfirmed, not absence'})
        expected_arguments=' '.join(command[1:])
        for _ in range(64):
            assert now()<end,'original Guardian startup phase deadline'
            assert child.poll() is None,'owned Guardian exited before startup capture'
            current=bounded_identity(child.pid,end)
            samples.append({'observed_at':now(),'identity':current})
            if current is None:continue
            if anchor is None:anchor=current['kernel_birth']
            assert current['pid']==current['group']==current['session']==child.pid,'Guardian startup group/session'
            assert current['kernel_birth']==anchor,'Guardian startup kernel birth changed'
            assert not current['state'].startswith('Z'),'Guardian startup sample is defunct'
            executable,separator,arguments=current['command'].partition(' ')
            if not executable or not separator or arguments!=expected_arguments:continue
            assert guardian_binding(current)['script_arguments']==expected_arguments,'Guardian fixed launch arguments'
            assert child.poll() is None and now()<end,'Guardian startup capture completed after exit/deadline'
            accepted=current;break
        assert accepted is not None,'Guardian full fixed launch identity not captured within bounded samples'
    except BaseException as fault:error=repr(fault)
    try:
        save(output/'guardian-start-samples.json',{'pid':child.pid,'launch_command':command,
            'anchor_kernel_birth':anchor,'samples':samples,'accepted':accepted,
            'original_error':error,'clock':CLOCK,'original_phase_deadline':end,'completed_at':now()})
    except BaseException as fault:persist_error=repr(fault)
    assert not error and not persist_error and accepted is not None and now()<end,(error,persist_error)
    return accepted


def guardian_child_wait(child,output,timeout,filename):
    started=now();value={'pid':child.pid,'clock':CLOCK,'started':started,
        'timeout_seconds':timeout,'exit_code':None,'reaped':False,'error':None}
    try:
        value['exit_code']=child.wait(timeout=timeout);value['reaped']=True
    except BaseException as fault:value['error']=repr(fault)
    value['completed_at']=now();value['elapsed']=value['completed_at']-started
    try:save(output/filename,value)
    except BaseException as fault:value['persist_error']=repr(fault)
    return value


def init_identity(binary,directory,output,end):
    # Allocate a finite observation and cancellation window inside the one
    # consumer deadline. Natural cold-init latency remains unmeasured.
    started=now();assert end-started>.5
    phase_end=min(end,started+2.5);work_end=phase_end-.5
    command=[str(binary),'init',str(directory)];name=directory.name
    attempt={'command':command,'binary_sha256':digest(binary),'directory':str(directory),
        'clock':CLOCK,'original_started':started,'phase_deadline':end,
        'helper_deadline':phase_end,'work_deadline':work_end,'cancel_reserve_seconds':.5,
        'expected_group':os.getpgrp(),'expected_session':os.getsid(0)}
    save(output/(name+'.helper-attempt.json'),attempt)
    raw={key:bytearray() for key in ['stdout','stderr']};handles={}
    selected=selectors.DefaultSelector();child=None;start_event=None;error=None;reap_error=None;exit_code=None
    primary_write_error=None;terminal_write_error=None;raw_tail_error=None;signal_error=None
    close_errors=[];overflow={key:False for key in raw};observed_bytes={key:0 for key in raw}
    public=None
    def append_raw(key,data):
        observed_bytes[key]+=len(data);remaining=65536-len(raw[key]);prefix=data[:remaining]
        raw[key].extend(prefix);handles[key].write(prefix);handles[key].flush()
        if len(data)>remaining:
            overflow[key]=True
            raise ValueError('offline helper '+key+' output overflow; bounded prefix retained')
    try:
        for key in raw:handles[key]=(output/(name+'.helper-'+key+'.bin')).open('xb')
        assert now()<work_end
        child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,close_fds=True)
        # Persist the actual Child PID before any blocking metadata/read query.
        start_event={**attempt,'pid':child.pid,'spawned_at':now(),
            'expected_inherited_group':os.getpgrp()}
        save(output/(name+'.helper-start.json'),start_event)
        observed=None;identity_error=None;born=None
        try:
            born=kernel_birth(child.pid);observed=bounded_identity(child.pid,work_end)
        except BaseException as fault:identity_error=repr(fault)
        save(output/(name+'.helper-identity.json'),{'pid':child.pid,'kernel_birth':born,
            'observed':observed,'query_error':identity_error,
            'scope':'actual post-spawn sample; null means no live sample, not no allocation'})
        if observed and not observed['state'].startswith('Z'):
            assert observed['group']==start_event['expected_inherited_group']
            assert observed['command']==' '.join(command)
        for key,pipe in [('stdout',child.stdout),('stderr',child.stderr)]:
            selected.register(pipe,selectors.EVENT_READ,key)
        while selected.get_map():
            if now()>=work_end:raise TimeoutError('original offline helper work deadline')
            for event,_ in selected.select(min(.05,max(.001,work_end-now()))):
                key=event.data;data=os.read(event.fileobj.fileno(),min(16384,65537-len(raw[key])))
                if not data:selected.unregister(event.fileobj);continue
                append_raw(key,data)
        exit_code=child.wait(timeout=max(.001,work_end-now()))
        assert exit_code==0 and now()<work_end,(exit_code,bytes(raw['stderr']))
        stdout=bytes(raw['stdout']);assert len(stdout)<=4096 and not raw['stderr']
        public=json.loads(stdout)
        assert public['config']['directory']==str(directory.resolve())
        assert isinstance(public['peer_id'],str) and public['peer_id'].startswith('12D3KooW')
        assert sorted(p.name for p in directory.iterdir())==['identity.key']
    except BaseException as fault:error=repr(fault)
    finally:
        # Keep the original cause and streamed raw bytes before cancellation.
        try:
            save(output/(name+'.helper-primary.json'),{'attempt':attempt,'start':start_event,
                'error':error,'exit_code_before_cancel':exit_code,'recorded_at':now(),
                'raw':{key:{'bytes':len(value),'observed_bytes':observed_bytes[key],'overflow':overflow[key],
                    'sha256':hashlib.sha256(value).hexdigest()} for key,value in raw.items()}})
        except BaseException as fault:primary_write_error=repr(fault)
        if child is not None:
            try:
                if child.poll() is None:child.kill()
            except BaseException as fault:signal_error=repr(fault)
            try:
                exit_code=child.wait(timeout=max(.001,phase_end-now()))
            except BaseException as fault:reap_error=repr(fault)
            try:
                for key,pipe in [('stdout',child.stdout),('stderr',child.stderr)]:
                    os.set_blocking(pipe.fileno(),False)
                    while len(raw[key])<=65536 and now()<phase_end:
                        try:data=os.read(pipe.fileno(),min(16384,65537-len(raw[key])))
                        except BlockingIOError:break
                        if not data:break
                        append_raw(key,data)
            except BaseException as fault:raw_tail_error=repr(fault)
            for pipe in [child.stdout,child.stderr]:
                try:pipe.close()
                except BaseException as fault:close_errors.append('pipe '+repr(fault))
        try:selected.close()
        except BaseException as fault:close_errors.append('selector '+repr(fault))
        for handle in handles.values():
            try:handle.close()
            except BaseException as fault:close_errors.append('raw file '+repr(fault))
        try:
            save(output/(name+'.helper-terminal.json'),{'attempt':attempt,'start':start_event,
                'original_error':error,'direct_wait_exit_code':exit_code,
                'direct_reaped':child is not None and exit_code is not None,'reap_error':reap_error,'signal_error':signal_error,
                'primary_persist_error':primary_write_error,'raw_tail_error':raw_tail_error,
                'close_errors':close_errors,
                'raw':{key:{'bytes':len(value),'observed_bytes':observed_bytes[key],'overflow':overflow[key],
                    'sha256':hashlib.sha256(value).hexdigest()} for key,value in raw.items()},
                'wall_before_terminal_write':now()-started,'recorded_at':now(),'clock':CLOCK,
                'scope':'owned helper terminal before outer transport cleanup'})
        except BaseException as fault:terminal_write_error=repr(fault)
    assert not any([error,signal_error,reap_error,primary_write_error,terminal_write_error,raw_tail_error,close_errors]) and exit_code==0 and now()<phase_end,(
        error,signal_error,reap_error,primary_write_error,terminal_write_error,raw_tail_error,close_errors,exit_code)
    assert public is not None
    stdout=bytes(raw['stdout'])
    save(output/(name+'.identity-init.json'),{'command':command,'pid':child.pid,
        'exit_code':exit_code,'reaped':True,'binary_sha256':attempt['binary_sha256'],
        'wall_before_public_receipt_write':now()-started,'clock':CLOCK,'phase_deadline':phase_end,
        'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'public_output':public,
        'scope':'offline identity generation only; no developer network peer or proof input'})
    accepted_at=now();assert accepted_at<phase_end and accepted_at<end
    return {'peer_id':public['peer_id'],'accepted_at_after_helper_owned_writes':accepted_at,
        'wall_after_helper_owned_writes':accepted_at-started,'original_helper_started':started,
        'clock':CLOCK,'helper_deadline':phase_end}


def ordinary_start(binary,directory,output,end):
    assert now()<end
    index=len(list(output.glob(directory.name+'.start-attempt-*.json')))
    save(output/(directory.name+f'.start-attempt-{index}.json'),{'directory':str(directory),
        'command':[str(binary),'--json','start'],'clock':CLOCK,'attempted_at':now(),'phase_deadline':end})
    assert now()<end
    return cli(binary,directory,'start',timeout=max(.001,min(2,end-now())))


class Cleanup:
    def __init__(self,output,maximum):
        self.path=output/'cleanup-budget.json';self.maximum=maximum
        if self.path.exists():self.state=json.loads(self.path.read_bytes())
        else:self.state={'clock':CLOCK,'remaining':maximum,'started':None,'spent':0.0};self.persist()
        assert self.state['clock']==CLOCK,'cleanup clock domain differs'
        assert 0<=self.state['remaining']<=maximum
    def persist(self):
        temp=self.path.with_suffix('.incoming')
        temp.write_text(json.dumps(self.state)+'\n');os.replace(temp,self.path)
    def remaining(self):
        elapsed=0 if self.state['started'] is None else now()-self.state['started']
        return max(0,self.state['remaining']-elapsed)
    def recover(self):
        if self.state['started'] is not None:
            elapsed=now()-self.state['started']
            self.state['remaining']=max(0,self.state['remaining']-elapsed)
            self.state['spent']+=elapsed;self.state['started']=None
            self.state['recovered_parent_cleanup_wall']=elapsed;self.persist()
    def begin(self):
        assert self.state['started'] is None and self.remaining()>0
        self.state['started']=now();self.persist()
    def end(self):
        elapsed=now()-self.state['started']
        self.state['remaining']=max(0,self.state['remaining']-elapsed)
        self.state['spent']+=elapsed;self.state['started']=None;self.persist()
        assert self.state['spent']<=self.maximum,'original aggregate cleanup exhausted'


def guardian_receipt(args,reason,budget,result,identity):
    return {'schema':1,'scope':'owned weightless transport guardian','guardian':identity,
        'binary_sha256':digest(args.binary),'driver_sha256':digest(__file__),
        'output':str(args.output.resolve()),'reason':reason,'maximum_cleanup':args.cleanup,
        'cleanup_budget':dict(budget.state),'cleanup':result,
        'groups_empty':result['groups_empty'],'errors':result['errors']}


def owned_actor_snapshot(binary,output,end):
    assert now()<end
    query=subprocess.run(['/bin/ps','-axo','pid=,pgid=,stat=,command='],capture_output=True,text=True,
        timeout=max(.001,min(.2,end-now())),check=True)
    assert len(query.stdout.encode())<=1024*1024 and now()<end
    rows={}
    for line in query.stdout.splitlines():
        parts=line.split(None,3)
        if len(parts)==4:rows[int(parts[0])]=parts
    attempts=[(p,json.loads(p.read_bytes())) for p in output.glob('*.helper-attempt.json')]
    helpers=[];nodes=[];unresolved=[];seen=set()
    for path,attempt in attempts:
        base=path.name.removesuffix('.helper-attempt.json')
        start_path=output/(base+'.helper-start.json');terminal_path=output/(base+'.helper-terminal.json')
        terminal=json.loads(terminal_path.read_bytes()) if terminal_path.exists() else None
        start=json.loads(start_path.read_bytes()) if start_path.exists() else (terminal or {}).get('start')
        if start is None:
            # An attempt with no actual PID cannot prove no allocation. A
            # transient command may also be absent from this one PS snapshot.
            unresolved.append({'attempt':str(path),'reason':'actual helper PID/start witness missing',
                'deferred_to_final_anchored_keeper_group':True})
            continue
        pid=start['pid'];seen.add(pid)
        if terminal and terminal.get('direct_reaped') and terminal.get('start',{}).get('pid')==pid:
            continue
        if pid not in rows:
            if kernel_birth(pid) is None:continue
            unresolved.append({'pid':pid,'reason':'native birth exists but snapshot omitted PID'});continue
        identity=bounded_identity(pid,end)
        if identity is None:
            unresolved.append({'pid':pid,'reason':'retained process row has no confirmed native identity sample'})
            continue
        sample_path=output/(base+'.helper-identity.json')
        sample=json.loads(sample_path.read_bytes()) if sample_path.exists() else {}
        original_birth=sample.get('kernel_birth')
        if original_birth is not None and identity['kernel_birth']!=original_birth:continue
        if (identity['group']!=attempt['expected_group'] or identity['session']!=attempt['expected_session']):
            unresolved.append({'pid':pid,'reason':'tracked helper group/session differs','current':identity});continue
        if identity['state'].startswith('Z'):
            unresolved.append({'pid':pid,'reason':'tracked helper zombie is not reaped','current':identity});continue
        if original_birth is None:
            unresolved.append({'pid':pid,'reason':'tracked live helper birth was not captured','current':identity});continue
        assert identity['command']==' '.join(attempt['command'])
        helpers.append({**identity,'expected_command':' '.join(attempt['command'])})
    for pid,parts in rows.items():
        command=parts[3]
        helper=next((item for _,item in attempts if command==' '.join(item['command'])),None)
        if helper is None and command!=str(binary)+' start':continue
        if helper is not None and pid in seen:continue
        identity=bounded_identity(pid,end)
        if identity is None:
            unresolved.append({'pid':pid,'reason':'new exact owned command identity unavailable'});continue
        expected_command=' '.join(helper['command']) if helper else str(binary)+' start'
        assert identity['command']==expected_command
        if helper:
            assert identity['group']==helper['expected_group'] and identity['session']==helper['expected_session']
            helpers.append({**identity,'expected_command':expected_command})
        else:
            assert identity['pid']==identity['group']==identity['session']
            nodes.append(identity)
    return helpers,nodes,unresolved


def stop_nodes(binary,output,budget):
    start=now();end=start+budget;errors=[];races=[];identities=[];helpers=[];recovered=[]
    unresolved=[];snapshot_ok=False;members=None;known_helpers=[]
    def fault(label,error):errors.append(label+' '+repr(error))
    for path in output.glob('node-*.process.json'):
        try:identities.append(json.loads(path.read_bytes()))
        except BaseException as error:fault('known node receipt '+str(path),error)
    # Retain independently captured start identities even when the broad PS
    # snapshot fails; query errors must not suppress their guarded cleanup.
    for path in output.glob('*.helper-start.json'):
        try:
            start_record=json.loads(path.read_bytes());base=path.name.removesuffix('.helper-start.json')
            sample_path=output/(base+'.helper-identity.json')
            sample=json.loads(sample_path.read_bytes()) if sample_path.exists() else {}
            terminal_path=output/(base+'.helper-terminal.json')
            terminal=json.loads(terminal_path.read_bytes()) if terminal_path.exists() else None
            if terminal and terminal.get('direct_reaped') and terminal.get('start',{}).get('pid')==start_record['pid']:continue
            if sample.get('kernel_birth') is not None:
                known_helpers.append({'pid':start_record['pid'],'group':start_record['expected_group'],
                    'session':start_record['expected_session'],'kernel_birth':sample['kernel_birth'],
                    'command':' '.join(start_record['command']),
                    'expected_command':' '.join(start_record['command'])})
        except BaseException as error:fault('known helper receipt '+str(path),error)
    def snapshot():
        nonlocal helpers,recovered,unresolved,snapshot_ok
        try:
            observed_helpers,recovered,unresolved=owned_actor_snapshot(binary,output,end);snapshot_ok=True
            helpers=list(known_helpers)
            seen={i['pid'] for i in helpers}
            helpers.extend(i for i in observed_helpers if i['pid'] not in seen)
        except BaseException as error:
            helpers=list(known_helpers);snapshot_ok=False;fault('owned actor query',error)
        try:
            save(output/f'cleanup-actors-{time.time_ns()}.json',{'clock':CLOCK,'captured_at':now(),
                'query_complete':snapshot_ok,'helpers':helpers,'ordinary_nodes':recovered,
                'unresolved_helpers':unresolved,'scope':'current exact/recorded actors; not historical spawn evidence'})
        except BaseException as error:fault('cleanup diagnostics persist',error)
        known={i['pid'] for i in identities}
        for identity in recovered:
            if identity['pid'] not in known:identities.append(identity)
    def kill_helper(identity):
        try:
            if kernel_birth(identity['pid'])!=identity['kernel_birth']:return
            current=bounded_identity(identity['pid'],end)
            if current is None:return
            # Bind the retained spawn request, never a sampled foreign command.
            assert current['command']==identity['expected_command']
            assert all(current[key]==identity[key] for key in ['pid','group','session','kernel_birth','command'])
            if not current['state'].startswith('Z'):os.kill(identity['pid'],signal.SIGKILL)
        except ProcessLookupError as error:
            races.append({'pid':identity['pid'],'action':'helper signal race','error':repr(error)})
            try:
                if kernel_birth(identity['pid'])==identity['kernel_birth']:fault('helper still has original birth',error)
            except BaseException as query_error:fault('helper race absence query',query_error)
        except BaseException as error:fault('helper custody/signal',error)
    def kill_group(identity):
        try:
            if kernel_birth(identity['pid'])!=identity['kernel_birth']:return
            current=bounded_identity(identity['pid'],end)
            if current is None:return
            assert current['command']==str(binary)+' start'
            assert all(current[key]==identity[key] for key in ['pid','group','session','kernel_birth','command'])
            assert current['pid']==current['group']==current['session']
            if not current['state'].startswith('Z'):os.killpg(identity['group'],signal.SIGKILL)
        except ProcessLookupError as error:
            races.append({'pid':identity['pid'],'action':'node group signal race','error':repr(error)})
            try:
                if kernel_birth(identity['pid'])==identity['kernel_birth']:fault('node still has original birth',error)
            except BaseException as query_error:fault('node race absence query',query_error)
        except BaseException as error:fault('node group custody/signal',error)
    snapshot()
    # Query/diagnostic errors never suppress cleanup of known start attempts.
    for path in sorted(output.glob('node-*')):
        if not path.is_dir():continue
        receipt=output/(path.name+'.process.json');control=path/'control.json'
        attempts=list(output.glob(path.name+'.start-attempt-*.json'))
        if not attempts and not receipt.exists() and not control.exists():continue
        if now()>=end:
            errors.append('aggregatecleanup exhausted before '+path.name);break
        identity=None
        try:
            if receipt.exists():identity=json.loads(receipt.read_bytes())
            elif control.exists():
                candidate=bounded_identity(json.loads(control.read_bytes())['pid'],end)
                if candidate:
                    assert candidate['command']==str(binary)+' start'
                    assert candidate['pid']==candidate['group']==candidate['session']
                    identity=candidate;identities.append(identity)
        except BaseException as error:fault('node start custody '+str(path),error)
        if identity:
            try:
                if kernel_birth(identity['pid']) is None:continue
            except BaseException as error:fault('node birth before Stop '+str(path),error)
        try:cli(binary,path,'stop',timeout=max(.001,min(.75,end-now()-.25)))
        except BaseException as error:fault('ordinary Stop '+str(path),error)
        if identity:kill_group(identity)
    while now()<end:
        # Rebind and stop actors first seen after the initial query, rather than
        # merely waiting for them. All work borrows this same cleanup deadline.
        snapshot()
        for identity in helpers:
            if now()>=end:break
            kill_helper(identity)
        for identity in recovered:
            if now()>=end:break
            kill_group(identity)
        try:
            query=subprocess.run(['/bin/ps','-axo','pid=,pgid=,stat=,command='],capture_output=True,text=True,
                timeout=max(.001,min(.2,end-now())),check=True)
            assert len(query.stdout.encode())<=1024*1024 and now()<end
            groups={i['group'] for i in identities}
            members=[line for line in query.stdout.splitlines() if len(line.split())>1 and int(line.split()[1]) in groups]
        except BaseException as error:fault('final owned group query',error);members=None
        try:final_helpers,final_nodes,final_unresolved=owned_actor_snapshot(binary,output,end)
        except BaseException as error:
            fault('final helper/daemon custody',error);final_helpers=final_nodes=[];final_unresolved=[{'reason':'final query unavailable'}]
        if members==[] and not final_helpers and not final_nodes and not final_unresolved and snapshot_ok:
            return {'elapsed':now()-start,'errors':errors,'races':races,'groups_empty':not errors,
                'native_group_members':[],'owned_helpers_absent':True,'unregistered_ordinary_nodes_absent':True}
        time.sleep(min(.01,max(0,end-now())))
    return {'elapsed':now()-start,'errors':errors,'races':races,'groups_empty':False,
        'native_group_members':members,'owned_helpers_absent':False,
        'unresolved_helpers':unresolved,'unregistered_ordinary_nodes_absent':False}


def main(args):
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    binary=output/'bin/naome';binary.parent.mkdir();shutil.copy2(args.binary,binary)
    summary={'scope':'weightless native transport/consumer evidence only; no genuine MPS or model inference',
        'binary_sha256':digest(binary),'driver_sha256':digest(__file__),'cases':{},'result':'fail'}
    end=now()+args.timeout;host=None;budget=Cleanup(output,args.cleanup)
    read_end,write_end=os.pipe()
    guardian_command=[sys.executable,'-B',str(Path(__file__).resolve()),'--guardian','--binary',str(binary),
        '--output',str(output),'--fd',str(read_end),'--timeout',str(args.timeout+args.cleanup),'--cleanup',str(args.cleanup)]
    guard=subprocess.Popen(guardian_command,
        pass_fds=(read_end,),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    os.close(read_end)
    guardian_identity=None
    summary['guardian_launch']={'pid':guard.pid,'command':guardian_command}
    try:
        guardian_identity=guardian_startup_identity(guard,guardian_command,output,end)
        save(output/'guardian-process.json',guardian_identity)
        assert now()<end,'Guardian authority persist exceeded original phase deadline'
        host=Host(binary,output)
        answer_cases=[] if args.reader_only else [
            ('valid_true','success',0,True),('valid_false','success',1,False),
            ('legacy_raw','malformed',0,None),('wrong_binding','wrong_target',0,None),('duplicate','failed',0,None)]
        for index,(name,outcome,row,expected) in enumerate(answer_cases):
            path=output/f'node-{index}';path.mkdir();host.choice=row
            port=socket.socket();port.bind(('127.0.0.1',0));number=port.getsockname()[1]
            config={'directory':str(path),'listen':f'/ip4/127.0.0.1/tcp/{number}','peers':[],
                'producer_sources':[],'discovery':{'mdns':False,'dht':False},
                'runtime':{'question_interval_ms':100,'proof_interval_ms':100,'mock_interest':False,
                    'jobs':{'interest':{'mock':{'outcome':outcome}}}}}
            (path/'config.json').write_text(json.dumps(config)+'\n');port.close()
            cli(binary,path,'interest','Set theory');ordinary_start(binary,path,output,end)
            control=json.loads((path/'control.json').read_bytes());identity=process_identity(control['pid']);assert identity
            save(output/(path.name+'.process.json'),identity)
            records=wait(lambda: [r for r in (journal(path) or {}).get('records',{}).values()
                if r['input']['role']=='interest' and r['state']==('complete' if expected is not None else 'in_doubt')],end)
            first=records[0];assert first['provider']==PROVIDER and first['model_allowance_ms']==20000 and first['spent_ms']>=first['model_allowance_ms']
            state=journal(path)
            obligation={k:first['input'][k] for k in ['role','question','purpose','root']}
            account_key=hashlib.sha256(json.dumps(obligation,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
            account=state['accounts'][account_key]
            assert account['created_ms']==first['created_ms'] and account['expires_ms']==first['expires_ms']
            assert account['settings']==first['settings'] and account['spent_ms']>=first['spent_ms']
            assert account['reserved_units']>=first['reserved_units'] and state['total_spent_ms']>=first['spent_ms']
            assert any(r['input']['role']=='find' and r['state']=='complete' for r in state['records'].values())
            observations=[e for e in logs(path) if e.get('event')=='interest_model_decision']
            if expected is not None:
                assert first['result']=={'kind':'interest','value':expected}
                assert any(e['job']==first['id'] and e['response']['selected']==expected for e in observations)
            else:
                assert first['result'] is None and not first['acknowledged'] and first['reserved_units']>0
                assert cli(binary,path,'status')['accepted_proofs']==0
            summary['cases'][name]={'record':first,'original_account_key':account_key,'original_account':account,'queue_charged_ms':first['spent_ms']-first['model_allowance_ms'],'total_spent_ms':state['total_spent_ms'],'observations':observations,'fixture_only':True}
            save(output/f'{name}.primary.json',summary['cases'][name])
            budget.begin()
            try:cli(binary,path,'stop',timeout=max(.001,min(1.0,budget.remaining()-.4,end-now())))
            finally:budget.end()
            assert budget.remaining()>0 and not process_group(identity)
            restored=journal(path);retained=restored['accounts'][account_key]
            assert retained['created_ms']==account['created_ms'] and retained['expires_ms']==account['expires_ms']
            assert retained['settings']==account['settings'] and retained['spent_ms']>=account['spent_ms']
            if expected is None:
                held=restored['records'][str(first['id'])]
                assert held['state']=='in_doubt' and held['result'] is None and not held['acknowledged']
                assert retained['reserved_units']>=account['reserved_units'] and held['spent_ms']>=first['spent_ms']
            save(output/f'{name}.retained-after-stop.json',{'original_account_key':account_key,'account':retained,
                'pre_stop_spent_ms':account['spent_ms'],'no_refund':True,'fixture_only':True})
        # Two ordinary nodes share the fake host only to qualify transport
        # custody and peer continuity, never actual MPS effectiveness.
        active=[];prepared=[];ports=[]
        host.choice=0
        identity_binary=(args.identity_binary or args.binary.parent/'naome-knowledge-dev').resolve()
        try:
            for index in [5,6]:
                path=output/f'node-{index}';path.mkdir()
                port=socket.socket();ports.append(port);port.bind(('127.0.0.1',0))
                initialized=init_identity(identity_binary,path,output,end)
                save(output/(path.name+'.helper-return.json'),initialized)
                accepted_after_return_write=now()
                assert accepted_after_return_write<initialized['helper_deadline'] and accepted_after_return_write<end
                prepared.append({'index':index,'path':path,'port':port,'number':port.getsockname()[1],
                    'peer_id':initialized['peer_id'],
                    'helper_accepted_after_return_write':accepted_after_return_write,
                    'helper_wall_including_return_write':accepted_after_return_write-initialized['original_helper_started']})
            assert len({p['peer_id'] for p in prepared})==2
            for peer in prepared:
                index=peer['index'];path=peer['path'];number=peer['number']
                config={'directory':str(path),'listen':f'/ip4/127.0.0.1/tcp/{number}',
                'peers':[{'id':p['peer_id'],'address':f"/ip4/127.0.0.1/tcp/{p['number']}"}
                    for p in prepared if p is not peer],
                'producer_sources':[],'discovery':{'mdns':False,'dht':False},
                'runtime':{'question_interval_ms':100,'proof_interval_ms':100,'mock_interest':False}}
                # Both remain ordinary nodes. The init helper creates only keys.
                config['runtime']['jobs']={'solving':{'mock':
                    {'outcome':'failed'} if index==5 else {'result_delay_ms':5000}}}
                (path/'config.json').write_text(json.dumps(config)+'\n')
            for peer in prepared:
                path=peer['path'];peer['port'].close()
                cli(binary,path,'interest','Set theory');ordinary_start(binary,path,output,end)
                assert json.loads((path/'identity.json').read_bytes())['peer_id']==peer['peer_id']
                control=json.loads((path/'control.json').read_bytes());identity=process_identity(control['pid']);assert identity
                save(output/(path.name+'.process.json'),identity)
                wait(lambda:any(e.get('event')=='interest_model_ready' for e in logs(path)),end)
                client=next(e['client'] for e in logs(path) if e.get('event')=='interest_client_started')
                active.append((path,identity,client))
        finally:
            for port in ports:port.close()
        node,identity,client=active[0];other,other_identity,other_client=active[1]
        def bidirectional_peering():
            witnesses=[]
            for current,partner in [(prepared[0],prepared[1]),(prepared[1],prepared[0])]:
                events=[e for e in logs(current['path']) if e.get('event') in ['connected','disconnected']
                    and e.get('peer')==partner['peer_id']]
                if not events or events[-1].get('connections',0)==0:return None
                witnesses.append({'node':current['peer_id'],'other_peer':partner['peer_id'],'event':events[-1]})
            return witnesses
        save(output/'bidirectional-static-peering.json',{'witnesses':wait(bidirectional_peering,end)})
        def delayed_solve():
            state=journal(other)
            if not state:return None
            ready={e['job'] for e in logs(other) if e.get('event')=='research_working' and e.get('phase')=='result_ready'}
            for record in state['records'].values():
                if (record['input']['role']=='solve' and record['state']=='running' and record['result'] is None
                    and record['id'] in ready and record['settings']['mock']['result_delay_ms']==5000):
                    return record
            return None
        reserved=wait(delayed_solve,end);reserved_id=reserved['id']
        save(output/'other-delayed-solve.reserved.json',{'record':reserved,'peer':other_identity,
            'result_ready':next(e for e in logs(other) if e.get('event')=='research_working'
                and e.get('phase')=='result_ready' and e.get('job')==reserved_id),
            'scope':'ordinary native Solve reservation, no completed proof yet'})
        fd_probes=[]
        for where,count,tag in [('header',32,'header-many'),('body',32,'body-many'),('header',32,'header-repeat')]:
            path,sender=host.rights(client,where,count,tag)
            wait(lambda:any(e.get('event')=='interest_model_observation' and e.get('model',{}).get('probe')==tag for e in logs(node)),end)
            probe=os.open(path,os.O_RDWR|os.O_NOFOLLOW)
            fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB);os.close(probe)
            names=fd_names(identity['pid'])
            assert sender.fileno()>=0 and str(path) not in names
            fd_probes.append({'where':where,'count':count,'lease_free_while_sender_open':True,'node_fd_names':names})
        affected=live_readers(node,identity);assert len(affected)==1
        old_reader=affected[0]
        fault_offset=len(logs(node));known_ids={e['id'] for e in logs(node) if e.get('event')=='accepted'}
        save(output/'partial-reader.identity.before.json',{'reader':old_reader,'host_client':client,'generation':host.nonce,'fault_log_offset':fault_offset})
        host.partial(client)
        wait(lambda:any(e.get('event')=='interest_client_reaped' and e.get('pid')==old_reader['pid'] for e in logs(node)[fault_offset:]),end)
        wait(lambda:kernel_birth(old_reader['pid'])!=old_reader['kernel_birth'],end)
        # The configured delay is not proof of freshness: require the exact
        # reserved job to remain without any Result at the confirmed fault.
        confirmed_fault_offset=len(logs(node))
        known_ids={e['id'] for e in logs(node) if e.get('event')=='accepted'}
        other_fault_offset=len(logs(other))
        other_known_ids={e['id'] for e in logs(other) if e.get('event')=='accepted'}
        held=journal(other)['records'][str(reserved_id)]
        assert held['state']=='running' and held['result'] is None
        assert held['input']==reserved['input'] and held['binding']==reserved['binding']
        assert not any(e.get('event')=='proof_generated' and e.get('job')==reserved_id for e in logs(other))
        save(output/'other-delayed-solve.at-confirmed-fault.json',{'record':held,
            'affected_send_offset':fault_offset,'affected_confirmed_fault_offset':confirmed_fault_offset,
            'other_log_offset':other_fault_offset,
            'affected_known_ids':sorted(known_ids),'other_known_ids':sorted(other_known_ids),
            'reader_original_identity_gone':old_reader,'result_absent':True})
        assert cli(binary,node,'status')['running'] and cli(binary,other,'status')['running']
        other_peer=next(e['peer_id'] for e in logs(other) if e.get('event')=='starting')
        completed_record=None
        def fetched_after_fault():
            nonlocal completed_record
            events=logs(node)[confirmed_fault_offset:]
            other_events=logs(other)[other_fault_offset:]
            if completed_record is None:
                record=(journal(other) or {}).get('records',{}).get(str(reserved_id))
                if not record or record['state']!='complete' or not record['result'] or record['result']['kind']!='proof':return None
                for key in ['id','input','binding','provider','configuration','settings','created_ms','expires_ms']:
                    assert record[key]==reserved[key]
                assert set(record['result'])=={'kind','value'}
                native=record['result']['value'];assert set(native)=={'source','helpers'}
                assert isinstance(native['source'],str) and native['source']
                assert isinstance(native['helpers'],list) and all(isinstance(item,str) for item in native['helpers'])
                save(output/'other-delayed-solve.completed.json',{'record':record,'clock':CLOCK,
                    'observed_at':now(),'source_sha256':hashlib.sha256(native['source'].encode()).hexdigest(),
                    'scope':'exact native completion captured once before legitimate journal retirement'})
                completed_record=record
            record=completed_record
            generated=next((e for e in other_events if e.get('event')=='proof_generated' and e.get('job')==reserved_id),None)
            if not generated:return None
            accepted=next((e for e in other_events if e.get('event')=='accepted'
                and e.get('source')=='mock_producer' and e.get('id')==generated['id']),None)
            if not accepted:return None
            assert generated['id'] not in other_known_ids
            objects=[o for o in stored_objects(SimpleNamespace(directory=other)) if o['proof_id']==generated['id']]
            if len(objects)!=1:return None
            obj=objects[0];assert proof_id(obj['statement_id'],obj['proof'])==obj['proof_id']
            for event in events:
                if event.get('event')=='accepted' and event.get('source')=='fetch' and event['id'] not in known_ids and event['id']==generated['id']:
                    response=next((e for e in events if e.get('event')=='exchange_response' and e.get('peer')==other_peer
                        and e.get('kind')=='object' and e.get('object_id')==event['id']),None)
                    if response:return {'accepted':event,'peer_response':response,'peer_id':other_peer,'proof_id':event['id'],
                        'other_solve_record':record,'other_generated':generated,'other_native_accepted':accepted,
                        'other_stored_object':obj,'native_source':record['result']['value']['source'],
                        'native_helpers':record['result']['value']['helpers'],
                        'native_source_sha256':hashlib.sha256(record['result']['value']['source'].encode()).hexdigest()}
            return None
        gossip=wait(fetched_after_fault,end)
        host.marker(other_client,'other-progress')
        wait(lambda:any(e.get('model',{}).get('probe')=='other-progress' for e in logs(other)),end)
        def repaired():
            actual=live_readers(node,identity)
            with host.lock:attached=client in host.clients
            ready=any(e.get('event')=='interest_model_ready' and e.get('model',{}).get('generation')==host.nonce for e in logs(node)[fault_offset:])
            if len(actual)==1 and actual[0]['pid']!=old_reader['pid'] and attached and ready:return actual[0]
            return None
        replacement=wait(repaired,end)
        save(output/'partial-reader.replacement.ready.json',{'old_identity_absent':old_reader,'actual_reader':replacement,'fresh_ready':True,'actual_host_attachment':True,'proof_gossip':gossip})
        for path,ident,_ in active:
            for event in logs(path):
                if event.get('event')=='interest_client_started':
                    current=process_identity(event['pid'])
                    if current:
                        assert not any(str(path)+'/' in name for name in fd_names(current['pid']))
        eof_offset=len(logs(node))
        with host.lock:current_channel=host.clients[client]
        save(output/'eof-reader.identity.before.json',{'reader':replacement,'client':client,'generation':host.nonce})
        current_channel.shutdown(socket.SHUT_RDWR)
        wait(lambda:any(e.get('event')=='interest_client_reaped' and e.get('pid')==replacement['pid'] for e in logs(node)[eof_offset:]),end)
        wait(lambda:kernel_birth(replacement['pid'])!=replacement['kernel_birth'],end)
        assert not live_readers(node,identity) and cli(binary,node,'status')['running']
        live_reader=next(e['pid'] for e in reversed(logs(other)) if e.get('event')=='interest_client_started')
        live_identity=process_identity(live_reader);assert live_identity and live_identity['group']==other_identity['group']
        os.kill(live_reader,signal.SIGSTOP)
        save(output/'suspended-reader.primary.json',{'identity':live_identity,'node':other_identity,'action':'ordinaryStop'})
        budget.begin()
        try:cli(binary,other,'stop',timeout=max(.001,min(1.0,budget.remaining()-.4)))
        finally:budget.end()
        assert kernel_birth(live_reader) is None and not process_group(other_identity)
        restart_offset=len(logs(other))
        ordinary_start(binary,other,output,end)
        control=json.loads((other/'control.json').read_bytes());crash_identity=process_identity(control['pid']);assert crash_identity
        # A restart keeps its original journal/allowance; it creates only a
        # fresh ordinary node/reader lifecycle for the group-crash witness.
        (output/(other.name+'.process.json')).unlink()
        save(output/(other.name+'.process.json'),crash_identity)
        wait(lambda:any(e.get('event')=='interest_model_ready' for e in logs(other)[restart_offset:]
            if e.get('model',{}).get('generation')==host.nonce),end)
        reader=next(e['pid'] for e in reversed(logs(other)) if e.get('event')=='interest_client_started')
        wait(lambda:kernel_birth(reader),end)
        reader_identity=process_identity(reader);assert reader_identity and reader_identity['group']==crash_identity['group']
        os.kill(reader,signal.SIGSTOP)
        save(output/'daemon-group-crash.primary.json',{'node':crash_identity,'reader':reader_identity,'action':'SIGKILL owneddaemonGroup'})
        assert kernel_birth(crash_identity['pid'])==crash_identity['kernel_birth']
        os.killpg(crash_identity['group'],signal.SIGKILL)
        wait(lambda:not process_group(crash_identity),end)
        assert kernel_birth(reader) is None
        summary['cases']['live_reader_custody']={'fd_probes':fd_probes,'partial_reader_reaped':True,'eof_reader_reaped':True,'suspended_reader_ordinaryStop_reaped':True,'suspended_reader_groupCrash_absent':True,
            'ordinary_nodes_survived_reader_fault':True,'independent_peer_and_client_progress':True,'fresh_proof_gossip_after_reader_fault':gossip,'partial_reader_before':old_reader,'replacement_ready':replacement,'eof_original_identity_absent':True,'fixture_only':True}
        save(output/'live_reader_custody.primary.json',summary['cases']['live_reader_custody'])
        summary['result']='pass'
    except BaseException as error:summary['error']=repr(error)
    finally:
        try:save(output/'primary.json',summary)
        except BaseException as fault:summary['primary_persist_error']=repr(fault);summary['result']='fail'
        cleanup_errors=[]
        try:
            if budget.state['started'] is None:budget.begin()
            summary['cleanup']=stop_nodes(binary,output,budget.remaining())
        except BaseException as fault:
            summary['cleanup']={'groups_empty':False,'errors':[repr(fault)],'elapsed':None}
        if host is not None:
            try:host.close()
            except BaseException as error:summary['cleanup']['errors'].append(repr(error))
        try:
            if budget.state['started'] is not None:budget.end()
        except BaseException as fault:summary['cleanup']['errors'].append(repr(fault))
        try:os.close(write_end)
        except BaseException as fault:summary['cleanup']['errors'].append(repr(fault))
        # Sequential owners borrow the persisted remainder. Guardian cleanup
        # writes its own elapsed debit, including recovery after parent loss.
        guardian_validation='direct Child wait'
        try:
            actual_wait=guardian_child_wait(guard,output,max(.001,budget.remaining()),'guardian-direct-wait.json')
            summary['guardian_direct_wait']=actual_wait
            assert actual_wait['reaped'] and not actual_wait['error'] and not actual_wait.get('persist_error'),'guardian direct Child wait evidence'
            assert actual_wait['exit_code']==0,'guardian direct Child exit'
            guardian_validation='receipt schema and startup authority'
            receipt=json.loads((output/'guardian-receipt.json').read_bytes())
            assert receipt['schema']==1 and guardian_identity is not None,'guardian receipt schema/startup identity'
            guardian_validation='fixed launched script and all arguments'
            assert guardian_binding(receipt['guardian'])['script_arguments']==' '.join(guardian_command[1:]),'guardian terminal fixed launch arguments'
            assert guardian_binding(receipt['guardian'])==guardian_binding(guardian_identity),'guardian startup/terminal binding'
            guardian_validation='receipt artifact and closure binding'
            assert receipt['binary_sha256']==digest(binary) and receipt['driver_sha256']==digest(__file__),'guardian binary/driver binding'
            assert receipt['output']==str(output) and receipt['maximum_cleanup']==args.cleanup,'guardian output/cleanup contract'
            assert receipt['groups_empty'] and not receipt['errors'],'guardian cleanup closure'
            assert kernel_birth(guard.pid)!=guardian_identity['kernel_birth'],'guardian kernel identity after direct wait'
            budget=Cleanup(output,args.cleanup)
            assert budget.state['started'] is None and budget.state['spent']<=args.cleanup,'guardian persisted cleanup budget'
            summary['guardian']=receipt
            summary['guardian_wait']={'exit_code':guard.returncode,'reaped':True,
                'binding':guardian_binding(guardian_identity),'kernel_identity_gone':True}
        except BaseException as error:
            summary['cleanup']['errors'].append(repr(error))
            summary['guardian_validation_failure']={'predicate':guardian_validation,'error':repr(error)}
            if guard.poll() is None:
                kill_start=now();guard.kill()
                canceled_wait=guardian_child_wait(guard,output,max(.001,budget.remaining()),'guardian-cancel-wait.json')
                summary['guardian_cancel_wait']=canceled_wait
                if not canceled_wait['reaped'] or canceled_wait['error'] or canceled_wait.get('persist_error'):
                    summary['cleanup']['errors'].append('guardian cancel wait '+repr(canceled_wait))
                budget=Cleanup(output,args.cleanup);budget.recover()
                budget.state['spent']+=now()-kill_start
                budget.state['remaining']=max(0,args.cleanup-budget.state['spent']);budget.persist()
        summary['cleanup']['aggregate_spent']=budget.state['spent']
        summary['cleanup']['aggregate_remaining']=budget.remaining()
        if summary['cleanup']['errors'] or not summary['cleanup']['groups_empty']:summary['result']='fail'
        save(output/'summary.json',summary)
    print(json.dumps({'result':summary['result'],'output':str(output)}))
    return 0 if summary['result']=='pass' else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--identity-binary',type=Path)
    parser.add_argument('--timeout',type=float,default=30);parser.add_argument('--cleanup',type=float,default=9.9)
    parser.add_argument('--guardian',action='store_true');parser.add_argument('--fd',type=int)
    parser.add_argument('--reader-only',action='store_true')
    args=parser.parse_args()
    assert 0<args.timeout<=60 and 0<args.cleanup<=10
    if args.guardian:
        identity=process_identity(os.getpid());assert identity and identity['group']==os.getpid()
        ready=__import__('select').select([args.fd],[],[],args.timeout)[0]
        if ready:assert os.read(args.fd,1)==b''
        os.close(args.fd)
        budget=Cleanup(args.output,args.cleanup)
        try:
            budget.recover();budget.begin()
            result=stop_nodes(args.binary,args.output,budget.remaining())
        except BaseException as fault:result={'groups_empty':False,'errors':[repr(fault)],'elapsed':None}
        finally:
            try:
                if budget.state['started'] is not None:budget.end()
            except BaseException as fault:result['errors'].append(repr(fault))
        receipt=guardian_receipt(args,'parentEOF' if ready else 'originalWallDeadline',budget,result,identity)
        save(args.output/'guardian-receipt.json',receipt)
        raise SystemExit(0 if result['groups_empty'] and not result['errors'] else 1)
    raise SystemExit(main(args))
