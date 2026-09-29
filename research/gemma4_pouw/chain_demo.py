"""Four-process local research chain with exact Gemma field-work replay.

Version 1 is an execution/validation prototype, not permissionless consensus.
"""
import hashlib,json,multiprocessing as mp,os,pathlib,subprocess,sys,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from field_verify import verify as verify_field,require
from verify_model_replay import verify as verify_model,hash_file,SHARDS

ROOT=pathlib.Path(__file__).resolve().parent
REPO=ROOT.parents[1]
PYTHON=os.environ.get('NAOME_GEMMA_PYTHON','/private/tmp/naome-llm-venv/bin/python')
PROFILE='naome-gemma-field-chain-research-v1'
PROMPTS=[ROOT/'gemma4_12b_universal_reflexivity.prompt.txt',
         ROOT/'gemma4_12b_distinct.prompt.txt']

def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(domain,obj):return hashlib.sha256(domain+canonical(obj)).hexdigest()

def genesis_for(keys):
    body={'profile':PROFILE,'protocol_version':1,'model_revision':'73bcf09092aa277861d5a191b989b666f7f32e8f',
          'model_shards':SHARDS,'prompt_sha256':[hash_file(p) for p in PROMPTS],
          'validators':[k.public_key().public_bytes_raw().hex() for k in keys],
          'quorum':3,'selection':'first locally finalized block; no fork-choice weight'}
    return {'body':body,'hash':digest(b'naome-research-genesis-v1\0',body)}

def block_hash(header):return digest(b'naome-research-block-v1\0',header)
def vote_message(block_hash_hex):return b'naome-research-vote-v1\0'+bytes.fromhex(block_hash_hex)

def paths(block_dir):
    p=pathlib.Path(block_dir)
    return p/'work.json',p/'work.npz',p/'work.nao'

def validate_block(block_dir,block,genesis,expected_height,expected_prev,check_weights=True):
    h=block['header']
    require(set(h)=={'profile','height','prev','nonce','prompt_id','receipt_sha256','witness_sha256','proof_sha256','model_revision'},'block header fields')
    require(h['profile']==PROFILE and h['height']==expected_height and h['prev']==expected_prev,'height/predecessor/profile')
    require(h['model_revision']==genesis['body']['model_revision'],'model revision')
    require(isinstance(h['prompt_id'],int) and 0<=h['prompt_id']<len(PROMPTS),'prompt id')
    require(h['prompt_id']==expected_height-1,'scheduled research question')
    require(len(bytes.fromhex(h['nonce']))==32,'nonce length')
    require(block['hash']==block_hash(h),'block hash')
    receipt,witness,proof=paths(block_dir)
    require(hash_file(receipt)==h['receipt_sha256'],'receipt commitment')
    require(hash_file(witness)==h['witness_sha256'],'witness commitment')
    require(hash_file(proof)==h['proof_sha256'],'proof commitment')
    meta=json.loads(receipt.read_text())
    require(meta['predecessor_sha256']==h['prev'] and meta['job_nonce_hex']==h['nonce'],'work challenge')
    require(meta.get('prompt_binding') is True,'challenge-bound inference prompt')
    prompt=PROMPTS[h['prompt_id']]
    require(hash_file(prompt)==genesis['body']['prompt_sha256'][h['prompt_id']],'genesis prompt')
    verify_field(receipt,witness,proof,h['prev'],prompt)
    verify_model(receipt,witness,proof,h['prev'],check_weights=check_weights,prompt_path=prompt)
    return True

def verify_qc(block,genesis):
    require(block['hash']==block_hash(block['header']),'QC block hash')
    votes=block.get('votes',[])
    require(len(votes)>=genesis['body']['quorum'],'quorum size')
    seen=set()
    for vote in votes:
        i=vote['validator']
        require(isinstance(i,int) and 0<=i<len(genesis['body']['validators']) and i not in seen,'vote signer')
        seen.add(i)
        pub=Ed25519PublicKey.from_public_bytes(bytes.fromhex(genesis['body']['validators'][i]))
        pub.verify(bytes.fromhex(vote['signature']),vote_message(block['hash']))
    return True

def node_loop(index,private_bytes,genesis,node_dir,pipe):
    key=Ed25519PrivateKey.from_private_bytes(private_bytes)
    node_dir=pathlib.Path(node_dir);node_dir.mkdir(parents=True,exist_ok=True)
    height=0;tip=genesis['hash'];weights_checked=False;validated_hash=None
    while True:
        msg=pipe.recv()
        if msg['op']=='stop':return
        try:
            if msg['op']=='verify':
                b=msg['block']
                validate_block(msg['dir'],b,genesis,height+1,tip,check_weights=not weights_checked)
                weights_checked=True
                validated_hash=b['hash']
                result={'ok':True,'validator':index,'signature':key.sign(vote_message(b['hash'])).hex()}
            elif msg['op']=='commit':
                b=msg['block'];require(b['header']['height']==height+1 and b['header']['prev']==tip,'commit linkage')
                require(b['hash']==validated_hash,'commit without local validation')
                verify_qc(b,genesis)
                with (node_dir/'ledger.jsonl').open('a') as f:f.write(json.dumps(b,sort_keys=True)+'\n')
                height+=1;tip=b['hash'];validated_hash=None;result={'ok':True,'height':height,'tip':tip}
            else:raise ValueError('unknown operation')
        except Exception as e:result={'ok':False,'reason':str(e)}
        pipe.send(result)

def produce(block_dir,height,prev,prompt_id,nonce):
    p=pathlib.Path(block_dir);p.mkdir(parents=True,exist_ok=True)
    cmd=[PYTHON,str(ROOT/'gemma_field_infer.py'),'--predecessor',prev,'--nonce',nonce,
         '--prompt-file',str(PROMPTS[prompt_id]),'--output-dir',str(p),'--name','work','--bind-prompt']
    t=time.perf_counter();run=subprocess.run(cmd,cwd=REPO,capture_output=True,text=True)
    require(run.returncode==0,'miner failed: '+run.stderr[-1000:])
    meta=json.loads((p/'work.json').read_text())
    require(meta['checker_exit']==0,'miner proof rejected')
    receipt,witness,proof=paths(p)
    header={'profile':PROFILE,'height':height,'prev':prev,'nonce':nonce,'prompt_id':prompt_id,
            'receipt_sha256':hash_file(receipt),'witness_sha256':hash_file(witness),
            'proof_sha256':hash_file(proof),'model_revision':meta['model_revision']}
    block={'header':header,'hash':block_hash(header),'votes':[]}
    return block,{'produce_s':round(time.perf_counter()-t,3),'miner_stdout':run.stdout.strip(),
                  'proof_id':meta['checker_stdout'].split('proof_id ')[1].splitlines()[0],
                  'challenge_seed':meta['challenge_seed_hex']}

def run_demo(output_dir):
    out=pathlib.Path(output_dir);out.mkdir(parents=True,exist_ok=True)
    keys=[Ed25519PrivateKey.generate() for _ in range(4)]
    genesis=genesis_for(keys)
    (out/'genesis.json').write_text(json.dumps(genesis,indent=2))
    (out/'validator_private_keys.json').write_text(json.dumps([k.private_bytes_raw().hex() for k in keys]))
    os.chmod(out/'validator_private_keys.json',0o600)
    ctx=mp.get_context('spawn');nodes=[]
    for i,key in enumerate(keys):
        parent,child=ctx.Pipe()
        proc=ctx.Process(target=node_loop,args=(i,key.private_bytes_raw(),genesis,str(out/f'node{i}'),child))
        proc.start();nodes.append((proc,parent))
    summary={'genesis_hash':genesis['hash'],'blocks':[],'node_pids':[proc.pid for proc,_ in nodes]}
    try:
        tip=genesis['hash']
        for height,prompt_id in [(1,0),(2,1)]:
            nonce=os.urandom(32).hex();block_dir=out/f'block{height}'
            block,measure=produce(block_dir,height,tip,prompt_id,nonce)
            if summary['blocks']:
                require(measure['proof_id']!=summary['blocks'][-1]['proof_id'],'reused canonical proof')
            # All four node processes stay live; serial GPU replay limits RAM.
            votes=[];validation_s=[]
            for proc,pipe in nodes:
                t=time.perf_counter();pipe.send({'op':'verify','dir':str(block_dir),'block':block})
                result=pipe.recv();validation_s.append(round(time.perf_counter()-t,3))
                require(result['ok'],'validator rejected block: '+str(result))
                votes.append({'validator':result['validator'],'signature':result['signature']})
            block['votes']=votes;verify_qc(block,genesis)
            (block_dir/'block.json').write_text(json.dumps(block,indent=2))
            for proc,pipe in nodes:
                pipe.send({'op':'commit','block':block})
                require(pipe.recv()['ok'],'node commit')
            tip=block['hash']
            summary['blocks'].append({'height':height,'hash':tip,**measure,'validation_s':validation_s,
                                      'votes':len(votes)})
            print('finalized',height,tip,flush=True)
        # A finalized tip rejects a replayed predecessor and an alternate fork.
        old=json.loads((out/'block1'/'block.json').read_text())
        nodes[0][1].send({'op':'verify','dir':str(out/'block1'),'block':old})
        summary['replayed_block_rejected']=not nodes[0][1].recv()['ok']
        fork,measure=produce(out/'fork2',2,summary['blocks'][0]['hash'],1,os.urandom(32).hex())
        nodes[1][1].send({'op':'verify','dir':str(out/'fork2'),'block':fork})
        summary['alternate_fork_rejected']=not nodes[1][1].recv()['ok']
        summary['fork_candidate_proof_id']=measure['proof_id']
        require(summary['replayed_block_rejected'] and summary['alternate_fork_rejected'],'fork/replay guards')
        (out/'summary.json').write_text(json.dumps(summary,indent=2))
        print(json.dumps(summary),flush=True)
    finally:
        for proc,pipe in nodes:
            if proc.is_alive():pipe.send({'op':'stop'})
        for proc,pipe in nodes:proc.join(timeout=10)

def replay_chain(output_dir,full_model=True):
    out=pathlib.Path(output_dir);genesis=json.loads((out/'genesis.json').read_text())
    require(genesis['hash']==digest(b'naome-research-genesis-v1\0',genesis['body']),'genesis hash')
    tip=genesis['hash']
    for height in (1,2):
        p=out/f'block{height}';b=json.loads((p/'block.json').read_text())
        require(b['header']['height']==height and b['header']['prev']==tip,'replay linkage')
        verify_qc(b,genesis)
        if full_model:validate_block(p,b,genesis,height,tip,check_weights=(height==1))
        else:
            receipt,witness,proof=paths(p)
            verify_field(receipt,witness,proof,tip,PROMPTS[b['header']['prompt_id']])
        tip=b['hash']
    return {'valid':True,'height':2,'tip':tip,'full_model':full_model}

if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('usage: chain_demo.py run|replay OUTPUT_DIR')
    if sys.argv[1]=='run':run_demo(sys.argv[2])
    elif sys.argv[1]=='replay':print(json.dumps(replay_chain(sys.argv[2])))
    else:raise SystemExit('unknown command')
