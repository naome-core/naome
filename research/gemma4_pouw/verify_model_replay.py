"""Independent Gemma model replay of one experimental field-work receipt."""
import hashlib,json,os,pathlib,subprocess,sys,tempfile
from field_verify import verify as verify_field,require

ROOT=pathlib.Path(__file__).resolve().parent
REPO=ROOT.parents[1]
PYTHON=os.environ.get('NAOME_GEMMA_PYTHON','/private/tmp/naome-llm-venv/bin/python')
WEIGHTS=pathlib.Path(os.environ.get('NAOME_GEMMA_MODEL','/private/tmp/naome-gemma4-12b'))
SHARDS={
    'model-00001-of-00002.safetensors':'0d58feed0c98a69c07317b4481aeae5ab2785f12a496ea96ab24c4842808de78',
    'model-00002-of-00002.safetensors':'5b00a1bcb596ce6e827b4cdea6ecf2a0f35bb01306eb87c1ea4b3bcde36c7755',
}
COMPARE=('input_sha256','packed_weight_sha256','scale_sha256','biases_sha256',
         'challenge_seed_hex','decoded_product_sha256','returned_projection_sha256',
         'a_scale_sha256','b_scale_sha256',
         'generated_token_ids','raw_sha256','source_sha256','prompt_sha256')
COMPARE += ('prompt_binding',)

def hash_file(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for part in iter(lambda:f.read(8*1024*1024),b''):h.update(part)
    return h.hexdigest()

def verify(json_path,npz_path,proof_path,expected_predecessor,check_weights=True,prompt_path=None):
    json_path=pathlib.Path(json_path);npz_path=pathlib.Path(npz_path);proof_path=pathlib.Path(proof_path)
    meta=json.loads(json_path.read_text())
    require(meta['predecessor_sha256']==expected_predecessor,'predecessor mismatch')
    if prompt_path is None:prompt_path=ROOT/'gemma4_12b_universal_reflexivity.prompt.txt'
    arithmetic=verify_field(json_path,npz_path,proof_path,expected_predecessor,prompt_path)
    if check_weights:
        for name,digest in SHARDS.items():require(hash_file(WEIGHTS/name)==digest,'model weight hash '+name)
    with tempfile.TemporaryDirectory(prefix='naome-gemma-replay-') as tmp:
        cmd=[PYTHON,str(ROOT/'gemma_field_infer.py'),'--predecessor',expected_predecessor,
             '--nonce',meta['job_nonce_hex'],'--output-dir',tmp,'--name','replay',
             '--prompt-file',str(prompt_path)]
        if meta.get('prompt_binding'):cmd.append('--bind-prompt')
        run=subprocess.run(cmd,cwd=REPO,capture_output=True,text=True)
        require(run.returncode==0,'Gemma replay failed: '+run.stderr[-1000:])
        base=pathlib.Path(tmp)/'replay'
        replay=json.loads(base.with_suffix('.json').read_text())
        for key in COMPARE:require(meta[key]==replay[key],'Gemma replay '+key)
        require(meta['fields']==replay['fields'],'Gemma replay field commitments')
        require(proof_path.read_bytes()==base.with_suffix('.nao').read_bytes(),'Gemma replay proof bytes')
        require(meta['checker_exit']==0 and replay['checker_exit']==0,'NAOME checker')
        checked=subprocess.run([str(REPO/'target/debug/naome-author'),'proof',str(proof_path)],capture_output=True,text=True)
        require(checked.returncode==0,'NAOME checker current proof')
    return {'valid':True,'proof_sha256':meta['source_sha256'],
            'challenge_seed_hex':meta['challenge_seed_hex'],
            'arithmetic':arithmetic,'replayed_tokens':len(meta['generated_token_ids'])}

if __name__=='__main__':
    if len(sys.argv)!=5:raise SystemExit('usage: verify_model_replay.py RECEIPT.json WITNESS.npz PROOF.nao PREDECESSOR_SHA256')
    print(json.dumps(verify(*sys.argv[1:])))
