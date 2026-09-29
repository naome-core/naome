"""Run negative vectors against a saved research block's arithmetic receipt."""
import json,pathlib,sys,tempfile
import numpy as np
from field_verify import verify

def main(base,prompt):
    base=pathlib.Path(base);prompt=pathlib.Path(prompt)
    meta=json.loads(base.with_suffix('.json').read_text())
    def check(label,mutate):
        with tempfile.TemporaryDirectory(prefix='naome-field-attack-') as d:
            d=pathlib.Path(d);j=d/'receipt.json';n=d/'witness.npz';p=d/'proof.nao'
            j.write_bytes(base.with_suffix('.json').read_bytes())
            n.write_bytes(base.with_suffix('.npz').read_bytes())
            p.write_bytes(base.with_suffix('.nao').read_bytes())
            mutate(j,n,p)
            try:verify(j,n,p,meta['predecessor_sha256'],prompt)
            except Exception as e:return {'name':label,'rejected':True,'reason':str(e)}
            return {'name':label,'rejected':False}
    def alter_json(key,value):
        def f(j,n,p):
            obj=json.loads(j.read_text());obj[key]=value;j.write_text(json.dumps(obj))
        return f
    def alter_array(key):
        def f(j,n,p):
            with np.load(n,allow_pickle=False) as z:data={k:z[k] for k in z.files}
            x=data[key].copy();x.flat[0]=x.flat[0]+1;data[key]=x
            np.savez_compressed(n,**data)
        return f
    def alter_transcript(j,n,p):
        obj=json.loads(j.read_text());obj['fields'][0]['transcript_sha256']='00'*32;j.write_text(json.dumps(obj))
    cases=[check('A cell',alter_array('a')),check('B cell',alter_array('b')),
           check('activation scale',alter_array('a_scale')),
           check('decoded output',alter_array('c_int32')),
           check('transcript hash',alter_transcript),
           check('nonce',alter_json('job_nonce_hex','00'*32)),
           check('predecessor',alter_json('predecessor_sha256','00'*32)),
           check('model revision',alter_json('model_revision','fake')),
           check('proof bytes',lambda j,n,p:p.write_text(p.read_text()+'\n#changed\n'))]
    result={'all_rejected':all(x['rejected'] for x in cases),'vectors':cases}
    print(json.dumps(result,indent=2))
    if not result['all_rejected']:raise SystemExit(1)

if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('usage: attack_vectors.py BLOCK_WORK_STEM PROMPT_TEMPLATE')
    main(sys.argv[1],sys.argv[2])
