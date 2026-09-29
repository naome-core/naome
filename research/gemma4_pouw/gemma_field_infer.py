"""Generate a checked Gemma proof with exact encoded field work in its first k_proj.

Research v1: independently replayable arithmetic, no PoUW hardness claim.
"""
import argparse,hashlib,json,os,pathlib,re,subprocess,sys,time
import numpy as np
import mlx.core as mx
import mlx.nn as nn
import mlx_lm.models.gemma4 as gemma4
from mlx_lm import load,stream_generate
from mlx_lm.sample_utils import make_sampler
from field_work import PRIMES,encode,metal_product,decode,crt_signed,sha
from prompt_binding import render

sys.modules['mlx_lm.models.gemma4_unified']=gemma4
_sanitize=gemma4.Model.sanitize
gemma4.Model.sanitize=lambda self,w:_sanitize(self,{k:v for k,v in w.items() if not k.removeprefix('model.').startswith('vision_embedder.')})

ROOT=pathlib.Path(__file__).resolve().parent
MODEL=os.environ.get('NAOME_GEMMA_MODEL','/private/tmp/naome-gemma4-12b')
DEFAULT_PROMPT=ROOT/'gemma4_12b_universal_reflexivity.prompt.txt'
DEFAULT_PREDECESSOR=hashlib.sha256(b'naome-gemma-field-research-genesis-v1').digest()
DEFAULT_JOB_NONCE=bytes.fromhex('2026092900000000000000000000000000000000000000000000000000000001')

def as_np(x):
    mx.eval(x)
    return np.array(x.astype(mx.float32))

class FieldProjection(nn.Module):
    def __init__(self, original, prompt_hash, predecessor, nonce):
        super().__init__()
        self.original=original
        self.prompt_hash=prompt_hash
        self.predecessor=predecessor
        self.nonce=nonce
        self.calls=0
        self.payload=None

    def __call__(self,x):
        self.calls+=1
        if self.calls!=1:return self.original(x)
        t=time.perf_counter()
        x_np=as_np(x)
        w=mx.dequantize(self.original.weight,scales=self.original.scales,biases=self.original.biases,
                        group_size=self.original.group_size,bits=self.original.bits,mode=self.original.mode)
        w_np=as_np(w)
        m,k=x_np.shape[-2:];n=w_np.shape[0]
        xa=x_np.reshape(m,k)
        a_scale=np.maximum(np.max(np.abs(xa),axis=1)/63.,1e-30).astype(np.float32)
        b_scale=np.maximum(np.max(np.abs(w_np),axis=1)/63.,1e-30).astype(np.float32)
        a=np.clip(np.rint(xa/a_scale[:,None]),-63,63).astype(np.int8)
        b=np.clip(np.rint(w_np/b_scale[:,None]),-63,63).astype(np.int8)
        seed=hashlib.sha256(b'naome-gemma-field-research-v1\0'+self.predecessor+self.nonce+
                            self.prompt_hash+bytes.fromhex(sha(a))+bytes.fromhex(sha(b))).digest()
        residues=[];fields=[]
        for q in PRIMES:
            encoded_a,encoded_b,factors=encode(a,b,seed,q)
            p,tr=metal_product(encoded_a,encoded_b,q)
            residues.append(decode(p,a,b,factors,q))
            fields.append({'q':q,'encoded_a_sha256':sha(encoded_a),'encoded_b_sha256':sha(encoded_b),
                           'product_sha256':sha(p),'transcript_sha256':sha(tr),
                           'transcript_shape':list(tr.shape)})
        c=crt_signed(*residues)
        scaled=(c.astype(np.float32)*a_scale[:,None]*b_scale[None,:]).reshape(m and x_np.shape[:-1]+(n,))
        y=mx.array(scaled).astype(x.dtype)
        mx.eval(y)
        self.payload={'a':a,'b':b,'a_scale':a_scale,'b_scale':b_scale,'c_int32':c,
                      'a_scale_sha256':sha(a_scale),'b_scale_sha256':sha(b_scale),
                      'input_shape':list(x_np.shape),'output_shape':list(y.shape),
                      'input_sha256':sha(x_np),'packed_weight_sha256':sha(np.array(self.original.weight)),
                      'scale_sha256':sha(as_np(self.original.scales)),
                      'biases_sha256':sha(as_np(self.original.biases)),
                      'predecessor_sha256':self.predecessor.hex(),'job_nonce_hex':self.nonce.hex(),
                      'challenge_seed_hex':seed.hex(),'fields':fields,
                      'decoded_product_sha256':sha(c),'returned_projection_sha256':sha(as_np(y)),
                      'hook_s':time.perf_counter()-t}
        return y

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--predecessor',default=DEFAULT_PREDECESSOR.hex())
    ap.add_argument('--nonce',default=DEFAULT_JOB_NONCE.hex())
    ap.add_argument('--output-dir',default=str(ROOT.parents[1]/'.local'/'gemma4-pouw-research'))
    ap.add_argument('--name',default='gemma_field_infer')
    ap.add_argument('--prompt-file',default=str(DEFAULT_PROMPT))
    ap.add_argument('--bind-prompt',action='store_true')
    args=ap.parse_args()
    predecessor=bytes.fromhex(args.predecessor);nonce=bytes.fromhex(args.nonce)
    if len(predecessor)!=32 or len(nonce)!=32:raise ValueError('predecessor and nonce must be 32 bytes')
    outdir=pathlib.Path(args.output_dir);outdir.mkdir(parents=True,exist_ok=True)
    stem=args.name
    prompt_template=pathlib.Path(args.prompt_file).read_text()
    prompt=render(prompt_template,args.predecessor,args.nonce) if args.bind_prompt else prompt_template
    (outdir/(stem+'.prompt.txt')).write_text(prompt)
    t=time.perf_counter();model,tok=load(MODEL);load_s=time.perf_counter()-t
    template=(pathlib.Path(MODEL)/'chat_template.jinja').read_text()
    text=tok.apply_chat_template([{'role':'user','content':prompt}],chat_template=template,
                                 tokenize=False,add_generation_prompt=True,enable_thinking=False)
    prompt_hash=hashlib.sha256(prompt.encode()).digest()
    original=model.language_model.model.layers[0].self_attn.k_proj
    hook=FieldProjection(original,prompt_hash,predecessor,nonce)
    model.language_model.model.layers[0].self_attn.k_proj=hook
    mx.reset_peak_memory();t=time.perf_counter()
    responses=list(stream_generate(model,tok,text,max_tokens=320,sampler=make_sampler(temp=0)))
    generation_s=time.perf_counter()-t
    raw=''.join(r.text for r in responses)
    token_ids=[int(r.token) for r in responses if r.finish_reason is None]
    (outdir/(stem+'.raw.txt')).write_text(raw)
    match=re.search(r'foundation\s*=\s*"naome:zfc"[\s\S]*?return\s+[A-Za-z_]\w*',raw)
    source=(match.group(0)+'\n') if match else raw.strip()+'\n'
    proof_path=outdir/(stem+'.nao');proof_path.write_text(source)
    checked=subprocess.run(['target/debug/naome-author','proof',str(proof_path)],capture_output=True,text=True)
    payload=hook.payload
    if payload is None:raise RuntimeError('field projection was not used')
    arrays={k:payload.pop(k) for k in ('a','b','a_scale','b_scale','c_int32')}
    np.savez_compressed(outdir/(stem+'.npz'),**arrays)
    payload.update({'profile':'naome-gemma-field-research-v1','model_revision':'73bcf09092aa277861d5a191b989b666f7f32e8f',
                    'prompt_sha256':prompt_hash.hex(),'prompt_binding':args.bind_prompt,
                    'prompt_tokens':len(tok.encode(text)),
                    'generated_token_ids':token_ids,'raw_sha256':hashlib.sha256(raw.encode()).hexdigest(),
                    'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
                    'checker_exit':checked.returncode,'checker_stdout':checked.stdout,'checker_stderr':checked.stderr,
                    'projection_calls':hook.calls,'load_s':load_s,'generation_s':generation_s,
                    'mlx_peak_memory_bytes':mx.get_peak_memory()})
    (outdir/(stem+'.json')).write_text(json.dumps(payload,indent=2))
    print(json.dumps({'checker_exit':checked.returncode,'token_count':len(token_ids),'hook_s':payload['hook_s'],
                      'generation_s':generation_s,'peak_memory':payload['mlx_peak_memory_bytes']}),flush=True)

if __name__=='__main__':main()
