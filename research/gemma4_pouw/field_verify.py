"""CPU-only independent replay of the experimental Gemma field receipt."""
import hashlib,json,pathlib,sys
import numpy as np
from prompt_binding import render

ROOT=pathlib.Path(__file__).resolve().parent
PRIMES=(65521,65519)
CHUNK=128

def sha(a):return hashlib.sha256(np.ascontiguousarray(a).tobytes()).hexdigest()

def uniform(seed,label,length,q):
    values=np.empty(length,dtype=np.int64)
    for i in range(length):
        counter=0
        while True:
            digest=hashlib.sha256(seed+label+i.to_bytes(4,'little')+counter.to_bytes(4,'little')).digest()
            value=int.from_bytes(digest[:2],'little')
            if 0<value<q:
                values[i]=value;break
            counter+=1
    return values

def encode(a,b,seed,q):
    m,k=a.shape;n,kb=b.shape
    assert k==kb
    el=uniform(seed,b'EL'+q.to_bytes(4,'little'),m,q)
    er=uniform(seed,b'ER'+q.to_bytes(4,'little'),k,q)
    fl=uniform(seed,b'FL'+q.to_bytes(4,'little'),n,q)
    fr=uniform(seed,b'FR'+q.to_bytes(4,'little'),k,q)
    ae=(a.astype(np.int64)+el[:,None]*er[None,:])%q
    bf=(b.astype(np.int64)+fl[:,None]*fr[None,:])%q
    return ae.astype(np.uint32),bf.astype(np.uint32),(el,er,fl,fr)

def product(a,b,q):
    m,k=a.shape;n=b.shape[0];chunks=(k+CHUNK-1)//CHUNK
    # Encoded entries lie in [0, q). Every exact integer product and every
    # partial sum fits in a float64 significand for this fixed workload, so
    # BLAS can calculate each chunk faster than NumPy's integer matmul. Cast
    # the exact integer result back before modular reduction.
    require(k*(q-1)**2 < 2**53,'inexact float64 product bound')
    require(a.min()>=0 and a.max()<q and b.min()>=0 and b.max()<q,'encoded field range')
    af=a.astype(np.float64);bf=b.astype(np.float64)
    partials=np.empty((m,n,chunks),dtype=np.uint32)
    c=np.zeros((m,n),dtype=np.int64)
    for i in range(chunks):
        start=i*CHUNK;end=min(start+CHUNK,k)
        chunk=(af[:,start:end]@bf[:,start:end].T).astype(np.int64)
        c=(c+chunk)%q
        partials[:,:,i]=c
    return c.astype(np.uint32),partials

def decode(p,a,b,f,q):
    el,er,fl,fr=f
    af=((a.astype(np.int64)@fr)%q)[:,None]*fl[None,:]%q
    bf=(b.astype(np.int64)+fl[:,None]*fr[None,:])%q
    ebf=el[:,None]*((bf@er)%q)[None,:]%q
    return (p.astype(np.int64)-af-ebf)%q

def crt(a,b):
    p1,p2=PRIMES
    x=a.astype(np.int64)+p1*(((b.astype(np.int64)-a.astype(np.int64))*pow(p1,-1,p2))%p2)
    mod=p1*p2;x[x>mod//2]-=mod
    if np.any(x<-(2**31)) or np.any(x>=2**31):raise ValueError('CRT range')
    return x.astype(np.int32)

def require(test,reason):
    if not test:raise ValueError(reason)

def verify(json_path,npz_path,proof_path,expected_predecessor=None,prompt_path=None):
    meta=json.loads(pathlib.Path(json_path).read_text())
    require(meta['profile']=='naome-gemma-field-research-v1','profile')
    require(meta['model_revision']=='73bcf09092aa277861d5a191b989b666f7f32e8f','model revision')
    if expected_predecessor is None:
        expected_predecessor=hashlib.sha256(b'naome-gemma-field-research-genesis-v1').hexdigest()
    require(meta['predecessor_sha256']==expected_predecessor,'predecessor')
    if prompt_path is None:prompt_path=ROOT/'gemma4_12b_universal_reflexivity.prompt.txt'
    template=pathlib.Path(prompt_path).read_text()
    prompt=render(template,meta['predecessor_sha256'],meta['job_nonce_hex']) if meta.get('prompt_binding') else template
    require(meta['prompt_sha256']==hashlib.sha256(prompt.encode()).hexdigest(),'prompt')
    require(meta['source_sha256']==hashlib.sha256(pathlib.Path(proof_path).read_bytes()).hexdigest(),'proof bytes')
    with np.load(npz_path,allow_pickle=False) as z:
        a=z['a'];b=z['b'];sa=z['a_scale'];sb=z['b_scale'];saved=z['c_int32']
    require(a.dtype==np.int8 and b.dtype==np.int8,'quant dtype')
    require(a.ndim==2 and a.shape[1]==3840 and 16<=a.shape[0]<=1024 and b.shape==(2048,3840),'matrix shape')
    require(meta['input_shape']==[1,a.shape[0],3840] and meta['output_shape']==[1,a.shape[0],2048],'recorded shape')
    require(int(a.min())>=-63 and int(a.max())<=63 and int(b.min())>=-63 and int(b.max())<=63,'int7 range')
    require(sa.dtype==np.float32 and sb.dtype==np.float32 and sa.shape==(a.shape[0],) and sb.shape==(b.shape[0],),'scale shapes')
    require(np.all(np.isfinite(sa)) and np.all(sa>0) and np.all(np.isfinite(sb)) and np.all(sb>0),'scale values')
    require(sha(sa)==meta['a_scale_sha256'] and sha(sb)==meta['b_scale_sha256'],'scale hashes')
    seed=hashlib.sha256(b'naome-gemma-field-research-v1\0'+bytes.fromhex(meta['predecessor_sha256'])+
                        bytes.fromhex(meta['job_nonce_hex'])+bytes.fromhex(meta['prompt_sha256'])+
                        bytes.fromhex(sha(a))+bytes.fromhex(sha(b))).digest()
    require(seed.hex()==meta['challenge_seed_hex'],'challenge seed')
    residues=[]
    for expected,q in zip(meta['fields'],PRIMES):
        require(expected['q']==q,'field order')
        ae,bf,factors=encode(a,b,seed,q)
        require(sha(ae)==expected['encoded_a_sha256'] and sha(bf)==expected['encoded_b_sha256'],'encoded matrices')
        p,t=product(ae,bf,q)
        require(sha(p)==expected['product_sha256'] and sha(t)==expected['transcript_sha256'],'Metal transcript/product')
        require(list(t.shape)==expected['transcript_shape'],'transcript shape')
        residues.append(decode(p,a,b,factors,q))
    c=crt(*residues)
    require(sha(c)==meta['decoded_product_sha256'] and np.array_equal(c,saved),'decoded int32')
    y=(c.astype(np.float32)*sa[:,None]*sb[None,:]).astype(np.float32)
    bits=y.view(np.uint32)
    rounded=(bits+np.uint32(0x7fff)+((bits>>16)&1)).astype(np.uint32)
    y_bf16=(rounded&np.uint32(0xffff0000)).view(np.float32)
    require(sha(y_bf16)==meta['returned_projection_sha256'],'scaled bfloat16 projection')
    # The independent check calculates every intermediate in both fields. It
    # does not prove that A was produced by an authentic model inference.
    return {'valid':True,'challenge_seed_hex':seed.hex(),'decoded_sha256':sha(c),
            'transcript_sha256':[f['transcript_sha256'] for f in meta['fields']]}

if __name__=='__main__':
    base=ROOT/'gemma_field_infer'
    args=sys.argv[1:] or [str(base.with_suffix('.json')),str(base.with_suffix('.npz')),str(base.with_suffix('.nao'))]
    print(json.dumps(verify(*args)))
