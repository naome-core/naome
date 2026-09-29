"""Demonstrate an amortized transcript shortcut for repeated public matrices.

Precompute ordinary AB cumulative chunks once. For each fresh challenge, form
the noisy transcript using low-rank cross terms, with no fresh full noisy GEMM.
This is a security counterexample for this fixed-workload prototype.
"""
import json,pathlib,sys,time
import numpy as np
from field_verify import PRIMES,CHUNK,encode,product,sha

def shortcut(base_partials,a,b,factors,q):
    el,er,fl,fr=factors
    m,k=a.shape;n=b.shape[0];chunks=base_partials.shape[-1]
    aa=a.astype(np.int64)%q;bb=b.astype(np.int64)%q
    out=np.empty((m,n,chunks),dtype=np.uint32)
    for c in range(chunks):
        end=min((c+1)*CHUNK,k)
        af=(aa[:,:end]@fr[:end])%q
        eb=(bb[:,:end]@er[:end])%q
        ef=int((er[:end]@fr[:end])%q)
        cross=af[:,None]*fl[None,:]+el[:,None]*eb[None,:]+(el[:,None]*fl[None,:])*ef
        out[:,:,c]=((base_partials[:,:,c].astype(np.int64)+cross)%q).astype(np.uint32)
    return out

def main(first,second):
    first=pathlib.Path(first);second=pathlib.Path(second)
    receipts=[json.loads(first.with_suffix('.json').read_text()),json.loads(second.with_suffix('.json').read_text())]
    with np.load(first.with_suffix('.npz'),allow_pickle=False) as z:a=z['a'];b=z['b']
    with np.load(second.with_suffix('.npz'),allow_pickle=False) as z:
        if not np.array_equal(a,z['a']) or not np.array_equal(b,z['b']):raise ValueError('same public A/B required')
    results=[]
    for q in PRIMES:
        t=time.perf_counter();_,cached=product((a.astype(np.int64)%q).astype(np.uint32),
                                               (b.astype(np.int64)%q).astype(np.uint32),q)
        precompute_s=time.perf_counter()-t
        for receipt in receipts:
            seed=bytes.fromhex(receipt['challenge_seed_hex'])
            ae,bf,factors=encode(a,b,seed,q)
            t=time.perf_counter();forged=shortcut(cached,a,b,factors,q);shortcut_s=time.perf_counter()-t
            # Independent direct CPU reference, solely to validate the attack.
            t=time.perf_counter();_,reference=product(ae,bf,q);direct_s=time.perf_counter()-t
            assert np.array_equal(forged,reference)
            expected=next(f for f in receipt['fields'] if f['q']==q)
            assert sha(forged)==expected['transcript_sha256']
            results.append({'q':q,'challenge_seed':seed.hex(),'cached_base_s':precompute_s,
                            'shortcut_s':shortcut_s,'direct_cpu_s':direct_s,
                            'exact_transcript_sha256':sha(forged),'match':True})
    print(json.dumps({'fixed_matrices_sha256':[sha(a),sha(b)],'results':results},indent=2))

if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('usage: shortcut_demo.py FIRST_STEM SECOND_STEM')
    main(*sys.argv[1:])
