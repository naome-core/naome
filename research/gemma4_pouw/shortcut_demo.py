"""Demonstrate an amortized transcript shortcut for repeated public matrices.

Precompute ordinary AB cumulative chunks once. Across changed prompts, reuse
all matching activation rows and calculate ordinary chunks only for new rows.
For each fresh challenge, form the noisy transcript using low-rank cross terms,
with no fresh full noisy GEMM. This is an exact algebraic shortcut for this
fixed workload, not a measured wall-clock advantage on every backend.
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
    with np.load(second.with_suffix('.npz'),allow_pickle=False) as z:other_a=z['a'];other_b=z['b']
    if not np.array_equal(b,other_b):raise ValueError('same public B required')
    row_index={row.tobytes():i for i,row in enumerate(a)}
    reused=[(i,row_index[row.tobytes()]) for i,row in enumerate(other_a) if row.tobytes() in row_index]
    fresh=[i for i,row in enumerate(other_a) if row.tobytes() not in row_index]
    results=[]
    for q in PRIMES:
        t=time.perf_counter();_,cached=product((a.astype(np.int64)%q).astype(np.uint32),
                                               (b.astype(np.int64)%q).astype(np.uint32),q)
        precompute_s=time.perf_counter()-t
        base_other=np.empty((other_a.shape[0],b.shape[0],cached.shape[-1]),dtype=np.uint32)
        for dest,source in reused:base_other[dest]=cached[source]
        t=time.perf_counter()
        if fresh:
            _,fresh_partials=product((other_a[fresh].astype(np.int64)%q).astype(np.uint32),
                                     (b.astype(np.int64)%q).astype(np.uint32),q)
            base_other[fresh]=fresh_partials
        fresh_rows_s=time.perf_counter()-t
        for index,(receipt,left,base) in enumerate(((receipts[0],a,cached),(receipts[1],other_a,base_other))):
            seed=bytes.fromhex(receipt['challenge_seed_hex'])
            ae,bf,factors=encode(left,b,seed,q)
            t=time.perf_counter();forged=shortcut(base,left,b,factors,q);shortcut_s=time.perf_counter()-t
            # Independent direct CPU reference, solely to validate the attack.
            t=time.perf_counter();_,reference=product(ae,bf,q);direct_s=time.perf_counter()-t
            assert np.array_equal(forged,reference)
            expected=next(f for f in receipt['fields'] if f['q']==q)
            assert sha(forged)==expected['transcript_sha256']
            results.append({'q':q,'challenge_seed':seed.hex(),'cached_base_s':precompute_s,
                            'fresh_rows_s':fresh_rows_s if index==1 else 0,
                            'shortcut_s':shortcut_s,'direct_cpu_s':direct_s,
                            'exact_transcript_sha256':sha(forged),'match':True})
    print(json.dumps({'input_a_sha256':[sha(a),sha(other_a)],'fixed_b_sha256':sha(b),
                      'reused_rows':len(reused),'new_rows':len(fresh),'second_rows':len(other_a),
                      'results':results},indent=2))

if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('usage: shortcut_demo.py FIRST_STEM SECOND_STEM')
    main(*sys.argv[1:])
