"""Experimental two-prime rank-one encoded matrix product on MLX Metal.

Functional arithmetic only. This is not a Pearl certificate or a hardness proof.
"""
import hashlib
import numpy as np
import mlx.core as mx

PRIMES = (65521, 65519)
CHUNK = 128

KERNEL = mx.fast.metal_kernel(
    name='naome_field_encoded_gemm_v1',
    input_names=['a', 'b', 'modulus'],
    output_names=['product', 'partials'],
    source='''
        uint idx = thread_position_in_grid.x;
        uint m = a_shape[0];
        uint k = a_shape[1];
        uint n = b_shape[0];
        if (idx >= m * n) return;
        uint i = idx / n;
        uint j = idx % n;
        uint q = modulus[0];
        uint chunks = (k + 127) / 128;
        uint running = 0;
        for (uint c = 0; c < chunks; ++c) {
            ulong block = 0;
            uint start = c * 128;
            uint end = min(start + 128, k);
            for (uint t = start; t < end; ++t) {
                block += (ulong)a[i * k + t] * (ulong)b[j * k + t];
            }
            running = (uint)(((ulong)running + block) % (ulong)q);
            partials[idx * chunks + c] = running;
        }
        product[idx] = running;
    ''',
)

def sha(data):
    return hashlib.sha256(np.ascontiguousarray(data).tobytes()).hexdigest()

def uniform(seed, label, length, q):
    """Rejection-sampled nonzero 16-bit field elements from SHA-256 counters."""
    out = np.empty(length, dtype=np.int64)
    for i in range(length):
        counter = 0
        while True:
            h = hashlib.sha256(seed + label + i.to_bytes(4,'little') + counter.to_bytes(4,'little')).digest()
            value = int.from_bytes(h[:2], 'little')
            if 0 < value < q:
                out[i] = value
                break
            counter += 1
    return out

def encode(a, b, seed, q):
    m,k = a.shape
    n,kb = b.shape
    assert k == kb
    el = uniform(seed, b'EL'+q.to_bytes(4,'little'), m, q)
    er = uniform(seed, b'ER'+q.to_bytes(4,'little'), k, q)
    fl = uniform(seed, b'FL'+q.to_bytes(4,'little'), n, q)
    fr = uniform(seed, b'FR'+q.to_bytes(4,'little'), k, q)
    # A + EL ER, B + FL FR, where B has transposed inference layout n x k.
    ae = (a.astype(np.int64) + el[:,None]*er[None,:]) % q
    bf = (b.astype(np.int64) + fl[:,None]*fr[None,:]) % q
    return ae.astype(np.uint32), bf.astype(np.uint32), (el,er,fl,fr)

def decode(encoded_product, a, b, factors, q):
    el,er,fl,fr = factors
    # C' - A F^T - E (B+F)^T, reduced between products to stay int64-safe.
    af = ((a.astype(np.int64) @ fr) % q)[:,None] * fl[None,:] % q
    bf = (b.astype(np.int64) + fl[:,None]*fr[None,:]) % q
    er_bf = (bf @ er) % q
    ebf = el[:,None] * er_bf[None,:] % q
    return (encoded_product.astype(np.int64) - af - ebf) % q

def metal_product(a, b, q):
    m,k = a.shape
    n = b.shape[0]
    chunks = (k+CHUNK-1)//CHUNK
    p,t = KERNEL(inputs=[mx.array(a),mx.array(b),mx.array([q],dtype=mx.uint32)],
                 output_shapes=[(m,n),(m,n,chunks)], output_dtypes=[mx.uint32,mx.uint32],
                 grid=(m*n,1,1), threadgroup=(128,1,1))
    mx.eval(p,t)
    return np.array(p), np.array(t)

def cpu_product_and_partials(a,b,q):
    m,k = a.shape
    n=b.shape[0]
    chunks=(k+CHUNK-1)//CHUNK
    partials=np.empty((m,n,chunks),dtype=np.uint32)
    running=np.zeros((m,n),dtype=np.int64)
    for c in range(chunks):
        s=c*CHUNK;e=min(s+CHUNK,k)
        running=(running+a[:,s:e].astype(np.int64)@b[:,s:e].astype(np.int64).T)%q
        partials[:,:,c]=running.astype(np.uint32)
    return running.astype(np.uint32),partials

def crt_signed(r1,r2):
    p1,p2=PRIMES
    inv=pow(p1,-1,p2)
    x=r1.astype(np.int64)+p1*(((r2.astype(np.int64)-r1.astype(np.int64))*inv)%p2)
    modulus=p1*p2
    x[x>modulus//2]-=modulus
    if np.any(x<np.iinfo(np.int32).min) or np.any(x>np.iinfo(np.int32).max):
        raise ValueError('decoded value outside signed int32')
    return x.astype(np.int32)
