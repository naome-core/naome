"""Small independent arithmetic invariants for the research field scheme."""
import hashlib,multiprocessing as mp,tempfile,threading,unittest
import numpy as np
from field_verify import PRIMES,encode,product,decode,crt,sha
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from chain_demo import genesis_for,block_hash,node_loop,PROFILE

class FieldReferenceTests(unittest.TestCase):
    def test_two_field_decode_and_all_partials(self):
        rng=np.random.default_rng(20260929)
        a=rng.integers(-63,64,(17,133),dtype=np.int8)
        b=rng.integers(-63,64,(19,133),dtype=np.int8)
        seed=hashlib.sha256(b'field-reference-test').digest()
        residues=[];commitments=[]
        for q in PRIMES:
            ae,bf,factors=encode(a,b,seed,q)
            p,partials=product(ae,bf,q)
            self.assertEqual(partials.shape,(17,19,2))
            self.assertTrue(np.array_equal(p,partials[:,:,-1]))
            self.assertFalse(np.array_equal(partials[:,:,0],partials[:,:,1]))
            residues.append(decode(p,a,b,factors,q))
            commitments.append(sha(partials))
        expected=a.astype(np.int32)@b.astype(np.int32).T
        self.assertTrue(np.array_equal(crt(*residues),expected))
        self.assertNotEqual(commitments[0],commitments[1])

    def test_challenge_changes_encoded_transcript(self):
        a=np.arange(32,dtype=np.int8).reshape(4,8)
        b=np.arange(24,dtype=np.int8).reshape(3,8)
        q=PRIMES[0]
        e1,f1,_=encode(a,b,b'one'*10+bytes(2),q)
        e2,f2,_=encode(a,b,b'two'*10+bytes(2),q)
        self.assertNotEqual(sha(e1),sha(e2))
        self.assertNotEqual(sha(product(e1,f1,q)[1]),sha(product(e2,f2,q)[1]))

    def test_node_rejects_commit_before_local_validation(self):
        keys=[Ed25519PrivateKey.generate() for _ in range(4)]
        genesis=genesis_for(keys)
        header={'profile':PROFILE,'height':1,'prev':genesis['hash']}
        block={'header':header,'hash':block_hash(header),'votes':[]}
        with tempfile.TemporaryDirectory() as directory:
            parent,child=mp.Pipe()
            node=threading.Thread(target=node_loop,args=(0,keys[0].private_bytes_raw(),genesis,directory,child))
            node.start()
            try:
                parent.send({'op':'commit','block':block})
                result=parent.recv()
                self.assertFalse(result['ok'])
                self.assertEqual(result['reason'],'commit without local validation')
            finally:
                parent.send({'op':'stop'})
                node.join(timeout=2)
            self.assertFalse(node.is_alive())

if __name__=='__main__':unittest.main()
