"""Offline negative cases for research-chain commitments and signatures."""
import copy,json,pathlib,shutil,sys,tempfile
import numpy as np
from chain_demo import verify_qc,block_hash,validate_block,hash_file

def rejected(obj,genesis):
    try:verify_qc(obj,genesis)
    except Exception as e:return {'rejected':True,'reason':str(e)}
    return {'rejected':False}

def rebound_work_rejected(root,block,genesis,kind):
    with tempfile.TemporaryDirectory(prefix='naome-work-tamper-') as temp:
        path=pathlib.Path(temp)
        for name in ('work.json','work.npz','work.nao'):
            shutil.copyfile(root/'block1'/name,path/name)
        altered=copy.deepcopy(block)
        if kind=='decoded output':
            with np.load(path/'work.npz',allow_pickle=False) as z:
                arrays={key:z[key] for key in z.files}
            arrays['c_int32'][0,0]+=1
            np.savez_compressed(path/'work.npz',**arrays)
            altered['header']['witness_sha256']=hash_file(path/'work.npz')
        elif kind=='transcript commitment':
            receipt=json.loads((path/'work.json').read_text())
            receipt['fields'][0]['transcript_sha256']='00'*32
            (path/'work.json').write_text(json.dumps(receipt))
            altered['header']['receipt_sha256']=hash_file(path/'work.json')
        altered['hash']=block_hash(altered['header'])
        try:validate_block(path,altered,genesis,1,genesis['hash'])
        except Exception as e:return {'rejected':True,'reason':str(e)}
        return {'rejected':False}

def main(path):
    root=pathlib.Path(path)
    genesis=json.loads((root/'genesis.json').read_text())
    block=json.loads((root/'block1'/'block.json').read_text())
    cases=[]
    altered=copy.deepcopy(block);altered['votes'][0]['signature']='00'*64
    cases.append({'name':'bad validator signature',**rejected(altered,genesis)})
    altered=copy.deepcopy(block);altered['votes']=altered['votes'][:2]
    cases.append({'name':'missing quorum',**rejected(altered,genesis)})
    altered=copy.deepcopy(block);altered['hash']='00'*32
    cases.append({'name':'forged block hash',**rejected(altered,genesis)})
    altered=copy.deepcopy(block);altered['header']['prev']='00'*32
    altered['hash']=block_hash(altered['header'])
    cases.append({'name':'rebound predecessor without votes',**rejected(altered,genesis)})
    for kind in ('decoded output','transcript commitment'):
        cases.append({'name':kind+' with rebound block hash',
                      **rebound_work_rejected(root,block,genesis,kind)})
    result={'all_rejected':all(x['rejected'] for x in cases),'vectors':cases}
    print(json.dumps(result,indent=2))
    if not result['all_rejected']:raise SystemExit(1)

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('usage: chain_attack_vectors.py CHAIN_DIR')
    main(sys.argv[1])
