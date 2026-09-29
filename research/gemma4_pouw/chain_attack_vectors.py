"""Offline negative cases for research-chain commitments and signatures."""
import copy,json,pathlib,sys
from chain_demo import verify_qc,block_hash,digest

def rejected(obj,genesis):
    try:verify_qc(obj,genesis)
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
    result={'all_rejected':all(x['rejected'] for x in cases),'vectors':cases}
    print(json.dumps(result,indent=2))
    if not result['all_rejected']:raise SystemExit(1)

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('usage: chain_attack_vectors.py CHAIN_DIR')
    main(sys.argv[1])
