"""Signed portable scratch state for the admission reader, without native-engine claims."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()


def reference(path):
    return {"path":str(Path(path).resolve()),"sha256":hashlib.sha256(Path(path).read_bytes()).hexdigest()}


def attach_native(directory,policy,evaluator,reviewer_key):
    control=Path(directory)/"native-state-fixture";control.mkdir()
    evaluator=Path(evaluator).resolve()
    paths={}
    for role in ("guard","operations","cli"):
        paths[role]=control/(role+"-fixture.py")
        paths[role].write_text("# Scratch runtime bytes; no native lifecycle evidence.\n")
    paths["evaluator"]=evaluator
    policy["native_guard"]={"shared_repositories":[str(Path(directory)/"candidate")]}
    policy.setdefault("journal",{})["evaluator_sha256"]=reference(paths["operations"])["sha256"]
    production=policy["production"]
    production["native_guard_sha256"]=reference(paths["guard"])["sha256"]
    production["evaluator_path"]=str(evaluator)
    hooks={"hooks":{"PreToolUse":[{"matcher":"Bash|apply_patch","hooks":[{"type":"command","command":str(paths["guard"])}]}],"Interrupt":[],"SessionEnd":[]}}
    hookfile=control/"hooks.json";hookfile.write_bytes(canonical(hooks))
    config=control/"config.toml";config.write_text('[features]\nhooks = true\n[projects.fixture]\ntrust_level = "trusted"\n')
    trust=control/"trust.json";trust.write_bytes(canonical({"trusted_hash":reference(hookfile)["sha256"]}))
    projections=[{"id":"hooks_definition","path":str(hookfile),"format":"json","selectors":[{"path":[],"expected":hooks}]},
        {"id":"hook_feature","path":str(config),"format":"toml","selectors":[{"path":["features","hooks"],"expected":True}]},
        {"id":"project_trust","path":str(config),"format":"toml","selectors":[{"path":["projects","fixture","trust_level"],"expected":"trusted"}]},
        {"id":"hook_trust","path":str(trust),"format":"json","selectors":[{"path":["trusted_hash"],"expected":reference(hookfile)["sha256"]}]}]
    spec=importlib.util.spec_from_file_location("fixture_native_evaluator",evaluator)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    native={"version":1,"maximum_age_seconds":3600,"cli_version":"0.160.0","runtime":[dict(reference(path),role=role) for role,path in paths.items()],"projections":projections,"required_routes":["PreToolUse:Bash","PreToolUse:apply_patch","Interrupt","SessionEnd"],"denied_routes":["PreToolUse:write_stdin","PreToolUse:MCP"]}
    production["native_admission"]=native
    now=time.time()
    proof={"version":1,"kind":"native-admission","issued_at":now,"expires_at":now+3600,"runtime_sha256":{role:reference(path)["sha256"] for role,path in paths.items()},"projection_sha256":hashlib.sha256(canonical(module.native_projection(policy))).hexdigest(),"engine":{"version":"0.160.0","feature":"enabled","project_trust":"trusted","hook_trust":"trusted"},"coverage":[]}
    for index,route in enumerate(native["required_routes"]+native["denied_routes"]):
        event=control/(str(index)+"-event.json");failure=control/(str(index)+"-failure.json")
        event.write_bytes(canonical({"tier":"scratch fixture, never actual native engine qualification","route":route,"event":"fixture"}))
        failure.write_bytes(canonical({"tier":"scratch fixture, never actual native engine qualification","route":route,"failure":"fixture"}))
        proof["coverage"].append({"route":route,"status":"covered" if route in native["required_routes"] else "denied","events":[reference(event)],"failures":[reference(failure)]})
    prooffile=control/"proof.json";reviewfile=control/"review.json"
    def sign_proof(value):
        core={key:data for key,data in value.items() if key!="independent_review"}
        review={"kind":"native-admission-review","decision":"approve","proof_core_sha256":hashlib.sha256(canonical(core)).hexdigest(),"issued_at":now,"expires_at":now+3600}
        reviewfile.write_bytes(canonical(review))
        signature=Path(str(reviewfile)+".sig");signature.unlink(missing_ok=True)
        subprocess.run(["ssh-keygen","-Y","sign","-q","-f",str(reviewer_key),"-n","naome-factory-v1",str(reviewfile)],check=True)
        value["independent_review"]=dict(reference(reviewfile),signature=str(signature),principal="reviewer")
        prooffile.write_bytes(canonical(value));native["proof"]=reference(prooffile)
    def bind_evaluator(path):
        path=Path(path).resolve()
        production['evaluator_path']=str(path)
        for record in native['runtime']:
            if record['role']=='evaluator':record.update(reference(path))
        proof['runtime_sha256']['evaluator']=reference(path)['sha256']
        sign_proof(proof)
    sign_proof(proof)
    return {"paths":paths,"module":module,"proof":proof,"sign_proof":sign_proof,"bind_evaluator":bind_evaluator,"hooks":hookfile,"config":config,"trust":trust,"review":reviewfile,"proof_path":prooffile}
