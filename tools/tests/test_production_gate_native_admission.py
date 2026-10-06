"""Actual signed scratch prerequisite and immutable Git-state negative controls."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import unittest
from test_production_gate import AdmissionTests, GATE, canonical, digest, run


class NativePrerequisiteTests(AdmissionTests):
    def git_state(self):
        return {str(path.relative_to(self.repo)):digest(path.read_bytes()) for path in self.repo.rglob('*') if path.is_file() and not path.is_symlink()}

    def save_policy(self):
        self.policy_path.write_bytes(canonical(self.policy))
        self.statement['policy_sha256']=digest(self.policy_path.read_bytes())
        self.write_bundle()

    def reject_no_mutation(self,arguments=None):
        before=self.git_state()
        result=self.check() if arguments is None else run(sys.executable,GATE,*arguments,check=False)
        self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn(b'native_prerequisite',result.stdout+result.stderr)
        self.assertEqual(self.git_state(),before)

    def test_real_signed_fixture_positive_is_readonly(self):
        before=self.git_state();result=self.check()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(self.git_state(),before)

    def test_missing_native_proof_denies_commit_hook_install_and_promotion_before_write(self):
        self.policy['production'].pop('native_admission');self.save_policy()
        self.reject_no_mutation()
        self.reject_no_mutation(['install-hooks','--repo',self.repo,'--policy',self.policy_path,'--bundle',self.bundle_path,'--evaluator',GATE])
        destination=self.temp/'shared';run('git','init','-q',destination)
        (destination/'owner.txt').write_text('unchanged destination')
        before={str(p.relative_to(destination)):digest(p.read_bytes()) for p in destination.rglob('*') if p.is_file()}
        result=run(sys.executable,GATE,'promote','--repo',self.repo,'--destination',destination,'--policy',self.policy_path,'--bundle',self.bundle_path,check=False)
        self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual({str(p.relative_to(destination)):digest(p.read_bytes()) for p in destination.rglob('*') if p.is_file()},before)

    def test_disabled_feature_and_changed_project_trust_deny(self):
        original=self.native['config'].read_text()
        for source in (original.replace('hooks = true','hooks = false'),original.replace('"trusted"','"untrusted"')):
            self.native['config'].write_text(source);self.reject_no_mutation()
        self.native['config'].write_text(original)

    def test_changed_matcher_and_changed_trust_hash_deny(self):
        original=self.native['hooks'].read_bytes()
        value=json.loads(original);value['hooks']['PreToolUse'][0]['matcher']='Bash'
        self.native['hooks'].write_bytes(canonical(value));self.reject_no_mutation()
        self.native['hooks'].write_bytes(original)
        self.native['trust'].write_bytes(canonical({'trusted_hash':'f'*64}));self.reject_no_mutation()

    def test_real_guard_helper_cli_byte_drift_denies(self):
        for role in ('guard','operations','cli'):
            path=self.native['paths'][role];original=path.read_bytes()
            path.write_bytes(original+b'# changed bytes\n');self.reject_no_mutation();path.write_bytes(original)

    def test_expired_and_stale_proof_deny_even_resigned(self):
        original=copy.deepcopy(self.native['proof'])
        for issued,expires in ((original['issued_at']-4000,original['expires_at']),(original['issued_at'],original['issued_at']-1)):
            proof=copy.deepcopy(original);proof.update(issued_at=issued,expires_at=expires)
            self.native['sign_proof'](proof);self.save_policy();self.reject_no_mutation()

    def test_missing_actual_event_or_uncovered_route_rejects_signed_proof(self):
        original=copy.deepcopy(self.native['proof'])
        for change in ('event','route'):
            proof=copy.deepcopy(original)
            if change=='event':proof['coverage'][0]['events']=[]
            else:proof['coverage'].pop()
            self.native['sign_proof'](proof);self.save_policy();self.reject_no_mutation()

    def test_event_bytes_and_signature_drift_are_rejected(self):
        event=Path(self.native['proof']['coverage'][0]['events'][0]['path']);event.write_text('genuine changed event')
        self.reject_no_mutation()

    def test_invalid_reviewer_signature_rejects(self):
        signature=Path(self.native['proof']['independent_review']['signature']);signature.write_text('invalid signature')
        before=self.git_state();result=self.check();self.assertNotEqual(result.returncode,0,result.stdout+result.stderr);self.assertEqual(self.git_state(),before)

    def bind_prefixed_trust(self,value):
        self.native['trust'].write_bytes(canonical({'trusted_hash':value}))
        for projection in self.policy['production']['native_admission']['projections']:
            if projection['id']=='hook_trust':projection['selectors'][0]['expected']=value
        self.native['proof']['projection_sha256']=digest(canonical(self.native['module'].native_projection(self.policy)))
        self.native['sign_proof'](self.native['proof']);self.save_policy()

    def test_official_sha256_prefixed_trust_is_valid_and_raw_projection_is_preserved(self):
        value='sha256:'+digest(self.native['hooks'].read_bytes())
        self.bind_prefixed_trust(value)
        result=self.check();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        projected=self.native['module'].native_projection(self.policy,self.repo.resolve())
        trust=next(record for record in projected if record['id']=='hook_trust')
        self.assertEqual(trust['values'][0]['value'],value)
        self.native['trust'].write_bytes(canonical({'trusted_hash':'sha256:'+'f'*64}))
        self.reject_no_mutation()

    def test_wrong_or_malformed_trust_prefix_is_rejected_before_any_write(self):
        for value in ('md5:'+'a'*64,'sha256:'+'a'*63,'sha256:'+'g'*64,'sha256::'+'a'*64):
            self.native['trust'].write_bytes(canonical({'trusted_hash':value}))
            for projection in self.policy['production']['native_admission']['projections']:
                if projection['id']=='hook_trust':projection['selectors'][0]['expected']=value
            self.save_policy();self.reject_no_mutation()

    def refresh_current_native_projection(self):
        self.native['proof']['projection_sha256']=digest(canonical(self.native['module'].native_projection(self.policy,self.repo.resolve())))
        self.native['sign_proof'](self.native['proof']);self.save_policy()

    def test_optional_handler_enabled_state_missing_null_and_true_are_valid_and_raw_bound(self):
        original_hash=json.loads(self.native['trust'].read_bytes())['trusted_hash']
        values=[]
        for source in ({'trusted_hash':original_hash},{'trusted_hash':original_hash,'enabled':None},{'trusted_hash':original_hash,'enabled':True}):
            self.native['trust'].write_bytes(canonical(source));self.refresh_current_native_projection()
            before=self.git_state();result=self.check();self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertEqual(self.git_state(),before)
            projected=self.native['module'].native_projection(self.policy,self.repo.resolve())
            actual=next(p for p in projected if p['id']=='hook_trust')['values']
            state=next(p for p in actual if p['path']==['enabled'])
            self.assertEqual(state,{'path':['enabled'],'present':'enabled' in source,'value':source.get('enabled')})
            self.assertEqual(next(p['value'] for p in actual if p['path']==['trusted_hash']),original_hash)
            values.append(digest(canonical(projected)))
        self.assertEqual(len(set(values)),3)

    def test_handler_disabled_or_malformed_enabled_state_denies_despite_valid_trusted_hash(self):
        original_hash=json.loads(self.native['trust'].read_bytes())['trusted_hash']
        for enabled in (False,'true',1,{},[]):
            self.native['trust'].write_bytes(canonical({'trusted_hash':original_hash,'enabled':enabled}));self.reject_no_mutation()

    def test_every_selected_handler_requires_supported_enabled_state(self):
        trusted_hash='sha256:'+digest(self.native['hooks'].read_bytes())
        handlers={'first':{'trusted_hash':trusted_hash},'second':{'trusted_hash':trusted_hash,'enabled':True}}
        self.native['trust'].write_bytes(canonical(handlers))
        trust=next(p for p in self.policy['production']['native_admission']['projections'] if p['id']=='hook_trust')
        trust['selectors']=[{'path':[name,'trusted_hash'],'expected':trusted_hash} for name in ('first','second')]
        self.refresh_current_native_projection()
        result=self.check();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        handlers['second']['enabled']=False
        self.native['trust'].write_bytes(canonical(handlers));self.reject_no_mutation()

    def test_candidate_validation_remains_possible_with_native_hold(self):
        self.policy['production'].pop('native_admission');self.save_policy()
        result=self.check(mode='candidate')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_forged_boolean_cannot_replace_native_artifact(self):
        self.policy['production']['native_admission']=True;self.save_policy();self.reject_no_mutation()


if __name__=='__main__':unittest.main()
