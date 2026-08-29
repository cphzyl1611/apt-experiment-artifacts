#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGET = Path('/home/cph/experiment-artifacts/fa1b2de-current86-canonical-intrinsic-317-r1/CURRENT86_Canonical_Intrinsic_317_Exact_Targets.json')
REPO = Path('/home/cph/fa1b2de-review-artifacts')
R1 = '4a3f0d8e36029fa82572a79a4c8817a31184d82a'
R4 = '9cec0141fb9599ca879d5d992005921585f24cbb'
SCOPE = '34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306'
TARGET_SHA = 'd8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac'
R4_PATH = 'current86-r4/fa1b2de-current86-canonical-source-authentication-governance-r4-patch/Design_FA1B2de_Current86_Canonical_Intrinsic_317_Source_Authentication_Governance_R4_PATCHED.md'
R4_SHA = 'b499b4cfddd4f72e404dda72c423bfa3db98b0514af52773b9bbec5cce6e2cc0'

class VerificationError(RuntimeError): pass

def digest(data): return hashlib.sha256(data).hexdigest()
def load(path):
    seen = set()
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out: raise VerificationError('DUPLICATE_JSON_KEY:' + str(path))
            out[key] = value
        return out
    return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_float=lambda _: (_ for _ in ()).throw(VerificationError('FLOAT_FORBIDDEN')), parse_constant=lambda _: (_ for _ in ()).throw(VerificationError('NONFINITE_FORBIDDEN')))
def git(*args):
    p = subprocess.run(['git','-C',str(REPO),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    if p.returncode: raise VerificationError(p.stderr.decode('utf-8','replace'))
    return p.stdout
def canonical(v):
    if isinstance(v,dict): return b'{'+b','.join(canonical(k)+b':'+canonical(v[k]) for k in sorted(v,key=lambda k:k.encode('utf-8')))+b'}'
    if isinstance(v,list): return b'['+b','.join(canonical(x) for x in v)+b']'
    return json.dumps(v,ensure_ascii=False,separators=(',',':')).encode('utf-8')
def verify_inputs():
    line=git('show','-s','--format=%T %P',R1).decode().split()
    if line != ['14c1d6916b4d58f588e62505276e0ceaed3ef995','9cec0141fb9599ca879d5d992005921585f24cbb']: raise VerificationError('R1_COMMIT_LINEAGE_MISMATCH')
    line=git('show','-s','--format=%T %P',R4).decode().split()
    if line != ['b1cca46922be1d6779aaf4b0282254bb2533959e','bc54c0feea1a8af346e2c70b39679cd01f4f3577']: raise VerificationError('R4_COMMIT_LINEAGE_MISMATCH')
    if digest(git('show',f'{R4}:{R4_PATH}')) != R4_SHA: raise VerificationError('R4_DESIGN_HASH_MISMATCH')
    if digest(TARGET.read_bytes()) != TARGET_SHA: raise VerificationError('TARGET_MANIFEST_HASH_MISMATCH')
def verify_targets():
    data=load(TARGET)
    if data['audit_scope_id'] != SCOPE or data['totals'] != {'EXACT_TARGET_TOTAL':317,'RAW_SIDE_TOTAL':86,'CANDIDATE_SIDE_TOTAL':231}: raise VerificationError('EXACT317_SCOPE_MISMATCH')
    rows=data['targets']
    if len(rows)!=317 or [r['target_index'] for r in rows] != list(range(1,318)): raise VerificationError('TARGET_ORDER_MISMATCH')
    if sum(r['source_side']=='RAW' for r in rows)!=86 or sum(r['source_side']=='CANDIDATE' for r in rows)!=231: raise VerificationError('SIDE_COUNT_MISMATCH')
    ids=set()
    for row in rows:
        basis={'audit_scope_id':SCOPE,'bound_candidate_scoring_id':row['bound_candidate_scoring_id'],'bound_raw_key':row['bound_raw_key'],'source_artifact_class':row['source_artifact_class'],'source_fact_type':row['required_source_fact_type'],'source_side':row['source_side']}
        ident=digest(canonical(basis))
        if ident != row['source_binding_target_id']: raise VerificationError('TARGET_ID_MISMATCH')
        ids.add(ident)
    if len(ids)!=317: raise VerificationError('TARGET_ID_DUPLICATE')
    return ids
def verify_package(production_ids):
    for path in ROOT.rglob('*.json'): load(path)
    manifest=load(ROOT/'CONTRACT_MANIFEST.json')
    required={'source_auth_target_count':317,'raw_side_target_count':86,'candidate_side_target_count':231,'source_auth_execution_readiness':'BLOCKED_MISSING_AUTHORITY_INPUTS','ec_b1':'CLOSED_CANDIDATE','ec_b2':'CLOSED_CANDIDATE','ec_b3':'CLOSED_CANDIDATE','ec_b4':'CLOSED_CANDIDATE','real_source_auth_targets_executed':0,'source_auth_executed':'NO','current86_p0_executed':'NO','current86_p1_executed':'NO','raw_level_human_decisions':0,'binding_publication':'NO','scoring_authority_mutation':'NO','binding_authority_mutation':'NO','denominator_change':'NO','accepted_binding_count_change':'NO','git_ref_mutation':'NO'}
    if any(manifest.get(k)!=v for k,v in required.items()): raise VerificationError('MANIFEST_BOUNDARY_MISMATCH')
    inv=load(ROOT/'SOURCE_AUTH_EXECUTION_CONTRACT_R2_DEPENDENCY_INVENTORY.json')
    if inv['missing_is_empty_authority_set'] or inv['execution_readiness']!='BLOCKED_MISSING_AUTHORITY_INPUTS': raise VerificationError('MISSING_AUTHORITY_SEMANTICS_MISMATCH')
    cons=load(ROOT/'SOURCE_AUTH_EXECUTION_CONTRACT_R2_TARGET_CONSERVATION.json')
    if cons['source_auth_target_count']!=317 or cons['raw_side_target_count']!=86 or cons['candidate_side_target_count']!=231 or cons['current_contract_only_partition'] != {'NOT_EXECUTED_PENDING_SOURCE_AUTH_GOVERNANCE':317}: raise VerificationError('CONSERVATION_MISMATCH')
    fixtures=load(ROOT/'tests/fixtures.py') if False else None
    fixture=ROOT/'fixtures/SYNTHETIC_FIXTURE_MANIFEST.json'
    if fixture.exists():
        f=load(fixture)
        if f.get('fixture_authority')!='NON_AUTHORITATIVE_SYNTHETIC_ONLY' or f.get('real_source_auth_targets_executed')!=0: raise VerificationError('FIXTURE_BOUNDARY_MISMATCH')
        if set(f.get('synthetic_target_ids',[])) & production_ids: raise VerificationError('SYNTHETIC_PRODUCTION_INTERSECTION')
def verify_inventory():
    listed=(ROOT/'FILE_LIST.txt').read_text().splitlines()
    actual=sorted(p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file())
    if listed != actual: raise VerificationError('FILE_LIST_MISMATCH')
    expected=[f'{digest((ROOT/rel).read_bytes())}  ./{rel}' for rel in actual if rel!='SHA256SUMS.txt']
    if (ROOT/'SHA256SUMS.txt').read_text().splitlines()!=expected: raise VerificationError('SHA256SUMS_MISMATCH')
def main():
    verify_inputs(); ids=verify_targets(); verify_package(ids); verify_inventory(); print(json.dumps({'package_verification':'PASS','governance_r4_input_authentication':'PASS','exact317_scope':'PASS','source_auth_execution_readiness':'BLOCKED_MISSING_AUTHORITY_INPUTS','real_source_auth_targets_executed':0,'git_ref_mutation':'NO'},sort_keys=True,separators=(',',':')))
if __name__=='__main__':
    try: main()
    except VerificationError as exc: print('PACKAGE_VERIFICATION=FAIL:'+str(exc),file=sys.stderr); raise SystemExit(1)
