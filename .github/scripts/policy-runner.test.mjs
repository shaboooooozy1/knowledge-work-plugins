import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const scripts = path.dirname(fileURLToPath(import.meta.url));
const schema = fs.readFileSync(path.resolve(scripts, '../policy/schema.json'), 'utf8');

// These executables and transports are test fixtures authored here, not plugin
// code. Every network request is intercepted; the test uses fake credentials.
const fakeGit = `#!${process.execPath}
const a=process.argv.slice(2);
const op=a.find(x=>['fetch','show','diff','init','rev-parse','merge-base','ls-tree','cat-file'].includes(x));
const old='1'.repeat(40), next='2'.repeat(40);
const manifest=sha=>JSON.stringify({name:'fixture',plugins:[{name:'sample',source:{source:'url',url:'https://github.com/example/plugin.git',sha}}]});
if(op==='show') {
 const ref=a.at(-1);
 const superseded=ref.startsWith('5'.repeat(40))&&process.env.TEST_SCENARIO==='superseded-pin'
   ||ref.startsWith('6'.repeat(40))&&process.env.TEST_SCENARIO==='base-advanced-superseded';
 const onBase=ref.startsWith(old)||ref.startsWith('5'.repeat(40))||ref.startsWith('6'.repeat(40));
 process.stdout.write(manifest(superseded?'4'.repeat(40):onBase?old:next));
}
else if(op==='merge-base') process.stdout.write(old+'\\n');
else if(op==='diff') { if(!a.includes(old)) process.exit(2); process.stdout.write('.claude-plugin/marketplace.json\\n'); }
else if(op==='rev-parse') process.stdout.write(next+'\\n');
else if(op==='ls-tree') process.stdout.write('100644 blob '+'3'.repeat(40)+'\\t.claude-plugin/plugin.json\\0');
else if(op==='cat-file') process.stdout.write(a.includes('-s')?'17\\n':'{"name":"sample"}');
`;
const mockFetch = `
import fs from 'node:fs';
const scenario=process.env.TEST_SCENARIO;
let gets=0;
const record=(url,options)=>fs.appendFileSync(process.env.TEST_CALLS,JSON.stringify({url,method:options.method||'GET',body:options.body?JSON.parse(options.body):null})+'\\n');
const ok=value=>({ok:true,status:200,json:async()=>value});
const verdict={passes:scenario!=='policy-failure',summary:'Fixture review.',violations:scenario==='policy-failure'?'SKILL.md:1 policy issue.':'',may_make_external_network_calls:false,may_download_additional_software:false,hooks:[],has_broad_scope_hooks:false,has_undisclosed_telemetry:false,description_matches_behavior:true};
globalThis.fetch=async(url,options={})=>{
 record(url,options);
 if(url.includes('/pulls/39')) {
   gets++;
   return ok({number:39,state:'open',head:{sha:(scenario==='stale-head'&&gets>1?'4':'2').repeat(40),repo:{full_name:'shaboooooozy1/knowledge-work-plugins'}},base:{sha:(scenario.startsWith('base-advanced-')&&gets>1?'6':'5').repeat(40),ref:'main',repo:{full_name:'shaboooooozy1/knowledge-work-plugins'}}});
 }
 if(url.endsWith('/check-runs')&&options.method==='POST') return ok({id:99});
 if(url.endsWith('/check-runs/99')&&options.method==='PATCH') return scenario==='publish-failure'?{ok:false,status:503}:ok({});
 if(url.startsWith('https://vstoken.actions.githubusercontent.com/')) return ok({value:'fixture-jwt'});
 if(url.endsWith('/v1/oauth/token')) return scenario==='auth-denied'?{ok:false,status:401}:ok({token_type:'Bearer',access_token:'fixture-access-token',expires_in:600});
 if(url.endsWith('/v1/messages')) {
   if(scenario==='not-logged-in') return ok({type:'result',is_error:true,result:'Not logged in'});
   if(scenario==='api-error') return {ok:false,status:500};
   if(scenario==='malformed') return ok({type:'message',stop_reason:'end_turn',content:[{type:'text',text:'not JSON'}]});
   if(scenario==='missing-field') delete verdict.has_undisclosed_telemetry;
   return ok({type:'message',stop_reason:scenario==='truncated'?'max_tokens':scenario==='refusal'?'refusal':'end_turn',content:[{type:'text',text:JSON.stringify(verdict)}]});
 }
 throw new Error('UNEXPECTED NETWORK REQUEST');
};
`;

function run(scenario) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-runner-test-'));
  try {
    fs.mkdirSync(path.join(temp, '.github/policy'), { recursive: true });
    fs.writeFileSync(path.join(temp, '.github/policy/schema.json'), schema);
    fs.writeFileSync(path.join(temp, '.github/policy/prompt.md'), 'Trusted fixture policy.');
    fs.mkdirSync(path.join(temp, 'bin'));
    fs.writeFileSync(path.join(temp, 'bin/git'), fakeGit, { mode: 0o755 });
    fs.writeFileSync(path.join(temp, 'mock-fetch.mjs'), mockFetch);
    const env = {
      PATH: path.join(temp, 'bin'), HOME: temp, TMPDIR: temp,
      GITHUB_REPOSITORY: 'shaboooooozy1/knowledge-work-plugins',
      GITHUB_REPOSITORY_ID: '1272807675', GITHUB_REF: 'refs/heads/main',
      GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_WORKSPACE: temp,
      GITHUB_RUN_ID: '12345', GITHUB_TOKEN: 'fixture-github-token',
      PR_NUMBER: '39', EXPECTED_HEAD_SHA: '2'.repeat(40),
      ANTHROPIC_FEDERATION_RULE_ID: scenario === 'missing-auth' ? '' : 'fdrl_Test',
      ANTHROPIC_ORGANIZATION_ID: '12345678-1234-1234-1234-123456789012',
      ANTHROPIC_SERVICE_ACCOUNT_ID: 'svac_Test',
      ACTIONS_ID_TOKEN_REQUEST_URL: 'https://vstoken.actions.githubusercontent.com/test',
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'fixture-request-token',
      TEST_SCENARIO: scenario, TEST_CALLS: path.join(temp, 'calls.jsonl'),
    };
    const result = spawnSync(process.execPath, [
      '--import', path.join(temp, 'mock-fetch.mjs'), path.join(scripts, 'run-policy-scan.mjs'),
    ], { env, encoding: 'utf8', timeout: 30000 });
    const read = name => JSON.parse(fs.readFileSync(path.join(temp, '.scan-cache', name), 'utf8'));
    const calls = fs.readFileSync(env.TEST_CALLS, 'utf8').trim().split('\n').map(JSON.parse);
    return { result, calls, status: read('scan-status.json'), verdicts: read('run-verdicts.json'),
      failures: read('run-failed.json') };
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

test('runner publishes one complete passing verdict for the exact head', () => {
  const r = run('pass');
  assert.equal(r.result.status, 0, r.result.stdout + r.result.stderr);
  assert.equal(r.status.state, 'pass');
  assert.equal(r.status.coverageComplete, true);
  assert.equal(r.verdicts.length, 1);
  assert.deepEqual(r.failures, []);
  assert.equal(r.calls.find(c => c.method === 'POST' && c.url.endsWith('/check-runs')).body.head_sha, '2'.repeat(40));
  assert.equal(r.calls.find(c => c.method === 'PATCH').body.conclusion, 'success');
  assert.ok(!r.result.stdout.includes('fixture-access-token'));
});
test('runner preserves a genuine policy rejection without pretending it is an infrastructure issue', () => {
  const r = run('policy-failure');
  assert.equal(r.result.status, 1);
  assert.equal(r.status.state, 'policy_failure');
  assert.deepEqual(r.failures, ['sample']);
  assert.equal(r.calls.find(c => c.method === 'PATCH').body.conclusion, 'failure');
});
test('unrelated main advancement during review does not invalidate the exact pin', () => {
  const r = run('base-advanced-safe');
  assert.equal(r.result.status, 0, r.result.stdout + r.result.stderr);
  assert.equal(r.status.state, 'pass');
  assert.equal(r.status.coverageComplete, true);
  assert.equal(r.calls.find(c => c.method === 'PATCH').body.conclusion, 'success');
});
for (const scenario of ['missing-auth', 'auth-denied', 'not-logged-in', 'api-error', 'malformed',
  'missing-field', 'truncated', 'refusal', 'stale-head', 'superseded-pin', 'base-advanced-superseded']) {
  test(`runner fails closed without fabricated policy findings: ${scenario}`, () => {
    const r = run(scenario);
    assert.equal(r.result.status, 1, r.result.stdout + r.result.stderr);
    assert.equal(r.status.state, 'infrastructure_error');
    assert.equal(r.status.coverageComplete, false);
    assert.deepEqual(r.verdicts, []);
    assert.deepEqual(r.failures, []);
    assert.equal(r.calls.find(c => c.method === 'PATCH').body.conclusion, 'failure');
    if (scenario === 'missing-auth') assert.ok(!r.calls.some(c => c.url.includes('anthropic.com')));
    if (scenario === 'auth-denied') assert.ok(!r.calls.some(c => c.url.endsWith('/v1/messages')));
  });
}
test('failed check publication cannot leave an overall passing run', () => {
  const r = run('publish-failure');
  assert.equal(r.result.status, 1);
  assert.equal(r.status.state, 'infrastructure_error');
  assert.equal(r.status.publicationComplete, false);
});
