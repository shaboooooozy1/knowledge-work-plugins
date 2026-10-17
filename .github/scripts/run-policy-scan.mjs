import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  API_ORIGIN, REPOSITORY, MAX_FILES, MAX_PAYLOAD_BYTES, PolicyError, requireTrue,
  validateContext, validatePullRequest, validateFederation, pinChange, requireCurrentBasePin, buildPayload,
  federatedAccessToken, jsonRequest, messagesRequest, parseModelResponse, requireCoverage, redactCredentialShapes,
} from './policy-core.mjs';

const env = process.env;
const root = env.GITHUB_WORKSPACE || process.cwd();
const out = path.join(root, '.scan-cache');
const runUrl = `https://github.com/${REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`;
const git = (cwd, args, encoding = 'utf8') => execFileSync('git', [
  '-C', cwd, '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', ...args,
], { encoding, timeout: 120000, maxBuffer: 4 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
const github = (endpoint, method = 'GET', body) => jsonRequest(fetch,
  `https://api.github.com/repos/${REPOSITORY}/${endpoint}`, {
    method, headers: {
      Authorization: `Bearer ${env.GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  }, 'GitHub API');
const save = (name, value) => fs.writeFileSync(path.join(out, name), JSON.stringify(value, null, 2) + '\n');

function collectSource(target, directory) {
  git(directory, ['init', '--bare', '--quiet']);
  git(directory, ['fetch', '--quiet', '--depth=1', '--no-tags', target.source.url, target.source.sha]);
  requireTrue(git(directory, ['rev-parse', 'FETCH_HEAD']).trim() === target.source.sha, 'Source fetch mismatch.');
  const args = ['ls-tree', '-r', '-z', '--full-tree', target.source.sha];
  if (target.source.path) args.push('--', target.source.path);
  const raw = git(directory, args).split('\0').filter(Boolean);
  requireTrue(raw.length > 0 && raw.length <= MAX_FILES, 'Source inventory is empty or too large.');
  const prefix = target.source.path ? target.source.path + '/' : '';
  const entries = [];
  let bytes = 0;
  for (const row of raw) {
    const tab = row.indexOf('\t');
    const [mode, kind, oid] = row.slice(0, tab).split(' ');
    const name = row.slice(tab + 1);
    requireTrue(kind === 'blob' && ['100644', '100755'].includes(mode), 'Unsupported source entry.');
    requireTrue(!prefix || name.startsWith(prefix), 'Source escaped the selected subtree.');
    const size = Number(git(directory, ['cat-file', '-s', oid]).trim());
    bytes += size;
    requireTrue(Number.isFinite(size) && bytes <= MAX_PAYLOAD_BYTES,
      'Source exceeds the review-size limit; no source was silently truncated.');
    entries.push({ path: name.slice(prefix.length), mode, content: git(directory, ['cat-file', 'blob', oid], null) });
  }
  return buildPayload(entries);
}

let checkId;
let sourceDirectory;
let finalConclusion = 'failure';
let records = [];
let coverageComplete = false;
let publicMessage = 'Policy scan did not finish. No policy approval was recorded.';
try {
  validateContext(env);
  requireTrue(Boolean(env.GITHUB_TOKEN), 'GitHub token is missing.');
  fs.mkdirSync(out, { recursive: true });
  // Invalidate any previous output before starting this single-PR run.
  save('run-verdicts.json', []);
  save('run-failed.json', []);
  save('scan-status.json', { state: 'infrastructure_error', coverageComplete: false });
  const pr = await github(`pulls/${env.PR_NUMBER}`);
  validatePullRequest(pr, env);
  const check = await github('check-runs', 'POST', {
    name: 'scan', head_sha: env.EXPECTED_HEAD_SHA, status: 'in_progress',
    external_id: `${env.GITHUB_RUN_ID}:${env.PR_NUMBER}`, details_url: runUrl,
    output: { title: 'Federated policy review in progress',
      summary: 'Reviewing the exact plugin pin with trusted-main scanner code. No merge is authorized.' },
  });
  checkId = check.id;
  requireTrue(Number.isInteger(checkId), 'GitHub check-run creation failed.');
  validateFederation(env);
  git(root, ['fetch', '--quiet', '--no-tags', 'origin', pr.base.sha, env.EXPECTED_HEAD_SHA]);
  const mergeBase = git(root, ['merge-base', pr.base.sha, env.EXPECTED_HEAD_SHA]).trim();
  requireTrue(/^[a-f0-9]{40}$/.test(mergeBase), 'Could not resolve the PR merge base.');
  const base = JSON.parse(git(root, ['show', `${mergeBase}:.claude-plugin/marketplace.json`]));
  const currentMain = JSON.parse(git(root, ['show', `${pr.base.sha}:.claude-plugin/marketplace.json`]));
  const head = JSON.parse(git(root, ['show', `${env.EXPECTED_HEAD_SHA}:.claude-plugin/marketplace.json`]));
  const changedPaths = git(root, ['diff', '--name-only', mergeBase, env.EXPECTED_HEAD_SHA])
    .trim().split('\n').filter(Boolean);
  const target = pinChange(base, head, changedPaths);
  requireCurrentBasePin(base, currentMain, target);
  sourceDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'plugin-policy-source-'));
  const payload = collectSource(target, sourceDirectory);
  const schema = JSON.parse(fs.readFileSync(path.join(root, '.github/policy/schema.json'), 'utf8'));
  const policy = fs.readFileSync(path.join(root, '.github/policy/prompt.md'), 'utf8');
  // No CLI, user profiles, hooks, tool calls or plugin code are executed.
  const accessToken = await federatedAccessToken(env);
  const response = await jsonRequest(fetch, `${API_ORIGIN}/v1/messages`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json',
      'anthropic-version': '2023-06-01' },
    body: JSON.stringify(messagesRequest(env.POLICY_SCAN_MODEL || 'claude-sonnet-5-5',
      policy, schema, target, payload)),
  }, 'Anthropic policy review');
  const verdict = parseModelResponse(response, schema);
  records = [{ name: target.name, sha: target.source.sha, pluginSource: target.source,
    source: 'scan', sourceFingerprint: payload.fingerprint, ...verdict }];
  requireCoverage([target], records);
  // A head update while scanning invalidates this run. Never approve a newer pin.
  const latestPr = await github(`pulls/${env.PR_NUMBER}`);
  validatePullRequest(latestPr, env);
  // Main may advance while the model is reviewing. Unrelated changes are fine,
  // but a superseding update to this plugin must invalidate the older bump.
  if (latestPr.base.sha !== pr.base.sha) {
    git(root, ['fetch', '--quiet', '--no-tags', 'origin', latestPr.base.sha]);
    const latestMain = JSON.parse(git(root, ['show', `${latestPr.base.sha}:.claude-plugin/marketplace.json`]));
    requireCurrentBasePin(base, latestMain, target);
  }
  coverageComplete = true;
  finalConclusion = verdict.passes ? 'success' : 'failure';
  publicMessage = verdict.passes
    ? 'One expected plugin pin received one complete, schema-valid passing verdict. Human merge approval is still required.'
    : 'The plugin received a complete negative policy verdict. See the scan artifact; do not merge this pin.';
  save('source-inventory.json', {
    name: target.name, pin: target.source.sha, source: target.source,
    files: payload.files.map(({ content, ...metadata }) => metadata),
  });
} catch (error) {
  // Never emit raw subprocess output, provider response bodies, tokens, or model
  // output. Error messages originating in our validator contain no credentials.
  publicMessage = error instanceof PolicyError
    ? error.message.replace(/[\r\n]/g, ' ').slice(0, 400)
    : 'Source inspection or local validation failed. No policy approval was recorded.';
  records = [];
  finalConclusion = 'failure';
} finally {
  if (sourceDirectory) fs.rmSync(sourceDirectory, { recursive: true, force: true });
  fs.mkdirSync(out, { recursive: true });
  save('run-verdicts.json', redactCredentialShapes(records));
  // Infrastructure errors must not masquerade as policy findings or trigger reverts.
  save('run-failed.json', coverageComplete ? records.filter(r => !r.passes).map(r => r.name) : []);
  save('scan-status.json', {
    state: coverageComplete ? (finalConclusion === 'success' ? 'pass' : 'policy_failure') : 'infrastructure_error',
    coverageComplete, pr: env.PR_NUMBER, headSha: env.EXPECTED_HEAD_SHA,
    message: publicMessage, model: env.POLICY_SCAN_MODEL || 'claude-sonnet-5-5',
    scannerCommit: env.GITHUB_SHA,
  });
  if (checkId) {
    try {
      await github(`check-runs/${checkId}`, 'PATCH', {
        status: 'completed', conclusion: finalConclusion, details_url: runUrl,
        output: { title: coverageComplete ? 'Plugin policy verdict' : 'Policy review incomplete',
          summary: publicMessage },
      });
    } catch {
      finalConclusion = 'failure';
      publicMessage = 'Could not publish the policy result to the exact PR head.';
      save('scan-status.json', {
        state: 'infrastructure_error', coverageComplete, publicationComplete: false,
        pr: env.PR_NUMBER, headSha: env.EXPECTED_HEAD_SHA, message: publicMessage,
      });
    }
  }
  console.log(`${finalConclusion === 'success' ? 'Policy review passed' : 'Policy review blocked'}: ${publicMessage}`);
  process.exitCode = finalConclusion === 'success' ? 0 : 1;
}
