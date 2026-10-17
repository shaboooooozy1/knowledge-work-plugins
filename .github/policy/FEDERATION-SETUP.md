# Fork-specific policy scanner

The scanner now treats missing authentication, missing verdicts, malformed output,
refusals, truncated responses and source-inspection failures as failures. It does
not run plugin code, load plugin hooks, use a CLI login, or execute a PR's workflow
while holding federation credentials.

## Authentication

The old composite action launched Claude Code with `--bare`, which ignores
federation credentials according to the
[Claude Code authentication reference](https://code.claude.com/docs/en/authentication).
The replacement uses the documented
[OIDC token exchange](https://platform.claude.com/docs/en/manage-claude/wif-reference)
and [JSON-schema Messages API](https://platform.claude.com/docs/en/build-with-claude/structured-outputs)
directly, with no model tools and no long-lived API key.

Create or select a GitHub Actions workload in the
[Claude Console](https://platform.claude.com/settings/workload-identity-federation).
Use the [GitHub Actions provider guide](https://platform.claude.com/docs/en/manage-claude/wif-providers/github-actions);
do not reuse another repository's federation identity.

Recommended rule boundaries:

- Issuer: `https://token.actions.githubusercontent.com`
- Audience: `https://api.anthropic.com`
- Exact subject: `repo:shaboooooozy1/knowledge-work-plugins:ref:refs/heads/main`
- Claims: `repository=shaboooooozy1/knowledge-work-plugins`,
  `repository_id=1272807675`, `repository_owner_id=251044545`,
  `ref=refs/heads/main`, `event_name=workflow_dispatch`
- Scope: `workspace:inference`
- Token lifetime: 600 seconds
- Service account: member of the selected workspace

Configure these non-secret repository Actions variables:

| Variable | Value |
|---|---|
| `ANTHROPIC_FEDERATION_RULE_ID` | Your `fdrl_...` rule |
| `ANTHROPIC_ORGANIZATION_ID` | Your organization UUID |
| `ANTHROPIC_SERVICE_ACCOUNT_ID` | Your `svac_...` service account |
| `ANTHROPIC_WORKSPACE_ID` | Your `wrkspc_...` workspace, required for a multi-workspace rule |
| `POLICY_SCAN_MODEL` | Optional; defaults to `claude-sonnet-5-5` |

IDs are configuration, not tokens. Never put JWTs or access tokens in these
variables; the scanner obtains a fresh GitHub assertion for each exchange and
keeps the short-lived Anthropic token in memory without logging it.

## Trusted execution and exact-head review

The repair must be reviewed and merged into `main` before live runs. The
federated job refuses to run from feature or bump branches, and the target PR
must be an open, same-repository, single-plugin, SHA-only marketplace change.
Pull-request-triggered runs execute offline contract tests with read-only
permissions; those tests are not a policy verdict.

The PR delta is measured from its merge base, not from the latest main tip.
Unrelated main-branch changes are allowed, but a change to this plugin's current
main pin or metadata blocks the older bump as superseded. The head and relevant
main pin are checked again after review to catch concurrent changes.

Dispatch from `main`, supplying both the PR number and its current full head SHA:

```sh
gh workflow run scan-plugins.yml \
  --repo shaboooooozy1/knowledge-work-plugins \
  --ref main \
  -f pr_number=39 \
  -f expected_head_sha=055fecc0d9088364496dd6a80f99162e84d2832c
```

The example head is a historical snapshot. Refresh it before dispatching; a
different or changed head fails the review rather than approving unseen content.
The scanner publishes a `scan` check on that exact PR head and checks the head
again before success. No merge, approval, branch deletion or comment is made.

The bump workflow dispatches the trusted-main scanner regardless of whether it
opened the PR using `GITHUB_TOKEN` or a dedicated PR token. Rerunning an old scan
workflow on a bump branch is not the repaired path.

## Coverage and evidence

The current scanner accepts one plugin per run, checks every UTF-8 blob in the
selected Git source or subdirectory, and inventories PNG assets by hash.
Symlinks, submodules, unresolved Git LFS pointers, other binary files, more than
2,000 source files, or more than 512 KiB of payload cause an explicit
infrastructure failure instead of a partial approval.

All policy fields in `schema.json` are required and typed. Exact source identity,
full pin SHA and complete one-target/one-verdict coverage are validated; a
contradictory passing verdict is rejected. Invalid results are never cached, and
the old verdict cache is not reused.

Artifacts include `scan-status.json`, `run-verdicts.json`, `run-failed.json`, and
the source inventory when completed. Only these four paths are allowlisted for
upload; hidden-file inclusion is explicit because `.scan-cache` is a hidden
directory. Infrastructure failures leave
`run-failed.json` empty; they are not fabricated policy violations and must not
trigger automatic pin reverts. The old batched `bump/plugin-shas` revert workflow
does not run for these trusted-main, single-PR reviews.

This is a static policy review, not a runtime compatibility test or permission
to merge. Configure `scan` as a required check separately, with maintainer
approval, after verifying the check is reported correctly on a canary PR.

## Offline verification

```sh
node --test .github/scripts/policy-*.test.mjs
```

Tests use only fake credentials and mocked transports. They make no Anthropic
requests and do not exercise or alter the user's accounts.
