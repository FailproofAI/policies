# failproofai policy packs

The policies we publish for [failproofai](https://github.com/FailproofAI/failproofai).

```bash
failproofai policies add FailproofAI/policies
```

**This repository is not special.** It is a pack like anyone else's — published
as a GitHub release, fetched over anonymous HTTPS, verified and pinned. There is
no short name for it and no route it can take that yours cannot. If you want to
publish your own, [skip to the bottom](#publish-your-own).

---

## What is in it

38 policies across 9 categories. Ten are on by default; the rest are opt-in,
because switching on a stranger's every policy unattended is an opinion nobody
asked us for.

| Category | Guards against |
|---|---|
| **Sanitize** | JWTs, API keys, connection strings, private keys and bearer tokens in tool output |
| **Environment** | reading and writing `.env`, environment-variable dumps, reads outside the project |
| **Dangerous Commands** | `sudo`, `curl \| sh`, `rm -rf`, writing secret key files |
| **Infra Commands** | `kubectl`, `terraform`, `aws`, `gcloud`, `az`, `helm`, `gh` pipeline triggers |
| **Git** | pushing to `main`, force-push, working on `main`, amend, stash drop, `git add -A` |
| **Database** | destructive SQL, schema alteration |
| **Packages & System** | publishing to registries, global installs, wrong package manager, large writes, background processes |
| **AI Behavior** | repeated identical tool calls |
| **Workflow** | require commit / push / PR / no-conflicts / green CI before the agent stops |

See exactly what you would be installing, without downloading any code:

```bash
failproofai policies show FailproofAI/policies
```

That reads the **manifest only**. Looking at a pack never runs a pack.

## Take part of it

```bash
failproofai policies add FailproofAI/policies                        # the defaults
failproofai policies add FailproofAI/policies --policy block-sudo
failproofai policies add FailproofAI/policies --category sanitize,git
failproofai policies add FailproofAI/policies --all
```

Scope it to particular agents — it guards all twelve otherwise:

```bash
failproofai policies add FailproofAI/policies --cli claude codex
```

Re-adding at a newer version **keeps what you chose** rather than switching the
rest back on.

## How installing works

Installing resolves the newest release, **pins that exact tag**, verifies every
asset against `SHA256SUMS`, and records the digest locally. That digest is
re-verified before every import, so a pack cannot change under a machine after
it was installed — including this one.

A release carries exactly three assets, at fixed names:

```
failproofai-pack.json     the catalog: names, descriptions, categories, defaults
failproofai-pack.mjs      the single entry artifact — the only file that runs
SHA256SUMS                covering both
```

Install URLs are **constructed** from `owner/repo/tag`, never discovered. There
is no index to poison and no redirect to follow.

## Publish your own

Ours takes the same path yours does, and there is nothing to sign up for.

```bash
mkdir my-guards && cd my-guards
failproofai publish --init          # writes a policy that already works
# edit it, then:
failproofai policies -i -c ./my-guards.mjs   # enforce it here, before anyone sees it
failproofai publish --repo <you>/my-guards
```

Write as many files as you like — one per category reads well. `publish` finds
every file that registers policies, bundles them into the one artifact a pack
has to be, counts the next version from the repository's own releases, and
uploads. After the first time, `failproofai publish` on its own is the whole
command.

Full detail: `failproofai publish --help`.

## What a policy looks like

```js
import { customPolicies, allow, deny } from "failproofai";

customPolicies.add({
  name: "block-force-push",
  description: "Block git push --force on any branch",
  category: "Git",          // groups it in the picker; what --category selects
  defaultEnabled: true,     // on for someone who installs with no flags
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    if (ctx.toolName !== "Bash") return allow();
    const cmd = String(ctx.toolInput?.command ?? "");
    if (/\bgit\s+push\b[^|;&]*\s(-f|--force)\b/.test(cmd)) {
      return deny("Force-push rewrites history someone else may have pulled.");
    }
    return allow();
  },
});
```

`ctx.toolName` and `ctx.toolInput` are **canonical across all twelve agent
CLIs** — Claude Code, Codex, Copilot, Cursor, OpenCode, Pi, Hermes, OpenClaw,
Factory, Devin, Antigravity and Goose — so one policy written once works
everywhere failproofai runs.

## Licence

MIT.
