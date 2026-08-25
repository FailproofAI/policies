# failproofai policy packs

Policies for [failproofai](https://github.com/FailproofAI/failproofai), published
as a GitHub release.

```bash
failproofai policies add core
```

`core` is a short spelling of `FailproofAI/policies` — this repository. It is
fetched, digest-verified and pinned exactly like anybody else's pack, because it
**is** anybody else's pack. There is no second delivery path for ours.

## Nothing ships with the CLI

The npm package carries no policies at all. Installing `failproofai` puts no
policy on your disk and enforces nothing until you ask for a pack — including
this one.

That is deliberate. A pack shipped inside the binary is a policy set chosen for
you and written to your machine before you asked, and it gives our own policies a
delivery route no third-party pack could use, which is the opposite of what this
lane exists to make possible.

## Anyone can publish

There is no registry, no submission, no approval, and nothing to ask us for. A
pack is a GitHub release with three assets, in **your** repository:

```bash
failproofai publish ./my-policies.mjs --repo you/your-pack --version 1.0.0
```

Anyone then runs:

```bash
failproofai policies add you/your-pack
```

Nobody needs an account here. We do not see it, gate it, or host it. Ours is
just the pack whose short name we happen to spell.

The trade is that there is no discovery either: someone has to be told your
`owner/repo`, exactly as with a GitHub Action or a dotfiles repo.

## Looking before you install

```bash
failproofai policies show you/their-pack
```

Reads the manifest **only** — the entry artifact is never downloaded, so
deciding about a stranger's pack cannot run a stranger's code.

## Taking part of a pack

With no flags you get the pack's own defaults: what its author marked safe to
switch on unattended, not everything it contains.

```bash
failproofai policies add core --policy block-rm-rf
failproofai policies add core --category sanitize,git
failproofai policies add core --all
```

Naming no tag installs the newest release **and pins it**. Re-adding at a newer
version keeps what you chose rather than switching the rest back on.

## What a release contains

| Asset | What it is |
|---|---|
| `failproofai-pack.json` | The manifest: pack id, version, every policy's metadata |
| `failproofai-pack.mjs` | One entry artifact carrying every implementation |
| `SHA256SUMS` | Digests for both, checked at install |

The digest is recorded locally and re-verified before every import, so a pack
cannot change under a machine after it was installed.

One entry file is a requirement, not a convenience: only the entry is
content-addressed, so a multi-file pack could not honestly claim to be
digest-pinned. Bundle first if yours is split.

## `failproofai/core`

The 38 policies in this pack — sanitizers, dangerous-command guards, git
safety, and the `require-*-before-stop` gates.

`block-failproofai-commands` is deliberately **not** among them. It is the guard
that stops an agent disabling failproofai, it is `alwaysOn`, and the pack loader
refuses any pack declaring `alwaysOn` — so shipping it here would produce a pack
failproofai itself rejects. It stays compiled into the CLI, which is the only
place a guard that cannot be switched off belongs.

## Policy names may not contain a slash

The loader refuses them. A policy called `failproofai/block-sudo` would register
under the canonical name of a compiled guard and silently replace it; prefixing
happens in the loader instead, which is what keeps a pack out of that namespace.

---

Built by `bun run build:pack` in the failproofai repo. `policy`, `pack` and `p`
are all spellings of `policies`, so older commands keep working.
