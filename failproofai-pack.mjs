// ../../../../tmp/claude-1000/corepack/.entry.generated.ts
import { customPolicies } from "failproofai";

// src/hooks/builtin-policies.ts
import { resolve as resolve2, join as join2 } from "node:path";
import { statSync as statSync2 } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { execSync, execFileSync } from "node:child_process";
import { homedir as homedir2 } from "node:os";

// src/hooks/policy-catalog.ts
var POLICY_CATALOG = [
  {
    name: "sanitize-jwt",
    description: "Stop Claude from reading JWTs in tool responses",
    displayTitle: "Redacted JWT tokens from tool output",
    impact: "Stops the agent from echoing auth tokens it saw in command output.",
    match: { events: ["PostToolUse"] },
    authority: "hard",
    defaultEnabled: true,
    category: "Sanitize"
  },
  {
    name: "sanitize-api-keys",
    description: "Stop Claude from reading API keys (OpenAI, Anthropic, GitHub, AWS, Stripe, Google) in tool responses",
    displayTitle: "Redacted API keys from tool output",
    impact: "Catches OpenAI / Anthropic / GitHub / AWS / Stripe / Google keys before the model sees them.",
    match: { events: ["PostToolUse"] },
    authority: "hard",
    defaultEnabled: true,
    category: "Sanitize",
    params: {
      additionalPatterns: {
        type: "pattern[]",
        description: "Additional API key patterns to scrub, each with { regex, label }",
        default: []
      }
    }
  },
  {
    name: "sanitize-connection-strings",
    description: "Stop Claude from reading database connection strings with embedded credentials in tool responses",
    displayTitle: "Redacted database connection strings from tool output",
    impact: "Strips embedded DB credentials before they reach the model context.",
    match: { events: ["PostToolUse"] },
    authority: "hard",
    defaultEnabled: true,
    category: "Sanitize"
  },
  {
    name: "sanitize-private-key-content",
    description: "Stop Claude from reading PEM private key content in tool responses",
    displayTitle: "Redacted PEM private keys from tool output",
    impact: "Prevents private key bodies from being echoed into chat context.",
    match: { events: ["PostToolUse"] },
    authority: "hard",
    defaultEnabled: true,
    category: "Sanitize"
  },
  {
    name: "sanitize-bearer-tokens",
    displayTitle: "Redacted bearer tokens from tool output",
    impact: "Strips Authorization: Bearer values before they hit the model.",
    description: "Stop Claude from reading Authorization Bearer tokens in tool responses",
    match: { events: ["PostToolUse"] },
    authority: "hard",
    defaultEnabled: true,
    category: "Sanitize"
  },
  {
    name: "protect-env-vars",
    displayTitle: "Tried to dump environment variables to chat",
    impact: "Env vars often contain secrets; blocking `env` / `printenv` keeps them out of the model context.",
    description: "Prevent commands that read environment variables",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["env-secrets-dump", "secret-exposure"],
    defaultEnabled: true,
    category: "Environment"
  },
  {
    name: "block-env-files",
    displayTitle: "Tried to read or write a .env file",
    impact: "`.env` files routinely contain API keys and DB credentials.",
    description: "Block reading/writing .env files",
    match: { events: ["PreToolUse"] },
    authority: "reviewable",
    reviewedBy: ["secret-exposure"],
    defaultEnabled: true,
    category: "Environment"
  },
  {
    name: "block-read-outside-cwd",
    displayTitle: "Tried to read files outside your project directory",
    impact: "Stops the agent from peeking at neighboring repos or your home directory.",
    description: "Block file reads outside the session working directory",
    match: { events: ["PreToolUse"], toolNames: ["Read", "Glob", "Grep", "Bash"] },
    authority: "reviewable",
    reviewedBy: ["read-outside-workspace"],
    defaultEnabled: false,
    category: "Environment",
    params: {
      allowPaths: {
        type: "string[]",
        description: "Absolute paths outside cwd that are allowed to be read",
        default: []
      }
    }
  },
  {
    name: "block-sudo",
    displayTitle: "Tried to run a command with sudo",
    impact: "Sudo gives the agent root — blocked unless explicitly allow-listed.",
    description: "Block sudo commands",
    match: { events: ["PreToolUse", "PermissionRequest"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: true,
    category: "Dangerous Commands",
    params: {
      allowPatterns: {
        type: "string[]",
        description: "Sudo command patterns to allow, matched token-by-token (e.g. 'sudo systemctl status')",
        default: []
      }
    }
  },
  {
    name: "block-curl-pipe-sh",
    displayTitle: "Tried to pipe a downloaded script straight to a shell",
    impact: "`curl ... | sh` runs unverified remote code on your machine.",
    description: "Block piping downloads to shell",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: true,
    category: "Dangerous Commands"
  },
  {
    name: "block-rm-rf",
    displayTitle: "Tried to recursively delete a system path",
    impact: "Catches catastrophic `rm -rf /` and Windows equivalents.",
    description: "Prevent catastrophic deletions",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["destructive-deletion"],
    defaultEnabled: false,
    category: "Dangerous Commands",
    params: {
      allowPaths: {
        type: "string[]",
        description: "Paths that are allowed to be recursively deleted",
        default: []
      }
    }
  },
  {
    name: "block-failproofai-commands",
    displayTitle: "Tried to disable, pause or modify failproofai itself",
    impact: "An agent that can pause or remove enforcement can switch off every other policy.",
    description: "Block failproofai CLI commands, self-pause and uninstallation",
    match: {
      events: ["PreToolUse", "PermissionRequest"],
      toolNames: ["Bash", "Write", "Edit", "NotebookEdit"]
    },
    defaultEnabled: true,
    alwaysOn: true,
    authority: "hard",
    category: "Dangerous Commands"
  },
  {
    name: "block-kubectl",
    displayTitle: "Tried to run a Kubernetes command",
    impact: "kubectl can change live cluster state — gated unless allow-listed.",
    description: "Block kubectl commands (Kubernetes cluster mutations)",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["production-infra-change"],
    defaultEnabled: false,
    category: "Infra Commands",
    params: {
      allowPatterns: {
        type: "string[]",
        description: "kubectl command patterns to allow, matched token-by-token (e.g. 'kubectl get *', 'kubectl describe *')",
        default: []
      }
    }
  },
  {
    name: "block-terraform",
    displayTitle: "Tried to run a Terraform/OpenTofu command",
    impact: "Terraform mutates real infrastructure — gated unless allow-listed.",
    description: "Block terraform and tofu (OpenTofu) commands",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["production-infra-change"],
    defaultEnabled: false,
    category: "Infra Commands",
    params: {
      allowPatterns: {
        type: "string[]",
        description: "terraform/tofu command patterns to allow (e.g. 'terraform plan', 'terraform validate')",
        default: []
      }
    }
  },
  {
    name: "block-aws-cli",
    displayTitle: "Tried to run an AWS CLI command",
    impact: "AWS CLI can spend money or break prod — gated.",
    description: "Block aws CLI commands",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["production-infra-change"],
    defaultEnabled: false,
    category: "Infra Commands",
    params: {
      allowPatterns: {
        type: "string[]",
        description: "aws CLI command patterns to allow (e.g. 'aws s3 ls *', 'aws sts get-caller-identity')",
        default: []
      }
    }
  },
  {
    name: "block-gcloud",
    displayTitle: "Tried to run a Google Cloud command",
    impact: "gcloud can spend money or break prod — gated.",
    description: "Block gcloud (Google Cloud) CLI commands",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["production-infra-change"],
    defaultEnabled: false,
    category: "Infra Commands",
    params: {
      allowPatterns: {
        type: "string[]",
        description: "gcloud command patterns to allow (e.g. 'gcloud auth list', 'gcloud config list')",
        default: []
      }
    }
  },
  {
    name: "block-az-cli",
    displayTitle: "Tried to run an Azure CLI command",
    impact: "az can spend money or break prod — gated.",
    description: "Block az (Azure) CLI commands",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["production-infra-change"],
    defaultEnabled: false,
    category: "Infra Commands",
    params: {
      allowPatterns: {
        type: "string[]",
        description: "az CLI command patterns to allow (e.g. 'az account show', 'az group list')",
        default: []
      }
    }
  },
  {
    name: "block-helm",
    displayTitle: "Tried to run a Helm command",
    impact: "Helm releases mutate cluster state — gated.",
    description: "Block helm commands",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["production-infra-change"],
    defaultEnabled: false,
    category: "Infra Commands",
    params: {
      allowPatterns: {
        type: "string[]",
        description: "helm command patterns to allow (e.g. 'helm list', 'helm status *')",
        default: []
      }
    }
  },
  {
    name: "block-gh-pipeline",
    displayTitle: "Tried to run a privileged GitHub CLI pipeline command",
    impact: "Catches `gh workflow run`, `gh pr merge`, `gh secret set`, etc.",
    description: "Block gh CLI pipeline-trigger subcommands (workflow run, run rerun/cancel, pr merge, release create/delete, cache delete, secret set/delete)",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Infra Commands",
    params: {
      allowPatterns: {
        type: "string[]",
        description: "gh pipeline command patterns to allow (e.g. specific scripted invocations); read-only gh subcommands like 'gh pr view' and 'gh run list' are not matched by this policy",
        default: []
      }
    }
  },
  {
    name: "block-secrets-write",
    displayTitle: "Tried to write a secret-key file",
    impact: "Stops the agent from creating `.pem`, `id_rsa`, `credentials.json`, etc.",
    description: "Block writing secret key files",
    match: { events: ["PreToolUse"], toolNames: ["Write"] },
    authority: "reviewable",
    reviewedBy: ["secret-exposure"],
    defaultEnabled: false,
    category: "Dangerous Commands",
    params: {
      additionalPatterns: {
        type: "string[]",
        description: "Additional filename patterns (substrings) to block",
        default: []
      }
    }
  },
  {
    name: "block-push-master",
    displayTitle: "Tried to push directly to main/master",
    impact: "Direct pushes to a protected branch bypass review.",
    description: "Block pushing to main/master",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: true,
    category: "Git",
    params: {
      protectedBranches: {
        type: "string[]",
        description: "Branch names to protect from direct pushes",
        default: ["main", "master"]
      }
    }
  },
  {
    name: "block-force-push",
    displayTitle: "Tried to force-push",
    impact: "Force-pushes rewrite history and can clobber teammates' work.",
    description: "Prevent force-pushing to any branch",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["git-history-rewrite"],
    defaultEnabled: false,
    category: "Git"
  },
  {
    name: "block-work-on-main",
    displayTitle: "Tried to commit or merge on main/master",
    impact: "Work should land via PR — direct commits skip review.",
    description: "Block git commits and merges on main/master branch",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Git",
    params: {
      protectedBranches: {
        type: "string[]",
        description: "Branch names where commits/merges are blocked",
        default: ["main", "master"]
      }
    }
  },
  {
    name: "warn-git-amend",
    displayTitle: "Used git commit --amend",
    impact: "Amending after a push rewrites history that others may have pulled.",
    description: "Warns before amending git commits, which rewrites history",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["git-history-rewrite"],
    defaultEnabled: false,
    category: "Git"
  },
  {
    name: "warn-git-stash-drop",
    displayTitle: "Tried to drop or clear git stash",
    impact: "Stash deletions are permanent and silent.",
    description: "Warns before permanently deleting stashed changes",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Git"
  },
  {
    name: "warn-git-clean",
    displayTitle: "Tried to delete untracked or ignored files with git clean",
    impact: "`git clean -fdx` takes `.env`, local config and unstaged work — git never had a copy of any of it.",
    description: "Warns before git clean deletes untracked directories (-d) or ignored files (-x / -X)",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Git",
    params: {
      destructiveFlags: {
        type: "string[]",
        description: "git clean flag letters that make it worth warning about, checked alongside --force. Narrow to ['x','X'] to allow `git clean -fd`, or widen with 'f' to warn on a bare `git clean -f`.",
        default: ["d", "x", "X"]
      }
    }
  },
  {
    name: "warn-all-files-staged",
    displayTitle: "Staged all files with git add -A / .",
    impact: "Wide stages routinely catch generated files or secrets you didn't intend to commit.",
    description: "Warns before staging all working tree files with git add -A / . / --all",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Git"
  },
  {
    name: "warn-destructive-sql",
    displayTitle: "Ran destructive SQL (DROP / TRUNCATE / DELETE without WHERE)",
    impact: "Easy way to wipe a table by accident.",
    description: "Warn before executing destructive SQL (DROP/TRUNCATE/DELETE without WHERE) via database clients",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["database-destruction"],
    defaultEnabled: false,
    category: "Database"
  },
  {
    name: "warn-schema-alteration",
    displayTitle: "Altered a database schema column",
    impact: "ALTER TABLE operations can lock tables and break readers.",
    description: "Warns before SQL schema changes (ALTER TABLE with column or rename operations)",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Database"
  },
  {
    name: "warn-package-publish",
    displayTitle: "Tried to publish a package",
    impact: "Publishes are irreversible — `npm publish` / `cargo publish` shouldn't happen without intent.",
    description: "Warn before publishing packages to public registries (npm, PyPI, crates.io, RubyGems, etc.)",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Packages & System"
  },
  {
    name: "warn-global-package-install",
    displayTitle: "Installed a package globally",
    impact: "`npm i -g`, `cargo install`, `pip --user` pollute your machine outside the project.",
    description: "Warns before installing packages globally (npm -g, cargo install, etc.)",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "reviewable",
    reviewedBy: ["system-modification"],
    defaultEnabled: false,
    category: "Packages & System"
  },
  {
    name: "prefer-package-manager",
    displayTitle: "Used a non-preferred package manager",
    impact: "Mixing package managers creates lockfile churn for your team.",
    description: "Blocks non-preferred package managers and tells Claude to use an allowed one (e.g., uv instead of pip)",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Packages & System",
    params: {
      allowed: {
        type: "string[]",
        description: "Allowed package manager names (e.g. ['uv', 'bun']). Any detected manager not in this list is blocked.",
        default: []
      },
      blocked: {
        type: "string[]",
        description: "Additional manager names to block beyond the built-in list (e.g. ['pdm', 'pipx']).",
        default: []
      }
    }
  },
  {
    name: "warn-large-file-write",
    displayTitle: "Wrote a file larger than the configured threshold",
    impact: "Catches accidentally large file writes (logs, binaries, model dumps).",
    description: "Warn before writing files larger than 1MB (configurable via thresholdKb param)",
    match: { events: ["PreToolUse"], toolNames: ["Write"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Packages & System",
    params: {
      thresholdKb: {
        type: "number",
        description: "File size threshold in KB above which a warning is issued",
        default: 1024
      }
    }
  },
  {
    name: "warn-background-process",
    displayTitle: "Started a long-lived background process",
    impact: "Catches `nohup` / `&` / `screen` / `tmux` / `disown` patterns that the agent often forgets to clean up.",
    description: "Warns before starting detached or background processes",
    match: { events: ["PreToolUse"], toolNames: ["Bash"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Packages & System"
  },
  {
    name: "warn-repeated-tool-calls",
    displayTitle: "Called the same tool 3+ times with identical arguments",
    impact: "Usually a sign of a stuck loop burning tokens.",
    description: "Warn when the same tool is called 3+ times with identical parameters",
    match: { events: ["PreToolUse"] },
    authority: "hard",
    defaultEnabled: false,
    category: "AI Behavior"
  },
  {
    name: "require-commit-before-stop",
    displayTitle: "Stopped with uncommitted changes",
    impact: "Work not in a commit is invisible to teammates and easy to lose.",
    description: "Require all changes to be committed before Claude stops",
    match: { events: ["Stop"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Workflow"
  },
  {
    name: "require-push-before-stop",
    displayTitle: "Stopped with unpushed commits",
    impact: "Local-only commits won't trigger CI or be reviewable.",
    description: "Require all commits to be pushed to remote before Claude stops",
    match: { events: ["Stop"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Workflow",
    params: {
      remote: {
        type: "string",
        description: "Remote name to push to (default: origin)",
        default: "origin"
      },
      baseBranch: {
        type: "string",
        description: "Base branch to compare against (default: main)",
        default: "main"
      }
    }
  },
  {
    name: "require-pr-before-stop",
    displayTitle: "Stopped without a PR for the branch",
    impact: "Branches without PRs don't get reviewed.",
    description: "Require a pull request to exist for the current branch before Claude stops",
    match: { events: ["Stop"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Workflow",
    params: {
      baseBranch: {
        type: "string",
        description: "Base branch to compare against (default: main)",
        default: "main"
      }
    }
  },
  {
    name: "require-no-conflicts-before-stop",
    displayTitle: "Stopped with a branch that conflicts with main",
    impact: "Conflicting branches can't merge — surface them early.",
    description: "Require the current branch to merge cleanly with the base branch before Claude stops",
    match: { events: ["Stop"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Workflow",
    params: {
      baseBranch: {
        type: "string",
        description: "Base branch to check for conflicts against (default: main)",
        default: "main"
      }
    }
  },
  {
    name: "require-ci-green-before-stop",
    displayTitle: "Stopped with failing CI",
    impact: "Failing CI blocks deploy.",
    description: "Require CI checks to pass on the current HEAD commit before Claude stops (ignores stale runs on prior commits)",
    match: { events: ["Stop"] },
    authority: "hard",
    defaultEnabled: false,
    category: "Workflow"
  }
];

// src/hooks/policy-helpers.ts
function allow(reason) {
  return reason ? { decision: "allow", reason } : { decision: "allow" };
}
function deny(reason) {
  return { decision: "deny", reason };
}
function instruct(reason) {
  return { decision: "instruct", reason };
}
// src/hooks/fp-home.ts
import { homedir } from "node:os";
import { resolve } from "node:path";
function failproofaiHome(home) {
  if (home)
    return resolve(home, ".failproofai");
  return process.env.FAILPROOFAI_HOME || resolve(homedir(), ".failproofai");
}
var at = (...parts) => resolve(failproofaiHome(), ...parts);
var atHome = (home, ...parts) => home ? resolve(failproofaiHome(home), ...parts) : at(...parts);
var logsDir = (home) => atHome(home, "logs");

// src/hooks/hook-logger.ts
import {
  appendFileSync,
  renameSync,
  mkdirSync,
  existsSync,
  statSync
} from "node:fs";
import { join } from "node:path";
var LEVEL_ORDER = { info: 0, warn: 1, error: 2 };
var MAX_FILE_SIZE = 512 * 1024;
var LOG_FILENAME = "hooks.log";
var DEFAULT_LOG_DIR = logsDir();
var resolved = false;
var currentLevel = "warn";
var fileLoggingEnabled = false;
var logDir = DEFAULT_LOG_DIR;
function ensureResolved() {
  if (resolved)
    return;
  resolved = true;
  const rawLevel = (process.env.FAILPROOFAI_LOG_LEVEL ?? "").toLowerCase();
  if (rawLevel === "info" || rawLevel === "warn" || rawLevel === "error") {
    currentLevel = rawLevel;
  }
  const rawFile = (process.env.FAILPROOFAI_HOOK_LOG_FILE ?? "").trim();
  if (rawFile) {
    fileLoggingEnabled = true;
    if (rawFile !== "1" && rawFile !== "true") {
      logDir = rawFile;
    }
  }
}
function shouldEmit(level) {
  ensureResolved();
  return LEVEL_ORDER[level] >= LEVEL_ORDER[currentLevel];
}
function emitStderr(label, msg) {
  process.stderr.write(`[failproofai:hook] ${label} ${msg}
`);
}
function ensureLogDir() {
  if (!existsSync(logDir)) {
    mkdirSync(logDir, { recursive: true });
  }
}
function rotateIfNeeded(filePath) {
  try {
    const stats = statSync(filePath);
    if (stats.size >= MAX_FILE_SIZE) {
      const archiveName = `hooks-${Date.now()}.log`;
      renameSync(filePath, join(logDir, archiveName));
    }
  } catch {}
}
function appendToFile(label, msg) {
  if (!fileLoggingEnabled)
    return;
  try {
    ensureLogDir();
    const filePath = join(logDir, LOG_FILENAME);
    rotateIfNeeded(filePath);
    const timestamp = new Date().toISOString();
    const line = `[${timestamp}] ${label} ${msg}
`;
    appendFileSync(filePath, line, "utf-8");
  } catch {}
}
function hookLogWarn(msg) {
  if (!shouldEmit("warn"))
    return;
  emitStderr("WARN", msg);
  appendToFile("WARN", msg);
}

// src/hooks/policy-authority.ts
var SEMANTIC_POLICY_NAMES = [
  "destructive-deletion",
  "production-infra-change",
  "git-history-rewrite",
  "push-to-protected-branch",
  "commit-on-protected-branch",
  "secret-exposure",
  "credential-exfiltration",
  "remote-code-execution",
  "privilege-escalation",
  "database-destruction",
  "read-outside-workspace",
  "agent-config-tampering",
  "system-modification",
  "env-secrets-dump",
  "external-destructive-action",
  "external-data-egress"
];
var SEMANTIC_REVIEWER_NAMES = new Set(SEMANTIC_POLICY_NAMES);
var warnedAuthority = new Set;

// src/hooks/pack-manifest.ts
var RESERVED_PROBE_IDS = new Set(["exempt", "user_asked"]);
var SEMANTIC_TOOL_CLASSES = new Set(["shell", "write", "read", "network", "other"]);
var PARAM_TYPES = new Set(["string", "number", "boolean", "string[]", "pattern[]"]);

// src/hooks/builtin-policies.ts
function isAgentInternalPath(resolved2) {
  const normResolved = resolved2.replaceAll("\\", "/");
  for (const dir of [".claude", ".codex", ".copilot", ".cursor", ".opencode", ".pi", ".gemini"]) {
    const root = join2(homedir2(), dir).replaceAll("\\", "/");
    if (normResolved === root || normResolved.startsWith(root + "/"))
      return true;
  }
  for (const sub of [join2(".config", "opencode"), join2(".local", "share", "opencode")]) {
    const root = join2(homedir2(), sub).replaceAll("\\", "/");
    if (normResolved === root || normResolved.startsWith(root + "/"))
      return true;
  }
  return false;
}
function isAgentSettingsFile(resolved2) {
  if (/[\\/]\.claude[\\/]settings(?:\.[^/\\]+)?\.json$/.test(resolved2))
    return true;
  if (/[\\/]\.codex[\\/]hooks\.json$/.test(resolved2))
    return true;
  if (/[\\/]\.copilot[\\/]hooks[\\/][^/\\]+\.json$/.test(resolved2))
    return true;
  if (/[\\/]\.github[\\/]hooks[\\/][^/\\]+\.json$/.test(resolved2))
    return true;
  if (/[\\/]\.cursor[\\/]hooks\.json$/.test(resolved2))
    return true;
  if (/[\\/]\.opencode[\\/]opencode\.jsonc?$/.test(resolved2))
    return true;
  if (/[\\/]\.opencode[\\/]plugins[\\/][^/\\]+\.(?:mjs|js|ts)$/.test(resolved2))
    return true;
  if (/[\\/]\.config[\\/]opencode[\\/]opencode\.jsonc?$/.test(resolved2))
    return true;
  if (/[\\/]\.config[\\/]opencode[\\/]config\.json$/.test(resolved2))
    return true;
  if (/[\\/]\.config[\\/]opencode[\\/]plugins[\\/][^/\\]+\.(?:mjs|js|ts)$/.test(resolved2))
    return true;
  if (/[\\/]\.pi[\\/](?:agent[\\/])?settings\.json$/.test(resolved2))
    return true;
  if (/[\\/]\.pi[\\/](?:agent[\\/])?extensions[\\/]/.test(resolved2))
    return true;
  if (/[\\/]\.gemini[\\/]settings\.json$/.test(resolved2))
    return true;
  if (/[\\/]\.gemini[\\/]config[\\/]hooks\.json$/.test(resolved2))
    return true;
  return false;
}
var isClaudeInternalPath = isAgentInternalPath;
var isClaudeSettingsFile = isAgentSettingsFile;
function getCommand(ctx) {
  return ctx.toolInput?.command ?? "";
}
function getFilePath(ctx) {
  return ctx.toolInput?.file_path ?? "";
}
function parseArgvTokens(cmd) {
  return cmd.trim().split(/\s+/).map((t) => t.replace(/^['"]|['"]$/g, ""));
}
var SHELL_OPERATORS = new Set(["&&", "||", "|", ";"]);
var SHELL_METACHAR_RE = /[;&<>`$()\\]/;
var JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;
var API_KEY_PATTERNS = [
  [/sk-ant-[A-Za-z0-9\-_]{20,}/, "Anthropic API key"],
  [/sk-proj-[A-Za-z0-9\-_]{20,}/, "OpenAI project API key"],
  [/sk-[A-Za-z0-9]{20,}/, "OpenAI API key"],
  [/ghp_[A-Za-z0-9]{36}/, "GitHub personal access token"],
  [/github_pat_[A-Za-z0-9_]{82}/, "GitHub fine-grained token"],
  [/AKIA[A-Z0-9]{16}/, "AWS access key ID"],
  [/sk_live_[A-Za-z0-9]{24,}/, "Stripe live secret key"],
  [/sk_test_[A-Za-z0-9]{24,}/, "Stripe test secret key"],
  [/AIza[0-9A-Za-z\-_]{35}/, "Google API key"]
];
var CONNECTION_STRING_RE = /(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|amqps?|smtps?):\/\/[^@\s]+@/;
var PRIVATE_KEY_RE = /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/;
var BEARER_TOKEN_RE = /Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}/i;
var SECRET_PATTERNS = [
  [PRIVATE_KEY_RE, "private key"],
  [JWT_RE, "JWT"],
  [BEARER_TOKEN_RE, "bearer token"],
  [CONNECTION_STRING_RE, "database credentials"],
  ...API_KEY_PATTERNS
];
var SQL_TOOL_RE = /\b(?:psql|mysql|sqlite3|pgcli|clickhouse-client)\b/;
var DESTRUCTIVE_SQL_RE = /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\b)/i;
var DELETE_NO_WHERE_RE = /\bDELETE\s+FROM\b/i;
var SQL_WHERE_RE = /\bWHERE\b/i;
var SCHEMA_ALTER_RE = /\bALTER\s+TABLE\b[\s\S]*\b(?:DROP\s+COLUMN|ADD\s+COLUMN|RENAME\s+(?:COLUMN|TO)|MODIFY\s+COLUMN)\b/i;
var PUBLISH_CMD_RE = /(?:npm\s+publish|bun\s+publish|pnpm\s+publish|yarn\s+npm\s+publish|twine\s+upload|poetry\s+publish|cargo\s+publish|gem\s+push)\b/;
var ENV_PRINTENV_RE = /(?:^|\s|;|&&|\|\|)(?:env|printenv)(?:\s|$|;|&&|\|)/;
var ECHO_ENV_RE = /echo\s+.*\$\{?[A-Za-z_]/;
var EXPORT_RE = /(?:^|\s|;|&&|\|\|)export\s+\w+/;
var PS_ENV_VAR_RE = /\$env:[A-Za-z_]/i;
var PS_CHILDITEM_ENV_RE = /(?:Get-ChildItem|dir|gci|ls)\s+Env:/i;
var DOTNET_GETENV_RE = /\[Environment\]::GetEnvironment/i;
var CMD_ECHO_ENV_RE = /echo\s+%[A-Za-z_]/i;
var ENV_FILE_PATH_RE = /(?:^|[\\/])\.env(?:\.|$)/;
var ENV_CMD_RE = /\.env(?:\b|\s|$|\.)/;
var PS_ELEVATION_RE = /Start-Process\s+.*-Verb\s+RunAs/i;
var RUNAS_RE = /(?:^|;|&&|\|\|)\s*runas\s/i;
var CURL_PIPE_SH_RE = /(?:curl|wget)\s.*\|\s*(?:sh|bash|zsh|dash|ksh|csh|tcsh|fish|ash)\b/;
var SEGMENT_SEPARATORS = /[;&|\n\r(){}`]+/;
var COMMAND_PREFIX_TOKENS = new Set([
  "npx",
  "bunx",
  "pnpx",
  "npm",
  "pnpm",
  "yarn",
  "dlx",
  "exec",
  "run",
  "eval",
  "node",
  "bun",
  "deno",
  "env",
  "command",
  "builtin",
  "nohup",
  "setsid",
  "time",
  "timeout",
  "nice",
  "stdbuf",
  "xargs",
  "sudo",
  "doas",
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "fish",
  "ash"
]);
var SELF_BINARY_TOKEN_RE = /(?:^|\/)failproofai[^/]*$/;
var SELF_ENTRY_PATH_RE = /failproofai\/(?:dist\/(?:cli|index)\.mjs|bin\/failproofai\.mjs)$/;
var CONFIG_SUBCOMMAND_RE = /^(?:config|configure|setup)$/;
var PAUSE_FLAG_RE = /^--pause(?:=|$)/;
var ENV_ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;
var RUNNER_OPERAND_RE = /^\d+[a-z]*$/i;
function classifySelfInvocation(raw) {
  const command = raw.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, "$$$1");
  let found = null;
  const selfVars = new Set;
  for (const [, name, value] of command.matchAll(/(?:^|[\s;&|])([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|]+)/g)) {
    const bare = value.replace(/^["']|["']$/g, "");
    if (SELF_BINARY_TOKEN_RE.test(bare) || SELF_ENTRY_PATH_RE.test(bare))
      selfVars.add(name);
  }
  const isSelfVarRef = (token) => {
    const m = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/.exec(token);
    return m ? selfVars.has(m[1]) : false;
  };
  for (const segment of command.split(SEGMENT_SEPARATORS)) {
    const tokens = segment.split(/\s+/).filter(Boolean);
    let i = 0;
    while (i < tokens.length) {
      const token = tokens[i];
      const isSkippable = ENV_ASSIGNMENT_RE.test(token) || token.startsWith("-") || token.startsWith(">") || token.startsWith("<") || RUNNER_OPERAND_RE.test(token) || COMMAND_PREFIX_TOKENS.has(token.slice(token.lastIndexOf("/") + 1));
      if (!isSkippable)
        break;
      i++;
    }
    if (i >= tokens.length)
      continue;
    if (!SELF_BINARY_TOKEN_RE.test(tokens[i]) && !SELF_ENTRY_PATH_RE.test(tokens[i]) && !isSelfVarRef(tokens[i])) {
      continue;
    }
    const args = tokens.slice(i + 1);
    const configAt = args.findIndex((a) => CONFIG_SUBCOMMAND_RE.test(a));
    if (configAt !== -1 && args.slice(configAt + 1).some((a) => PAUSE_FLAG_RE.test(a))) {
      return "pause";
    }
    found = "cli";
  }
  return found;
}
function decodeAnsiC(body) {
  return body.replace(/\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|.)/g, (_, seq) => {
    try {
      if (seq[0] === "x")
        return String.fromCharCode(parseInt(seq.slice(1), 16));
      if (seq[0] === "u" || seq[0] === "U")
        return String.fromCodePoint(parseInt(seq.slice(1), 16));
      if (/^[0-7]+$/.test(seq))
        return String.fromCharCode(parseInt(seq, 8));
    } catch {
      return seq;
    }
    const named = {
      a: "\x07",
      b: "\b",
      e: "\x1B",
      f: "\f",
      n: `
`,
      r: "\r",
      t: "\t",
      v: "\v",
      "\\": "\\",
      "'": "'",
      '"': '"',
      "?": "?"
    };
    return named[seq] ?? seq;
  });
}
function stripShellQuoting(command) {
  const joined = command.replace(/\\\r?\n/g, "");
  const ansiDecoded = joined.replace(/\$'((?:[^'\\]|\\.)*)'/g, (_, body) => decodeAnsiC(body));
  return ansiDecoded.replace(/\\(.)/g, "$1").replace(/['"]/g, "");
}
var PS_WEB_PIPE_RE = /(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\s+.*\|\s*(?:Invoke-Expression|iex)/i;
var SHORT_FLAG_BUNDLE_RE = /^-[a-zA-Z]*f[a-zA-Z]*$/;
var SAFE_FORCE_PREFIXES = ["--force-with-lease", "--force-if-includes"];
var SECRET_FILE_RE = /\.(?:pem|key)$/;
var SECRET_FILE_ID_RSA_RE = /id_rsa/;
var SECRET_FILE_CREDENTIALS_RE = /credentials/;
var GIT_COMMIT_MERGE_RE = /git\s+(commit|merge|rebase|cherry-pick)\b/;
var FAILPROOFAI_STATE_PATH_RE = /\.failproofai(?:\/|\b)/;
var STATE_READ_COMMANDS = new Set([
  "cat",
  "bat",
  "less",
  "more",
  "head",
  "tail",
  "nl",
  "strings",
  "xxd",
  "od",
  "jq",
  "yq",
  "diff",
  "cmp",
  "wc",
  "sort",
  "uniq",
  "column",
  "awk",
  "cut",
  "ls",
  "dir",
  "tree",
  "stat",
  "file",
  "du",
  "df",
  "readlink",
  "realpath",
  "basename",
  "dirname",
  "pwd",
  "test",
  "find",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "ag",
  "ack",
  "md5sum",
  "sha1sum",
  "sha256sum",
  "shasum",
  "cksum",
  "cd",
  "pushd",
  "popd",
  "cp",
  "rsync",
  "install",
  "tee",
  "sed",
  "true",
  "false",
  ":",
  "echo",
  "printf",
  "[",
  "[[",
  "]",
  "]]",
  "test",
  "read",
  "for",
  "select",
  "case",
  "done",
  "fi",
  "esac"
]);
var SHELL_KEYWORD_PREFIXES = new Set(["do", "then", "else", "elif", "if", "while", "until", "!"]);
var LOOP_HEADER_RE = /(?:^|[\s(])(?:while|until|for|select)\s/;
var COPY_COMMANDS = new Set(["cp", "rsync", "install"]);
var OPERAND_WRITE_COMMANDS = new Set(["tee"]);
var SECOND_OPERAND_WRITERS = new Set(["uniq", "xxd"]);
var OUTPUT_FLAG_COMMANDS = {
  sort: ["-o", "--output"],
  tree: ["-o", "--output"],
  curl: ["-o", "--output", "--output-dir", "-D", "--dump-header", "--trace", "--trace-ascii"]
};
var FIND_WRITE_ACTIONS = new Set(["-fprint", "-fprint0", "-fprintf", "-fls"]);
var SAFE_EXEC_COMMANDS = new Set([
  "cat",
  "bat",
  "head",
  "tail",
  "nl",
  "strings",
  "xxd",
  "od",
  "jq",
  "yq",
  "wc",
  "ls",
  "stat",
  "file",
  "du",
  "readlink",
  "realpath",
  "basename",
  "dirname",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "md5sum",
  "sha1sum",
  "sha256sum",
  "shasum",
  "cksum",
  "echo",
  "printf",
  "true",
  ":"
]);
var GIT_DESTRUCTIVE_SUBCOMMANDS = new Set([
  "clean",
  "rm",
  "restore",
  "checkout",
  "reset",
  "stash"
]);
var GIT_FLAGS_WITH_OPERANDS = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"]);
function gitSubcommandIndex(args) {
  for (let i = 0;i < args.length; i++) {
    const arg = args[i];
    if (GIT_FLAGS_WITH_OPERANDS.has(arg)) {
      i++;
      continue;
    }
    if (arg.startsWith("-"))
      continue;
    return i;
  }
  return -1;
}
function gitSubcommand(args) {
  const i = gitSubcommandIndex(args);
  return i < 0 ? undefined : args[i];
}
var STATE_MENTION_COMMANDS = new Set(["git", "gh", "glab", "echo", "printf", "curl", "code", "open"]);
var FIND_EXEC_ACTIONS = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
var PIPELINE_SEPARATORS = /\|\||&&|[;\n\r&]+/;
var VAR_REFERENCE_RE = /\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g;
var STATE_GLOB_CANDIDATES = [
  ".failproofai",
  "~/.failproofai",
  "$HOME/.failproofai",
  "${HOME}/.failproofai",
  "/root/.failproofai",
  "/home/u/.failproofai",
  "/Users/u/.failproofai"
];
var GLOB_DECOYS = [
  ".config",
  ".cache",
  ".local",
  ".git",
  ".npm",
  ".ssh",
  ".bashrc",
  "node_modules",
  "dist",
  "build",
  "target",
  "coverage",
  "tmp",
  "src",
  "~/.config",
  "~/.cache",
  "$HOME/.config",
  "${HOME}/.cache",
  "/home/u/.config",
  "/Users/u/.config",
  "/root/.cache",
  "/tmp/build",
  "a",
  "foo.txt",
  "test-failures"
];
function globCouldNameState(raw) {
  const stripped = raw.replace(/^[()]+|[()]+$/g, "");
  return globWordCouldNameState(raw) || stripped !== raw && globWordCouldNameState(stripped);
}
function globWordCouldNameState(token) {
  if (!GLOB_METACHAR_RE.test(token))
    return false;
  for (const word of expandBraces(token)) {
    if (wordNamesState(word))
      return true;
  }
  return false;
}
var BRACE_EXPANSION_LIMIT = 4096;
var BRACE_EXPANSION_ROUNDS = 24;
function expandBraces(token) {
  let words = [token];
  for (let round = 0;round < BRACE_EXPANSION_ROUNDS; round++) {
    const next = [];
    let expanded = false;
    for (const word of words) {
      const group = firstBraceGroup(word);
      if (!group) {
        next.push(word);
        continue;
      }
      expanded = true;
      for (const alternative of group.alternatives) {
        next.push(word.slice(0, group.start) + alternative + word.slice(group.end + 1));
      }
    }
    if (!expanded)
      return next;
    if (next.length > BRACE_EXPANSION_LIMIT)
      return [collapseBraces(token)];
    words = next;
  }
  return words.map(collapseBraces);
}
function collapseBraces(word) {
  let out = "";
  let depth = 0;
  for (const ch of word) {
    if (ch === "{") {
      if (depth === 0)
        out += "*";
      depth++;
      continue;
    }
    if (ch === "}") {
      if (depth > 0)
        depth--;
      continue;
    }
    if (depth === 0)
      out += ch;
  }
  return out;
}
function firstBraceGroup(word) {
  const start = word.indexOf("{");
  if (start === -1)
    return null;
  let depth = 0;
  const alternatives = [];
  let current = "";
  for (let i = start;i < word.length; i++) {
    const ch = word[i];
    if (ch === "{") {
      depth++;
      if (depth === 1)
        continue;
    } else if (ch === "}") {
      depth--;
      if (depth === 0) {
        alternatives.push(current);
        return { start, end: i, alternatives };
      }
    } else if (ch === "," && depth === 1) {
      alternatives.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  return null;
}
function wordNamesState(word) {
  if (FAILPROOFAI_STATE_PATH_RE.test(word))
    return true;
  const segments = word.split("/");
  for (let end = 1;end <= segments.length; end++) {
    if (globPrefixNamesState(segments.slice(0, end).join("/")))
      return true;
  }
  return false;
}
var GLOB_METACHAR_RE = /[*?[{]|[@+!]\(/;
function compileGlobPattern(token) {
  let pattern = "";
  for (let i = 0;i < token.length; i++) {
    const extended = extglobAt(token, i);
    if (extended) {
      pattern += extended.source;
      i = extended.end;
      continue;
    }
    const ch = token[i];
    if (ch === "*")
      pattern += "[^/]*";
    else if (ch === "?")
      pattern += "[^/]";
    else if (ch === "[") {
      const bracket = bracketExpressionAt(token, i);
      if (!bracket) {
        pattern += "\\[";
        continue;
      }
      pattern += bracket.source;
      i = bracket.end;
    } else
      pattern += ch.replace(/[.+^${}()|\\\]]/g, "\\$&");
  }
  return pattern;
}
function extglobAt(token, start) {
  const operator = token[start];
  if (!"?*+@!".includes(operator) || token[start + 1] !== "(")
    return null;
  const alternatives = [];
  let current = "";
  let depth = 0;
  let i = start + 1;
  for (;i < token.length; i++) {
    const ch = token[i];
    if (ch === "(") {
      depth++;
      if (depth === 1)
        continue;
    } else if (ch === ")") {
      depth--;
      if (depth === 0) {
        alternatives.push(current);
        break;
      }
    } else if (ch === "|" && depth === 1) {
      alternatives.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (i >= token.length)
    return null;
  if (operator === "!")
    return { source: "[^/]*", end: i };
  const body = alternatives.map((alternative) => compileGlobPattern(alternative)).join("|");
  const quantifier = operator === "?" ? "?" : operator === "*" ? "*" : operator === "+" ? "+" : "";
  return { source: `(?:${body})${quantifier}`, end: i };
}
function bracketExpressionAt(token, start) {
  let i = start + 1;
  let negated = false;
  if (token[i] === "!" || token[i] === "^") {
    negated = true;
    i++;
  }
  let body = "";
  if (token[i] === "]") {
    body += "]";
    i++;
  }
  while (i < token.length && token[i] !== "]") {
    const inner = token[i] === "[" ? token[i + 1] : undefined;
    if (inner === ":" || inner === "." || inner === "=") {
      const close = token.indexOf(`${inner}]`, i + 2);
      if (close !== -1) {
        body += token.slice(i, close + 2);
        i = close + 2;
        continue;
      }
    }
    body += token[i];
    i++;
  }
  if (i >= token.length)
    return null;
  if (/\[[.=:]/.test(body))
    return { source: "[^/]", end: i };
  const escaped = body.replace(/[\\\]]/g, "\\$&");
  if (escaped.length === 0)
    return { source: "[^/]", end: i };
  return { source: `[${negated ? "^" : ""}${escaped}]`, end: i };
}
function globPrefixNamesState(token) {
  if (!GLOB_METACHAR_RE.test(token))
    return false;
  const pattern = "^" + compileGlobPattern(token);
  let re;
  try {
    re = new RegExp(pattern + "$");
  } catch {
    return false;
  }
  if (!STATE_GLOB_CANDIDATES.some((candidate) => re.test(candidate)))
    return false;
  return !GLOB_DECOYS.some((decoy) => re.test(decoy));
}
function substitutionBodies(command) {
  const bodies = [];
  for (let i = 0;i < command.length; i++) {
    if (command[i] === "`") {
      const close = command.indexOf("`", i + 1);
      if (close === -1)
        break;
      bodies.push(command.slice(i + 1, close));
      i = close;
      continue;
    }
    if (command[i] !== "$" || command[i + 1] !== "(")
      continue;
    let depth = 1;
    let j = i + 2;
    for (;j < command.length && depth > 0; j++) {
      if (command[j] === "(")
        depth++;
      else if (command[j] === ")")
        depth--;
    }
    if (depth === 0)
      bodies.push(command.slice(i + 2, j - 1));
    i = j - 1;
  }
  return bodies;
}
var REDIRECT_TARGET_RE = /\d*>{1,2}\|?\s*("[^"]*"|'[^']*'|[^\s;&|<>]+)/g;
function bareToken(token) {
  return token.replace(/^[(){}'"]+|[(){}'"]+$/g, "");
}
function unquotedToken(token) {
  return token.replace(/^['"]+|['"]+$/g, "");
}
function commandBasename(token) {
  const bare = bareToken(token);
  return bare.slice(bare.lastIndexOf("/") + 1);
}
function commandWords(simpleCommand) {
  const tokens = simpleCommand.trim().split(/\s+/).map(bareToken).filter(Boolean);
  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    if (/^\d*(?:>{1,2}\|?|<{1,3})/.test(token)) {
      i += /^\d*(?:>{1,2}\|?|<{1,3})$/.test(token) ? 2 : 1;
      continue;
    }
    const skippable = ENV_ASSIGNMENT_RE.test(token) || token.startsWith("-") || RUNNER_OPERAND_RE.test(token) || SHELL_KEYWORD_PREFIXES.has(token) || COMMAND_PREFIX_TOKENS.has(commandBasename(token));
    if (!skippable)
      break;
    i++;
  }
  return tokens.slice(i);
}
function simpleCommandDestroys(words, namesState) {
  if (words.length === 0)
    return false;
  const head = commandBasename(words[0]);
  const args = words.slice(1);
  if (head === "find") {
    if (args.some((a) => a === "-delete"))
      return true;
    if (args.some((a) => FIND_WRITE_ACTIONS.has(a)))
      return true;
    return args.some((a, i) => FIND_EXEC_ACTIONS.has(a) && !SAFE_EXEC_COMMANDS.has(commandBasename(args[i + 1] ?? "")));
  }
  if (head === "sed") {
    if (args.some((a) => a.startsWith("-i") || a.startsWith("--in-place")))
      return true;
    return args.some((a, i) => /(?:^|[;}/\s])w$/.test(a) && namesState(args[i + 1] ?? "")) || args.some((a) => /(?:^|[;}/\s])w\s*\S*\.failproofai/.test(a));
  }
  if (head === "awk" || head === "gawk" || head === "mawk") {
    return args.some((a) => /system\s*\(|\|\s*["']|\|&/.test(a));
  }
  if (COPY_COMMANDS.has(head)) {
    if (args.includes("--remove-source-files") && args.some((a) => namesState(a)))
      return true;
    const targetAt = args.findIndex((a) => a === "-t" || a === "--target-directory");
    if (targetAt !== -1 && namesState(args[targetAt + 1] ?? ""))
      return true;
    if (args.some((a) => a.startsWith("--target-directory=") && namesState(a)))
      return true;
    const operands = args.filter((a) => !a.startsWith("-"));
    const destination = operands[operands.length - 1];
    return destination !== undefined && namesState(destination);
  }
  if (OPERAND_WRITE_COMMANDS.has(head)) {
    return args.some((a) => !a.startsWith("-") && namesState(a));
  }
  if (SECOND_OPERAND_WRITERS.has(head)) {
    const operands = args.filter((a) => !a.startsWith("-"));
    return operands.length > 1 && namesState(operands[operands.length - 1]);
  }
  if (head === "git") {
    const subcommand = gitSubcommand(args);
    return subcommand !== undefined && GIT_DESTRUCTIVE_SUBCOMMANDS.has(subcommand);
  }
  if (writesViaOutputFlag(head, args, namesState))
    return true;
  if (STATE_READ_COMMANDS.has(head) || STATE_MENTION_COMMANDS.has(head))
    return false;
  return true;
}
function writesViaOutputFlag(head, args, namesState) {
  const flags = OUTPUT_FLAG_COMMANDS[head];
  if (!flags)
    return false;
  for (let i = 0;i < args.length; i++) {
    const arg = args[i];
    const long = flags.find((f) => f.startsWith("--") && arg.startsWith(`${f}=`));
    if (long && namesState(arg))
      return true;
    const bundled = /^-[A-Za-z]*[oD]$/.test(arg) && flags.includes(`-${arg[arg.length - 1]}`);
    if ((flags.includes(arg) || bundled) && namesState(args[i + 1] ?? ""))
      return true;
  }
  return false;
}
function destroysFailproofaiState(command, depth = 0) {
  if (depth === 0) {
    const bodies = substitutionBodies(command);
    for (let i = 0;i < bodies.length && i < 64; i++) {
      if (destroysFailproofaiState(bodies[i], 1))
        return true;
      bodies.push(...substitutionBodies(bodies[i]));
    }
  }
  const assignments = [
    ...command.matchAll(/(?:^|[\s;&|(])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|)]+)/g)
  ].map(([, name, value]) => [name, value.replace(/^["']|["']$/g, "")]);
  const stateVars = new Set;
  for (let pass = 0;pass < assignments.length + 1; pass++) {
    const before = stateVars.size;
    for (const [name, value] of assignments) {
      const holdsState = FAILPROOFAI_STATE_PATH_RE.test(value) || [...value.matchAll(VAR_REFERENCE_RE)].some(([, ref]) => stateVars.has(ref));
      if (holdsState)
        stateVars.add(name);
    }
    if (stateVars.size === before)
      break;
  }
  const namesState = (text) => {
    if (FAILPROOFAI_STATE_PATH_RE.test(text))
      return true;
    for (const [, name] of text.matchAll(VAR_REFERENCE_RE)) {
      if (stateVars.has(name))
        return true;
    }
    return text.split(/\s+/).some((token) => globCouldNameState(unquotedToken(token)));
  };
  let cwdInState = false;
  let parenDepth = 0;
  let cdParenDepth = null;
  let loopCarriesState = false;
  for (const pipeline of command.split(PIPELINE_SEPARATORS)) {
    if (!pipeline.trim())
      continue;
    const simpleCommands = pipeline.split("|");
    const reachesState = namesState(pipeline) || cwdInState || loopCarriesState;
    if (reachesState && LOOP_HEADER_RE.test(pipeline))
      loopCarriesState = true;
    if (/(?:^|\s)done(?:\s|$)/.test(pipeline))
      loopCarriesState = false;
    if (reachesState) {
      for (const [, target] of pipeline.matchAll(REDIRECT_TARGET_RE)) {
        if (namesState(target.replace(/^["']|["']$/g, "")))
          return true;
      }
    }
    for (const simple of simpleCommands) {
      parenDepth += (simple.match(/\(/g) ?? []).length;
      const words = commandWords(simple);
      const head = words.length > 0 ? commandBasename(words[0]) : "";
      if (head === "cd" || head === "pushd") {
        const operand = words.slice(1).find((w) => !w.startsWith("-"));
        cwdInState = operand !== undefined && namesState(operand);
        cdParenDepth = cwdInState ? parenDepth : null;
      } else if (head === "popd") {
        cwdInState = false;
        cdParenDepth = null;
      } else if (reachesState && words.length > 0 && simpleCommandDestroys(words, namesState)) {
        return true;
      }
      parenDepth -= (simple.match(/\)/g) ?? []).length;
      if (cdParenDepth !== null && parenDepth < cdParenDepth) {
        cwdInState = false;
        cdParenDepth = null;
      }
    }
  }
  return false;
}
var FAILPROOFAI_UNINSTALL_RE = /(?:npm\s+(?:uninstall|remove|un|r)\s.*failproofai|bun\s+remove\s.*failproofai|yarn\s+global\s+remove\s+failproofai|pnpm\s+(?:remove|uninstall|un)\s.*failproofai)/;
var GIT_AMEND_RE = /\bgit\s+commit\b.*--amend\b/;
var GIT_STASH_DROP_RE = /\bgit\s+stash\s+(?:drop|clear)\b/;
var GIT_CMD_RE = /^(?:\/\S*\/)?git$/;
var SHORT_FLAG_CLUSTER_RE = /^-[A-Za-z]+$/;
var GIT_CLEAN_FORCE_WAIVED_RE = /^clean\.requireforce=(?:false|0|no|off)$/i;
var GIT_CLEAN_DESTRUCTIVE_FLAGS = ["d", "x", "X"];
var GIT_ADD_ALL_RE = /\bgit\s+add\s+(?:-A\b|--all\b|\.(?:\s|$|;|&&|\|\|))/;
var NPM_GLOBAL_RE = /\bnpm\s+(?:install|i)\b(?=.*(?:\s-g\b|--global\b))/;
var YARN_GLOBAL_RE = /\byarn\s+global\s+add\b/;
var PNPM_GLOBAL_RE = /\bpnpm\s+(?:add|install|i)\b(?=.*(?:\s-g\b|--global\b))/;
var BUN_GLOBAL_RE = /\bbun\s+(?:install|add)\b(?=.*(?:\s-g\b|--global\b))/;
var CARGO_INSTALL_RE = /\bcargo\s+install\b/;
var PIP_SYSTEM_RE = /\bpip(?:3)?\s+install\b(?=.*(?:--user\b|--break-system-packages\b))/;
var PKG_MANAGER_DETECTORS = {
  pip: [/\bpip\b/, /\bpip3\b/, /\bpython3?\s+-m\s+pip\b/],
  npm: [/\bnpm\b/, /\bnpx\b/],
  yarn: [/\byarn\b/],
  pnpm: [/\bpnpm\b/, /\bpnpx\b/],
  bun: [/\bbun\b/, /\bbunx\b/],
  uv: [/\buv\b/],
  poetry: [/\bpoetry\b/],
  pipenv: [/\bpipenv\b/],
  conda: [/\bconda\b/],
  cargo: [/\bcargo\b/]
};
var NOHUP_RE = /\bnohup\s+\S/;
var SCREEN_DETACH_RE = /\bscreen\s+-[A-Za-z]*d[A-Za-z]*\b/;
var TMUX_DETACH_RE = /\btmux\s+(?:new-session|new)\b[^|&;]*-d\b/;
var DISOWN_RE = /\bdisown\b/;
var BACKGROUND_AMPERSAND_RE = /(?<![&|])\s?&\s*(?:$|#|;)/;
var KUBECTL_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*kubectl(?:\s|$)/;
var TERRAFORM_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*(?:terraform|tofu)(?:\s|$)/;
var AWS_CLI_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*aws(?:\s|$)/;
var GCLOUD_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*gcloud(?:\s|$)/;
var AZ_CLI_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*az(?:\s|$)/;
var HELM_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*helm(?:\s|$)/;
var GH_PIPELINE_RE = /(?:^|[;\n]|&&|\|\|?|&)\s*gh\s+(?:workflow\s+(?:run|enable|disable)|run\s+(?:rerun|cancel)|pr\s+merge|release\s+(?:create|delete)|cache\s+delete|secret\s+(?:set|delete))\b/;
var gitBranchCache = new Map;
var GIT_BRANCH_CACHE_MAX_ENTRIES = 500;
function statGitHeadMtimeMs(cwd) {
  try {
    return statSync2(join2(cwd, ".git", "HEAD")).mtimeMs;
  } catch {
    return null;
  }
}
function getCurrentBranch(cwd) {
  try {
    const headMtimeMs = statGitHeadMtimeMs(cwd);
    const cached = gitBranchCache.get(cwd);
    if (cached && headMtimeMs !== null && cached.headMtimeMs === headMtimeMs) {
      return cached.branch || null;
    }
    const branch = execSync("git rev-parse --abbrev-ref HEAD", {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 3000
    }).trim();
    if (headMtimeMs !== null) {
      if (gitBranchCache.size >= GIT_BRANCH_CACHE_MAX_ENTRIES)
        gitBranchCache.clear();
      gitBranchCache.set(cwd, { branch, headMtimeMs });
    }
    return branch || null;
  } catch {
    return null;
  }
}
function getHeadSha(cwd) {
  try {
    const sha = execSync("git rev-parse HEAD", {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 3000
    }).trim();
    return sha || null;
  } catch {
    return null;
  }
}
function getThirdPartyCheckRuns(cwd, sha) {
  try {
    const json = execFileSync("gh", [
      "api",
      `repos/{owner}/{repo}/commits/${sha}/check-runs`,
      "--jq",
      '.check_runs | map(select(.app.slug != "github-actions")) | map({name: .name, status: .status, conclusion: (.conclusion // "")})'
    ], {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 15000
    }).trim();
    if (!json || json === "[]")
      return [];
    return JSON.parse(json);
  } catch {
    return [];
  }
}
function getCommitStatuses(cwd, sha) {
  try {
    const json = execFileSync("gh", [
      "api",
      `repos/{owner}/{repo}/commits/${sha}/statuses`,
      "--jq",
      "map({name: .context, state: .state}) | unique_by(.name)"
    ], {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 15000
    }).trim();
    if (!json || json === "[]")
      return [];
    const statuses = JSON.parse(json);
    return statuses.map((s) => ({
      name: s.name,
      status: s.state === "pending" ? "in_progress" : "completed",
      conclusion: s.state === "pending" ? "" : s.state === "success" ? "success" : "failure"
    }));
  } catch {
    return [];
  }
}
function matchesAllowedPattern(cmd, pattern) {
  const cmdTokens = parseArgvTokens(cmd);
  const patTokens = parseArgvTokens(pattern);
  if (cmdTokens.length < patTokens.length)
    return false;
  if (cmdTokens.some((tok) => SHELL_OPERATORS.has(tok)))
    return false;
  if (cmdTokens.some((tok) => SHELL_METACHAR_RE.test(tok)))
    return false;
  return patTokens.every((tok, i) => tok === "*" || tok === cmdTokens[i]);
}
function sanitizeJwt(ctx) {
  const output = JSON.stringify(ctx.payload);
  if (JWT_RE.test(output)) {
    return {
      decision: "deny",
      reason: "JWT token detected in tool output",
      message: "[REDACTED: JWT token removed by failproofai]"
    };
  }
  return allow();
}
function sanitizeApiKeys(ctx) {
  const output = JSON.stringify(ctx.payload);
  for (const [pattern, label] of API_KEY_PATTERNS) {
    if (pattern.test(output)) {
      return {
        decision: "deny",
        reason: `${label} detected in tool output`,
        message: `[REDACTED: ${label} removed by failproofai]`
      };
    }
  }
  const additional = ctx.params?.additionalPatterns ?? [];
  for (const { regex, label } of additional) {
    try {
      if (new RegExp(regex).test(output)) {
        return {
          decision: "deny",
          reason: `${label} detected in tool output`,
          message: `[REDACTED: ${label} removed by failproofai]`
        };
      }
    } catch {
      hookLogWarn(`additionalPatterns: invalid regex "${regex}", skipping`);
    }
  }
  return allow();
}
function sanitizeConnectionStrings(ctx) {
  const output = JSON.stringify(ctx.payload);
  if (CONNECTION_STRING_RE.test(output)) {
    return {
      decision: "deny",
      reason: "Database connection string with credentials detected in tool output",
      message: "[REDACTED: connection string removed by failproofai]"
    };
  }
  return allow();
}
function sanitizePrivateKeyContent(ctx) {
  const output = JSON.stringify(ctx.payload);
  if (PRIVATE_KEY_RE.test(output)) {
    return {
      decision: "deny",
      reason: "Private key content detected in tool output",
      message: "[REDACTED: private key content removed by failproofai]"
    };
  }
  return allow();
}
function sanitizeBearerTokens(ctx) {
  const output = JSON.stringify(ctx.payload);
  if (BEARER_TOKEN_RE.test(output)) {
    return {
      decision: "deny",
      reason: "Bearer token detected in tool output",
      message: "[REDACTED: Bearer token removed by failproofai]"
    };
  }
  return allow();
}
function warnDestructiveSql(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  if (!SQL_TOOL_RE.test(cmd))
    return allow();
  if (DESTRUCTIVE_SQL_RE.test(cmd)) {
    return instruct("STOP: This command contains destructive SQL (DROP/TRUNCATE/DELETE). Confirm with the user before executing.");
  }
  if (DELETE_NO_WHERE_RE.test(cmd) && !SQL_WHERE_RE.test(cmd)) {
    return instruct("STOP: This command contains destructive SQL (DROP/TRUNCATE/DELETE). Confirm with the user before executing.");
  }
  return allow();
}
function warnLargeFileWrite(ctx) {
  if (ctx.toolName !== "Write")
    return allow();
  const content = ctx.toolInput?.content;
  if (typeof content !== "string")
    return allow();
  const thresholdKb = ctx.params?.thresholdKb ?? 1024;
  const thresholdBytes = thresholdKb * 1024;
  if (content.length > thresholdBytes) {
    return instruct(`STOP: You are writing a file larger than ${thresholdKb}KB (${Math.round(content.length / 1024)}KB). This is unusually large. Confirm this is intentional before proceeding.`);
  }
  return allow();
}
function warnPackagePublish(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  if (PUBLISH_CMD_RE.test(cmd)) {
    return instruct("STOP: This command publishes a package to a public registry. Confirm with the user that this is intentional.");
  }
  return allow();
}
function protectEnvVars(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  if (ENV_PRINTENV_RE.test(cmd)) {
    return deny("Command reads environment variables");
  }
  if (ECHO_ENV_RE.test(cmd)) {
    return deny("Command echoes environment variable");
  }
  if (EXPORT_RE.test(cmd)) {
    return deny("Command exports environment variable");
  }
  if (PS_ENV_VAR_RE.test(cmd)) {
    return deny("Command reads environment variable via PowerShell");
  }
  if (PS_CHILDITEM_ENV_RE.test(cmd)) {
    return deny("Command reads environment variables via PowerShell");
  }
  if (DOTNET_GETENV_RE.test(cmd)) {
    return deny("Command reads environment variable via .NET");
  }
  if (CMD_ECHO_ENV_RE.test(cmd)) {
    return deny("Command echoes environment variable via cmd");
  }
  return allow();
}
function blockEnvFiles(ctx) {
  const cmd = getCommand(ctx);
  const filePath = getFilePath(ctx);
  if (filePath && ENV_FILE_PATH_RE.test(filePath)) {
    return deny("Access to .env file blocked");
  }
  if (ctx.toolName === "Bash" && ENV_CMD_RE.test(cmd)) {
    return deny("Command references .env file");
  }
  return allow();
}
function quoteAwareSegments(command) {
  const segments = [];
  let tokens = [];
  let token = "";
  let quote = null;
  const endToken = () => {
    if (token)
      tokens.push(token);
    token = "";
  };
  const endSegment = () => {
    endToken();
    if (tokens.length)
      segments.push(tokens);
    tokens = [];
  };
  for (let i = 0;i < command.length; i++) {
    const c = command[i];
    if (quote) {
      if (c === "\\" && quote === '"' && i + 1 < command.length) {
        token += command[++i];
        continue;
      }
      if (c === quote) {
        quote = null;
        continue;
      }
      token += c;
      continue;
    }
    if (c === "\\" && i + 1 < command.length) {
      token += command[++i];
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    if (/\s/.test(c)) {
      endToken();
      continue;
    }
    if (/[;&|\n\r(){}`]/.test(c)) {
      endSegment();
      continue;
    }
    token += c;
  }
  endSegment();
  return segments;
}
var EVAL_FLAG_RE = /^-{1,2}c$/;
function namesElevation(command, depth = 0) {
  for (const tokens of quoteAwareSegments(command)) {
    let i = 0;
    while (i < tokens.length) {
      const token = tokens[i];
      const base = token.slice(token.lastIndexOf("/") + 1);
      if (base === "sudo" || base === "doas")
        return true;
      const isSkippable = ENV_ASSIGNMENT_RE.test(token) || token.startsWith("-") || token.startsWith(">") || token.startsWith("<") || RUNNER_OPERAND_RE.test(token) || COMMAND_PREFIX_TOKENS.has(base);
      if (!isSkippable)
        break;
      if (EVAL_FLAG_RE.test(token) && depth < 3 && i + 1 < tokens.length) {
        if (namesElevation(tokens[i + 1], depth + 1))
          return true;
      }
      i++;
    }
  }
  return false;
}
function blockSudo(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx).trimStart();
  if (namesElevation(cmd)) {
    const allowPatterns = ctx.params?.allowPatterns ?? [];
    if (allowPatterns.some((p) => matchesAllowedPattern(cmd, p)))
      return allow();
    return deny("sudo commands are blocked");
  }
  if (PS_ELEVATION_RE.test(cmd)) {
    return deny("Elevated process launch is blocked");
  }
  if (RUNAS_RE.test(cmd)) {
    return deny("runas elevation is blocked");
  }
  return allow();
}
function blockCurlPipeSh(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  if (CURL_PIPE_SH_RE.test(cmd)) {
    return deny("Piping downloads to shell is blocked");
  }
  if (PS_WEB_PIPE_RE.test(cmd)) {
    return deny("Piping downloads to Invoke-Expression is blocked");
  }
  return allow();
}
function extractGitPushArgs(cmd) {
  return cmd.split(/&&|\|\||[|;\n]/).map((s) => s.trim()).filter((s) => /^git\s+push\s/.test(s)).map((s) => s.replace(/^git\s+push\s+/, ""));
}
function blockPushMaster(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const protectedBranches = ctx.params?.protectedBranches ?? ["main", "master"];
  if (protectedBranches.length === 0)
    return allow();
  const args = extractGitPushArgs(getCommand(ctx));
  const branchPattern = new RegExp(`\\b(?:${protectedBranches.map((b) => b.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})\\b`);
  if (args.some((a) => branchPattern.test(a))) {
    return deny(`Pushing to ${protectedBranches.join("/")} is blocked`);
  }
  return allow();
}
var HOME_PREFIX_RE = /^(?:~[A-Za-z0-9_.-]*|\$HOME|\$\{HOME\})(?=$|\/)/;
var RM_CMD_RE = /^(?:\/\S*\/)?rm$/;
var FIND_CMD_RE = /^(?:\/\S*\/)?find$/;
var FIND_EXEC_RE = /^-(?:exec|execdir|ok|okdir)$/;
var FIND_GLOBAL_OPT_RE = /^-(?:[HLP]|D|O\d*)$/;
var FIND_EXPR_START_RE = /^(?:-|\\?[(!])/;
var SCRATCH_ROOTS = ["/tmp", "/var/tmp"];
var CATASTROPHIC_DEPTH = 2;
function expandHomePrefix(path) {
  const m = path.match(/^(?:~|\$HOME|\$\{HOME\})(?=$|\/)/);
  return m ? homedir2() + path.slice(m[0].length) : path;
}
function stripTrailingGlob(path) {
  return path.replace(/\/\*$/, "").replace(/\/+$/, "");
}
function isCatastrophicTarget(token) {
  const raw = token.replace(/^['"]|['"]$/g, "");
  if (raw === "")
    return false;
  const homePrefix = raw.match(HOME_PREFIX_RE);
  if (!homePrefix && /^[$`]/.test(raw))
    return true;
  const belowRoot = homePrefix ? raw.slice(homePrefix[0].length) : raw.startsWith("/") ? raw : null;
  if (belowRoot === null)
    return false;
  const segments = stripTrailingGlob(belowRoot).split("/").filter(Boolean);
  if (!homePrefix && SCRATCH_ROOTS.some((r) => `/${segments.join("/")}`.startsWith(`${r}/`)))
    return false;
  return segments.length <= CATASTROPHIC_DEPTH;
}
function recursiveDeletionTargets(seg) {
  const tokens = parseArgvTokens(seg);
  const findIdx = tokens.findIndex((t) => FIND_CMD_RE.test(t));
  if (findIdx >= 0) {
    const expr = tokens.slice(findIdx + 1);
    const execIdx = expr.findIndex((t) => FIND_EXEC_RE.test(t));
    const deletes = expr.includes("-delete") || execIdx >= 0 && RM_CMD_RE.test(expr[execIdx + 1] ?? "");
    if (deletes) {
      let start = 0;
      while (start < expr.length && FIND_GLOBAL_OPT_RE.test(expr[start])) {
        start += expr[start] === "-D" ? 2 : 1;
      }
      const rest = expr.slice(start);
      const end = rest.findIndex((t) => FIND_EXPR_START_RE.test(t));
      return end < 0 ? rest : rest.slice(0, end);
    }
  }
  const rmIdx = tokens.findIndex((t) => RM_CMD_RE.test(t));
  if (rmIdx >= 0) {
    const args = tokens.slice(rmIdx + 1);
    const shortFlags = args.filter((t) => /^-[^-]/.test(t)).join("");
    const longFlags = args.filter((t) => /^--/.test(t));
    const recursive = /r/i.test(shortFlags) || longFlags.some((f) => /^--recursive$/i.test(f));
    const force = /f/.test(shortFlags) || longFlags.some((f) => /^--force$/i.test(f));
    if (recursive && force)
      return args.filter((t) => !t.startsWith("-"));
  }
  return null;
}
function shellSegments(cmd) {
  return cmd.split(/&&|\|\||[|;\n]/).map((s) => s.trim()).filter((s) => s !== "");
}
function deletionTargetIsAllowed(cmd, allowPaths) {
  if (allowPaths.length === 0)
    return false;
  const normalizedAllowPaths = allowPaths.map((p) => stripTrailingGlob(expandHomePrefix(p)) || "/");
  let sawRecursiveDelete = false;
  for (const seg of shellSegments(cmd)) {
    const targets = recursiveDeletionTargets(seg);
    if (targets === null)
      continue;
    sawRecursiveDelete = true;
    for (const target of targets) {
      const normalized = stripTrailingGlob(expandHomePrefix(target)) || "/";
      const covered = normalizedAllowPaths.some((np) => normalized === np || normalized.startsWith(np + "/"));
      if (!covered) {
        const segCovered = allowPaths.some((p) => {
          const escaped = p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          return new RegExp(`${escaped}(?:[/"'\\s/*]|$)`).test(seg);
        });
        if (!segCovered)
          return false;
      }
    }
  }
  return sawRecursiveDelete;
}
function blockRmRf(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  const hasCatastrophicTarget = shellSegments(cmd).some((seg) => {
    const targets = recursiveDeletionTargets(seg);
    return targets !== null && targets.some(isCatastrophicTarget);
  });
  if (hasCatastrophicTarget) {
    const allowPaths = ctx.params?.allowPaths ?? [];
    if (deletionTargetIsAllowed(cmd, allowPaths))
      return allow();
    return deny("Catastrophic deletion blocked");
  }
  if (/Remove-Item\s+.*-Recurse.*-Force.*(?:[A-Z]:\\(?:\s|$)|\\\*)/i.test(cmd)) {
    return deny("Catastrophic deletion blocked");
  }
  if (/(?:rd|rmdir)\s+\/s\s+\/q\s+[A-Z]:\\/i.test(cmd)) {
    return deny("Catastrophic deletion blocked");
  }
  return allow();
}
function blockForcePush(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  for (const segment of extractGitPushArgs(getCommand(ctx))) {
    let sawEndOfOptions = false;
    for (const token of segment.split(/\s+/)) {
      if (token === "--") {
        sawEndOfOptions = true;
        continue;
      }
      if (sawEndOfOptions)
        continue;
      if (isForcePushFlag(token)) {
        return deny("Force-pushing is blocked");
      }
    }
  }
  return allow();
}
function isForcePushFlag(token) {
  if (token === "--force")
    return true;
  if (SAFE_FORCE_PREFIXES.some((prefix) => token.startsWith(prefix)))
    return false;
  if (token.startsWith("--force"))
    return true;
  return SHORT_FLAG_BUNDLE_RE.test(token);
}
function blockSecretsWrite(ctx) {
  if (ctx.toolName !== "Write")
    return allow();
  const filePath = getFilePath(ctx);
  if (SECRET_FILE_RE.test(filePath) || SECRET_FILE_ID_RSA_RE.test(filePath) || SECRET_FILE_CREDENTIALS_RE.test(filePath)) {
    return deny("Writing secret key files is blocked");
  }
  const additionalPatterns = ctx.params?.additionalPatterns ?? [];
  for (const pattern of additionalPatterns) {
    if (filePath.includes(pattern)) {
      return deny(`Writing blocked file pattern: ${pattern}`);
    }
  }
  return allow();
}
var READ_LIKE_CMDS = /(?:^|;|&&|\|\||\|)\s*(?:ls|find|cat|head|tail|less|more|wc|file|stat|tree|du)\s/;
function extractAbsolutePaths(command) {
  const paths = [];
  const pathRe = /(?<![a-zA-Z0-9_.\-~\\*?:=/])(?:~\/[^\s;|&"'()\[\]{}]*|~(?=\s|$|[;|&"'()\[\]{}])|\/[^\s;|&"'()\[\]{}]*)/g;
  function addPaths(s) {
    pathRe.lastIndex = 0;
    let m;
    while ((m = pathRe.exec(s)) !== null) {
      let p = m[0];
      if (/^\/{2,}$/.test(p))
        continue;
      if (p === "~")
        p = homedir2();
      else if (p.startsWith("~/"))
        p = join2(homedir2(), p.slice(2));
      paths.push(p);
    }
  }
  let firstBarePipe = command.length;
  let inDouble = false, inSingle = false;
  for (let i = 0;i < command.length; i++) {
    const c = command[i];
    if (c === '"' && !inSingle)
      inDouble = !inDouble;
    else if (c === "'" && !inDouble)
      inSingle = !inSingle;
    else if (c === "|" && !inDouble && !inSingle) {
      firstBarePipe = i;
      break;
    }
  }
  const firstSegment = command.slice(0, firstBarePipe);
  const quotedRe = /"([^"]*)"|'([^']*)'/g;
  let qm;
  while ((qm = quotedRe.exec(firstSegment)) !== null) {
    const content = qm[1] ?? qm[2] ?? "";
    if (/[*?\[\]^$+()\\]/.test(content))
      continue;
    addPaths(content);
  }
  const stripped = command.replace(/"[^"]*"/g, (m) => " ".repeat(m.length)).replace(/'[^']*'/g, (m) => " ".repeat(m.length));
  addPaths(stripped);
  return paths;
}
function blockReadOutsideCwd(ctx) {
  const cwd = process.env.CLAUDE_PROJECT_DIR || ctx.session?.cwd;
  if (!cwd)
    return allow();
  const allowPaths = ctx.params?.allowPaths ?? [];
  if (ctx.toolName === "Bash") {
    const cmd = getCommand(ctx);
    if (!READ_LIKE_CMDS.test(cmd))
      return allow();
    const paths = extractAbsolutePaths(cmd);
    const cwdWithSep2 = cwd.endsWith("/") ? cwd : cwd + "/";
    for (const p of paths) {
      const resolved3 = resolve2(cwd, p);
      if (isClaudeSettingsFile(resolved3)) {
        return deny(`Reading agent settings file blocked: ${resolved3}`);
      }
      if (isClaudeInternalPath(resolved3))
        continue;
      if (resolved3 === "/dev/null")
        continue;
      if (resolved3 !== cwd && !resolved3.startsWith(cwdWithSep2)) {
        if (allowPaths.some((ap) => resolved3 === ap || resolved3.startsWith(ap.endsWith("/") ? ap : ap + "/")))
          continue;
        return deny(`Bash read outside project directory blocked: ${resolved3}`);
      }
    }
    return allow();
  }
  const filePath = getFilePath(ctx);
  const searchPath = ctx.toolInput?.path ?? "";
  const target = filePath || searchPath;
  if (!target)
    return allow();
  const resolved2 = resolve2(cwd, target);
  if (isClaudeSettingsFile(resolved2)) {
    return deny(`Reading agent settings file blocked: ${resolved2}`);
  }
  if (isClaudeInternalPath(resolved2))
    return allow();
  if (resolved2 === "/dev/null")
    return allow();
  const cwdWithSep = cwd.endsWith("/") ? cwd : cwd + "/";
  if (resolved2 !== cwd && !resolved2.startsWith(cwdWithSep)) {
    if (allowPaths.some((ap) => resolved2 === ap || resolved2.startsWith(ap.endsWith("/") ? ap : ap + "/")))
      return allow();
    return deny(`Access outside project directory blocked: ${resolved2}`);
  }
  return allow();
}
function blockWorkOnMain(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  const match = cmd.match(GIT_COMMIT_MERGE_RE);
  if (!match)
    return allow();
  const cwd = ctx.session?.cwd;
  if (!cwd)
    return allow();
  const branch = getCurrentBranch(cwd);
  if (!branch)
    return allow();
  const protectedBranches = ctx.params?.protectedBranches ?? ["main", "master"];
  if (protectedBranches.includes(branch)) {
    return deny(`Git ${match[1]} on ${branch} is blocked. Create a feature branch first.`);
  }
  return allow();
}
function blockFailproofaiCommands(ctx) {
  if (ctx.toolName === "Write" || ctx.toolName === "Edit" || ctx.toolName === "NotebookEdit") {
    const path = getFilePath(ctx) || (ctx.toolInput?.notebook_path ?? "");
    if (FAILPROOFAI_STATE_PATH_RE.test(path)) {
      return deny("Writing to failproofai's own state would switch enforcement off. " + "If a policy is blocking legitimate work, say so and let the operator decide.");
    }
    return allow();
  }
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  const unescaped = stripShellQuoting(cmd);
  const kind = classifySelfInvocation(cmd) ?? classifySelfInvocation(unescaped);
  if (kind === "pause") {
    return deny("Pausing failproofai enforcement is a human action, not an agent one. " + "If a policy is blocking legitimate work, say so and let the operator decide.");
  }
  if (kind === "cli") {
    return deny("Running failproofai CLI commands is blocked");
  }
  if (FAILPROOFAI_UNINSTALL_RE.test(cmd) || FAILPROOFAI_UNINSTALL_RE.test(unescaped)) {
    return deny("Uninstalling failproofai is blocked");
  }
  if (destroysFailproofaiState(cmd) || destroysFailproofaiState(unescaped)) {
    return deny("Deleting, moving or overwriting failproofai's own state would switch enforcement off. " + "If a policy is blocking legitimate work, say so and let the operator decide.");
  }
  return allow();
}
function blockInfraCli(ctx, re, denyMsg) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  if (!re.test(cmd))
    return allow();
  const allowPatterns = ctx.params?.allowPatterns ?? [];
  if (allowPatterns.some((p) => matchesAllowedPattern(cmd, p)))
    return allow();
  return deny(denyMsg);
}
function blockKubectl(ctx) {
  return blockInfraCli(ctx, KUBECTL_RE, "kubectl commands are blocked");
}
function blockTerraform(ctx) {
  return blockInfraCli(ctx, TERRAFORM_RE, "terraform/tofu commands are blocked");
}
function blockAwsCli(ctx) {
  return blockInfraCli(ctx, AWS_CLI_RE, "aws CLI commands are blocked");
}
function blockGcloud(ctx) {
  return blockInfraCli(ctx, GCLOUD_RE, "gcloud commands are blocked");
}
function blockAzCli(ctx) {
  return blockInfraCli(ctx, AZ_CLI_RE, "az (Azure) CLI commands are blocked");
}
function blockHelm(ctx) {
  return blockInfraCli(ctx, HELM_RE, "helm commands are blocked");
}
function blockGhPipeline(ctx) {
  return blockInfraCli(ctx, GH_PIPELINE_RE, "gh pipeline-trigger commands are blocked");
}
var TOOL_CALL_TRACKER_MAX_BYTES = 65536;
async function warnRepeatedToolCalls(ctx) {
  const THRESHOLD = 3;
  const transcriptPath = ctx.session?.transcriptPath;
  if (!transcriptPath || !ctx.toolName || !ctx.toolInput)
    return allow();
  const trackerPath = `${transcriptPath}.tool-calls.json`;
  const fingerprint = JSON.stringify({ tool: ctx.toolName, input: ctx.toolInput });
  let counts = {};
  try {
    const raw = await readFile(trackerPath, "utf8");
    counts = JSON.parse(raw);
  } catch {}
  const prevCount = counts[fingerprint] ?? 0;
  if (prevCount >= THRESHOLD) {
    return instruct(`STOP: You have already called ${ctx.toolName} ${prevCount} times with identical parameters. This is wasteful and unproductive. Do NOT repeat this call — use a different approach or ask the user for clarification.`);
  }
  counts[fingerprint] = prevCount + 1;
  try {
    const serialized = JSON.stringify(counts);
    if (serialized.length <= TOOL_CALL_TRACKER_MAX_BYTES) {
      await writeFile(trackerPath, serialized, "utf8");
    }
  } catch {}
  return allow();
}
function warnGitAmend(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  if (GIT_AMEND_RE.test(cmd)) {
    return instruct("STOP: This command amends the last commit, which rewrites git history. If this commit has already been pushed to a shared branch, this will cause divergence for other contributors. Confirm with the user before executing.");
  }
  return allow();
}
function warnGitStashDrop(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  if (GIT_STASH_DROP_RE.test(cmd)) {
    return instruct("STOP: This command permanently deletes stashed changes (git stash drop/clear). Stash entries cannot be recovered after deletion. Confirm with the user before executing.");
  }
  return allow();
}
function readGitCleanFlags(args) {
  const letters = new Set;
  let force = false;
  let dryRun = false;
  let sawEndOfOptions = false;
  for (const token of args) {
    if (token === "--") {
      sawEndOfOptions = true;
      continue;
    }
    if (sawEndOfOptions)
      continue;
    if (token === "--force") {
      force = true;
      continue;
    }
    if (token === "--dry-run") {
      dryRun = true;
      continue;
    }
    if (token.startsWith("--"))
      continue;
    if (!SHORT_FLAG_CLUSTER_RE.test(token))
      continue;
    for (const letter of token.slice(1)) {
      if (letter === "f")
        force = true;
      if (letter === "n")
        dryRun = true;
      letters.add(letter);
    }
  }
  if (force)
    letters.add("f");
  return { force, dryRun, letters };
}
function gitCleanForceWaived(globalOptions) {
  for (let i = 0;i < globalOptions.length; i++) {
    const token = globalOptions[i];
    const value = token === "-c" ? globalOptions[i + 1] : token.startsWith("-c") ? token.slice(2) : undefined;
    if (value !== undefined && GIT_CLEAN_FORCE_WAIVED_RE.test(value))
      return true;
  }
  return false;
}
function warnGitClean(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const destructiveFlags = ctx.params?.destructiveFlags ?? GIT_CLEAN_DESTRUCTIVE_FLAGS;
  if (destructiveFlags.length === 0)
    return allow();
  for (const segment of shellSegments(getCommand(ctx))) {
    const tokens = parseArgvTokens(segment);
    const gitIdx = tokens.findIndex((t) => GIT_CMD_RE.test(t));
    if (gitIdx < 0)
      continue;
    const args = tokens.slice(gitIdx + 1);
    const subIdx = gitSubcommandIndex(args);
    if (subIdx < 0 || args[subIdx] !== "clean")
      continue;
    const flags = readGitCleanFlags(args.slice(subIdx + 1));
    if (flags.dryRun)
      continue;
    if (!flags.force && !gitCleanForceWaived(args.slice(0, subIdx)))
      continue;
    if (!destructiveFlags.some((f) => flags.letters.has(f)))
      continue;
    return instruct("STOP: This command deletes untracked files from the working tree (git clean). Git has no copy of " + "untracked or ignored files, so nothing it removes can be recovered: -d takes whole untracked " + "directories, and -x / -X also take .gitignore'd files such as .env, local config and scratch work. " + "Re-run it with --dry-run and confirm the exact paths with the user before executing.");
  }
  return allow();
}
function warnAllFilesStaged(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  if (GIT_ADD_ALL_RE.test(cmd)) {
    return instruct("STOP: This command stages all files in the working tree (git add -A / --all / .). This may inadvertently include build artifacts, generated files, or sensitive files not covered by .gitignore. Confirm with the user before executing.");
  }
  return allow();
}
function warnSchemaAlteration(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  if (!SQL_TOOL_RE.test(cmd))
    return allow();
  if (SCHEMA_ALTER_RE.test(cmd)) {
    return instruct("STOP: This command contains a schema-altering SQL statement (ALTER TABLE with column or rename operation). Schema changes on production databases are irreversible or disruptive. Confirm with the user before executing.");
  }
  return allow();
}
function warnGlobalPackageInstall(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  const isGlobal = NPM_GLOBAL_RE.test(cmd) || YARN_GLOBAL_RE.test(cmd) || PNPM_GLOBAL_RE.test(cmd) || BUN_GLOBAL_RE.test(cmd) || CARGO_INSTALL_RE.test(cmd) || PIP_SYSTEM_RE.test(cmd);
  if (isGlobal) {
    return instruct("STOP: This command installs a package globally, which modifies the system-wide environment outside the project. This can conflict with other projects or system tools. Confirm with the user before executing.");
  }
  return allow();
}
var SEGMENT_SPLIT_RE = /\s*(?:&&|\|\||\||;)\s*/;
function preferPackageManager(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  if (!cmd)
    return allow();
  const allowed = ctx.params?.allowed ?? [];
  if (allowed.length === 0)
    return allow();
  const allowedSet = new Set(allowed.map((a) => a.toLowerCase()));
  const blocked = ctx.params?.blocked ?? [];
  const allowedList = allowed.join(", ");
  const segments = cmd.split(SEGMENT_SPLIT_RE);
  for (const segment of segments) {
    const trimmed = segment.trim();
    if (!trimmed)
      continue;
    let segmentAllowed = false;
    for (const manager of allowedSet) {
      const patterns = PKG_MANAGER_DETECTORS[manager];
      if (!patterns)
        continue;
      for (const pattern of patterns) {
        if (pattern.test(trimmed)) {
          segmentAllowed = true;
          break;
        }
      }
      if (segmentAllowed)
        break;
    }
    if (segmentAllowed)
      continue;
    for (const [manager, patterns] of Object.entries(PKG_MANAGER_DETECTORS)) {
      if (allowedSet.has(manager))
        continue;
      for (const pattern of patterns) {
        if (pattern.test(trimmed)) {
          return deny(`"${manager}" is not an allowed package manager. ` + `Allowed package managers for this project: ${allowedList}. ` + `Rewrite this command using an allowed package manager.`);
        }
      }
    }
    for (const name of blocked) {
      const lower = name.toLowerCase();
      if (allowedSet.has(lower))
        continue;
      const re = new RegExp(`\\b${lower.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);
      if (re.test(trimmed)) {
        return deny(`"${lower}" is not an allowed package manager. ` + `Allowed package managers for this project: ${allowedList}. ` + `Rewrite this command using an allowed package manager.`);
      }
    }
  }
  return allow();
}
function warnBackgroundProcess(ctx) {
  if (ctx.toolName !== "Bash")
    return allow();
  const cmd = getCommand(ctx);
  const isBackground = NOHUP_RE.test(cmd) || SCREEN_DETACH_RE.test(cmd) || TMUX_DETACH_RE.test(cmd) || DISOWN_RE.test(cmd) || BACKGROUND_AMPERSAND_RE.test(cmd);
  if (isBackground) {
    return instruct("STOP: This command starts a background or detached process (nohup, screen -d, tmux -d, or trailing &). Background processes persist after Claude's session and may be difficult to track or stop. Confirm with the user before executing.");
  }
  return allow();
}
function isPlanMode(ctx) {
  return ctx.session?.permissionMode === "plan";
}
function requireCommitBeforeStop(ctx) {
  if (isPlanMode(ctx))
    return allow("Plan mode — no changes made, skipping commit check.");
  const cwd = ctx.session?.cwd;
  if (!cwd)
    return allow("No working directory available, skipping commit check.");
  try {
    const status = execSync("git status --porcelain", {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 5000
    }).trim();
    if (status.length > 0) {
      return deny("You have uncommitted changes in the working directory. Commit all changes now.");
    }
    return allow("All changes are committed.");
  } catch {
    return allow("Not a git repository, skipping commit check.");
  }
}
function requirePushBeforeStop(ctx) {
  if (isPlanMode(ctx))
    return allow("Plan mode — no changes made, skipping push check.");
  const cwd = ctx.session?.cwd;
  if (!cwd)
    return allow("No working directory available, skipping push check.");
  try {
    const remotes = execSync("git remote", {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 3000
    }).trim();
    if (!remotes)
      return allow("No git remote configured, skipping push check.");
    const remote = ctx.params?.remote ?? "origin";
    const branch = getCurrentBranch(cwd);
    if (!branch || branch === "HEAD")
      return allow("Detached HEAD, skipping push check.");
    const baseBranch = ctx.params?.baseBranch ?? "main";
    if (branch === baseBranch) {
      return allow(`On base branch "${baseBranch}", skipping push check.`);
    }
    try {
      const ahead = execFileSync("git", ["log", `${remote}/${baseBranch}..HEAD`, "--oneline"], { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 5000 }).trim();
      if (!ahead) {
        return allow(`No commits ahead of ${remote}/${baseBranch}, skipping push check.`);
      }
      const diff = execFileSync("git", ["diff", "--stat", `${remote}/${baseBranch}`, "HEAD"], { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 5000 }).trim();
      if (!diff) {
        return allow(`No file changes compared to ${remote}/${baseBranch}, skipping push check.`);
      }
    } catch {}
    let hasTracking = false;
    try {
      execFileSync("git", ["rev-parse", "--verify", `${remote}/${branch}`], {
        cwd,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
        timeout: 3000
      });
      hasTracking = true;
    } catch {}
    if (!hasTracking) {
      return deny(`Branch "${branch}" has not been pushed to remote "${remote}". ` + `Run now: git push -u ${remote} ${branch}`);
    }
    const unpushed = execFileSync("git", ["log", `${remote}/${branch}..HEAD`, "--oneline"], {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 5000
    }).trim();
    if (unpushed.length > 0) {
      const commitCount = unpushed.split(`
`).length;
      return deny(`You have ${commitCount} unpushed commit${commitCount > 1 ? "s" : ""} on branch "${branch}". ` + `Run now: git push`);
    }
    return allow(`All commits pushed to "${remote}".`);
  } catch {
    return allow("Could not check push status, skipping.");
  }
}
function requirePrBeforeStop(ctx) {
  if (isPlanMode(ctx))
    return allow("Plan mode — no changes made, skipping PR check.");
  const cwd = ctx.session?.cwd;
  if (!cwd)
    return allow("No working directory available, skipping PR check.");
  try {
    try {
      execSync("gh --version", { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 3000 });
    } catch {
      return allow("GitHub CLI (gh) not installed, skipping PR check.");
    }
    const branch = getCurrentBranch(cwd);
    if (!branch || branch === "HEAD")
      return allow("Detached HEAD, skipping PR check.");
    const baseBranch = ctx.params?.baseBranch ?? "main";
    if (branch === baseBranch) {
      return allow(`On base branch "${baseBranch}", skipping PR check.`);
    }
    try {
      const ahead = execFileSync("git", ["log", `origin/${baseBranch}..HEAD`, "--oneline"], { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 5000 }).trim();
      if (!ahead) {
        return allow(`No commits ahead of origin/${baseBranch}, skipping PR check.`);
      }
      const diff = execFileSync("git", ["diff", "--stat", `origin/${baseBranch}`, "HEAD"], { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 5000 }).trim();
      if (!diff) {
        return allow(`No file changes compared to origin/${baseBranch}, skipping PR check.`);
      }
    } catch {}
    let prJson;
    try {
      prJson = execSync("gh pr view --json number,url,state", {
        cwd,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
        timeout: 15000
      }).trim();
    } catch {
      return deny(`No pull request found for branch "${branch}". ` + `Run now: gh pr create`);
    }
    const pr = JSON.parse(prJson);
    if (pr.state === "OPEN") {
      return allow(`PR #${pr.number} exists: ${pr.url}`);
    }
    if (pr.state === "MERGED") {
      return allow(`PR #${pr.number} was merged: ${pr.url}. ` + `Switch off this branch (e.g. 'git checkout ${baseBranch} && git pull') before stopping again.`);
    }
    return deny(`Pull request for branch "${branch}" is ${pr.state.toLowerCase()}. Run now: gh pr create`);
  } catch {
    return allow("Could not check PR status, skipping.");
  }
}
function requireNoConflictsBeforeStop(ctx) {
  if (isPlanMode(ctx))
    return allow("Plan mode — no changes made, skipping conflict check.");
  const cwd = ctx.session?.cwd;
  if (!cwd)
    return allow("No working directory available, skipping conflict check.");
  const branch = getCurrentBranch(cwd);
  if (!branch || branch === "HEAD")
    return allow("Detached HEAD, skipping conflict check.");
  const baseBranch = ctx.params?.baseBranch ?? "main";
  if (branch === baseBranch) {
    return allow(`On base branch "${baseBranch}", skipping conflict check.`);
  }
  try {
    execSync("gh --version", { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 3000 });
  } catch {
    return allow("gh CLI not installed, skipping conflict check.");
  }
  let prJson;
  try {
    prJson = execSync("gh pr view --json mergeable,number,url,state", {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 15000
    }).trim();
  } catch {
    return allow("No pull request found for branch, skipping conflict check.");
  }
  let pr;
  try {
    pr = JSON.parse(prJson);
  } catch {
    return allow("Could not parse gh pr view output, skipping conflict check.");
  }
  if (pr.state !== "OPEN") {
    return allow(`PR #${pr.number} is ${pr.state.toLowerCase()}; skipping conflict check.`);
  }
  try {
    execFileSync("git", ["rev-parse", "--verify", `origin/${baseBranch}`], {
      cwd,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 3000
    });
    const ahead = execFileSync("git", ["log", `origin/${baseBranch}..HEAD`, "--oneline"], { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 5000 }).trim();
    if (ahead) {
      execFileSync("git", ["merge-tree", "--write-tree", "--name-only", `origin/${baseBranch}`, "HEAD"], { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 1e4 });
    }
  } catch (err) {
    const e = err;
    if (e.status === 1) {
      const out = (typeof e.stdout === "string" ? e.stdout : e.stdout?.toString("utf8") ?? "").trim();
      const lines = out.split(`
`);
      const files = [];
      for (let i = 1;i < lines.length; i++) {
        const line = lines[i];
        if (line === "")
          break;
        files.push(line);
      }
      const fileList = files.length ? files.join(", ") : "one or more files";
      return deny(`Branch "${branch}" has merge conflicts with ${baseBranch} in: ${fileList}. ` + `Rebase or merge origin/${baseBranch} now and resolve the conflicts.`);
    }
  }
  if (pr.mergeable === "CONFLICTING") {
    return deny(`PR #${pr.number} has merge conflicts per GitHub (${pr.url}). ` + `Rebase or merge origin/${baseBranch} now and resolve the conflicts.`);
  }
  if (pr.mergeable === "UNKNOWN") {
    return deny(`GitHub is still computing mergeability for PR #${pr.number} (${pr.url}). ` + `Wait ~10 seconds, then re-check with \`gh pr view --json mergeable\` before attempting to stop again.`);
  }
  return allow(`PR #${pr.number} merges cleanly per GitHub.`);
}
function requireCiGreenBeforeStop(ctx) {
  if (isPlanMode(ctx))
    return allow("Plan mode — no changes made, skipping CI check.");
  const cwd = ctx.session?.cwd;
  if (!cwd)
    return allow("No working directory available, skipping CI check.");
  try {
    try {
      execSync("gh --version", { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 3000 });
    } catch {
      return allow("GitHub CLI (gh) not installed, skipping CI check.");
    }
    const branch = getCurrentBranch(cwd);
    if (!branch || branch === "HEAD")
      return allow("Detached HEAD, skipping CI check.");
    const sha = getHeadSha(cwd);
    let workflowRuns = [];
    try {
      const runsJson = execFileSync("gh", ["run", "list", "--branch", branch, "--limit", "20", "--json", "status,conclusion,name,headSha"], { cwd, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 15000 }).trim();
      if (runsJson && runsJson !== "[]") {
        const allWorkflowRuns = JSON.parse(runsJson);
        const headRuns = sha ? allWorkflowRuns.filter((r) => r.headSha === sha) : allWorkflowRuns;
        const seen = new Set;
        workflowRuns = headRuns.filter((r) => {
          if (seen.has(r.name))
            return false;
          seen.add(r.name);
          return true;
        });
      }
    } catch {}
    let thirdPartyChecks = [];
    let commitStatuses = [];
    if (sha) {
      thirdPartyChecks = getThirdPartyCheckRuns(cwd, sha);
      commitStatuses = getCommitStatuses(cwd, sha);
    }
    const allChecks = [...workflowRuns, ...thirdPartyChecks, ...commitStatuses];
    if (allChecks.length === 0)
      return allow(`No CI runs found for branch "${branch}".`);
    const failing = allChecks.filter((r) => r.status === "completed" && r.conclusion !== "success" && r.conclusion !== "skipped" && r.conclusion !== "cancelled" && r.conclusion !== "neutral");
    if (failing.length > 0) {
      const names = failing.map((r) => `"${r.name}"`).join(", ");
      return deny(`CI checks are failing on branch "${branch}": ${names}. Fix the failing checks now.`);
    }
    const pending = allChecks.filter((r) => r.status === "in_progress" || r.status === "queued" || r.status === "waiting");
    if (pending.length > 0) {
      const names = pending.map((r) => `"${r.name}"`).join(", ");
      return deny(`CI checks are still running on branch "${branch}": ${names}. Wait for all checks to complete, then verify they pass.`);
    }
    return allow(`All CI checks passed on branch "${branch}".`);
  } catch {
    return allow("Could not check CI status, skipping.");
  }
}
var POLICY_IMPLEMENTATIONS = {
  "sanitize-jwt": sanitizeJwt,
  "sanitize-api-keys": sanitizeApiKeys,
  "sanitize-connection-strings": sanitizeConnectionStrings,
  "sanitize-private-key-content": sanitizePrivateKeyContent,
  "sanitize-bearer-tokens": sanitizeBearerTokens,
  "protect-env-vars": protectEnvVars,
  "block-env-files": blockEnvFiles,
  "block-read-outside-cwd": blockReadOutsideCwd,
  "block-sudo": blockSudo,
  "block-curl-pipe-sh": blockCurlPipeSh,
  "block-rm-rf": blockRmRf,
  "block-failproofai-commands": blockFailproofaiCommands,
  "block-kubectl": blockKubectl,
  "block-terraform": blockTerraform,
  "block-aws-cli": blockAwsCli,
  "block-gcloud": blockGcloud,
  "block-az-cli": blockAzCli,
  "block-helm": blockHelm,
  "block-gh-pipeline": blockGhPipeline,
  "block-secrets-write": blockSecretsWrite,
  "block-push-master": blockPushMaster,
  "block-force-push": blockForcePush,
  "block-work-on-main": blockWorkOnMain,
  "warn-git-amend": warnGitAmend,
  "warn-git-stash-drop": warnGitStashDrop,
  "warn-git-clean": warnGitClean,
  "warn-all-files-staged": warnAllFilesStaged,
  "warn-destructive-sql": warnDestructiveSql,
  "warn-schema-alteration": warnSchemaAlteration,
  "warn-package-publish": warnPackagePublish,
  "warn-global-package-install": warnGlobalPackageInstall,
  "prefer-package-manager": preferPackageManager,
  "warn-large-file-write": warnLargeFileWrite,
  "warn-background-process": warnBackgroundProcess,
  "warn-repeated-tool-calls": warnRepeatedToolCalls,
  "require-commit-before-stop": requireCommitBeforeStop,
  "require-push-before-stop": requirePushBeforeStop,
  "require-pr-before-stop": requirePrBeforeStop,
  "require-no-conflicts-before-stop": requireNoConflictsBeforeStop,
  "require-ci-green-before-stop": requireCiGreenBeforeStop
};
function assertCatalogBijection() {
  const implNames = new Set(Object.keys(POLICY_IMPLEMENTATIONS));
  const missing = POLICY_CATALOG.filter((e) => !implNames.has(e.name)).map((e) => e.name);
  if (missing.length > 0) {
    throw new Error(`failproofai: builtin policies missing an implementation: ${missing.join(", ")}`);
  }
  const catalogNames = new Set(POLICY_CATALOG.map((e) => e.name));
  const orphaned = [...implNames].filter((n) => !catalogNames.has(n));
  if (orphaned.length > 0) {
    throw new Error(`failproofai: policy implementations with no catalog entry: ${orphaned.join(", ")}`);
  }
}
assertCatalogBijection();
var BUILTIN_POLICIES = POLICY_CATALOG.map((entry) => ({
  ...entry,
  fn: POLICY_IMPLEMENTATIONS[entry.name]
}));

// ../../../../tmp/claude-1000/corepack/.entry.generated.ts
for (const policy of BUILTIN_POLICIES) {
  if (policy.alwaysOn)
    continue;
  customPolicies.add({
    name: policy.name,
    description: policy.description,
    category: policy.category,
    defaultEnabled: policy.defaultEnabled === true,
    match: policy.match,
    fn: policy.fn,
    ...policy.authority !== undefined ? { authority: policy.authority } : {},
    ...policy.reviewedBy !== undefined ? { reviewedBy: policy.reviewedBy } : {}
  });
}
