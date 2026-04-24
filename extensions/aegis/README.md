# Aegis Governance Extension for OpenClaw

> Runtime governance for OpenClaw tool execution — policy-as-code, audit trail, and approval workflows powered by the Aegis policy engine.

---

## Overview

The Aegis extension integrates the [Aegis](../../) runtime governance layer into OpenClaw as a thin **governance passthrough**. It intercepts every tool call via the `before_tool_call` hook, delegates the policy decision to the Aegis daemon, and passes the result back to the execution pipeline.

**Key capabilities:**

- **Policy-as-code** — Write OPA/Rego policies that control which tool calls are allowed, denied, or require human approval.
- **Audit trail** — Every tool invocation is recorded as a structured JSONL event across four lifecycle phases (requested → decided → started → completed).
- **Approval workflows** — Policies can require human approval before a tool executes, with configurable timeout and severity.

**The thin passthrough model:**

1. **OpenClaw** gathers context (tool name, arguments, session info) and sends it to the extension.
2. **Aegis** evaluates OPA/Rego policy and returns a decision (`allow`, `deny`, or `ask`) plus an opaque cookie.
3. **MXC** (the sandbox runtime) redeems the cookie and enforces the `ExecutionEnvelope` (filesystem ACLs, network rules, timeouts).

The extension itself never enforces decisions — it is a bridge between the OpenClaw plugin system and the Aegis daemon.

---

## Architecture

### Subprocess Proxy Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  OpenClaw Gateway (Node.js)                                     │
│                                                                 │
│   Agent requests tool call                                      │
│       │                                                         │
│       ▼                                                         │
│   before_tool_call hook ──► Aegis Extension                     │
│                               │                                 │
│                               │  Spawn: aegis decide --openclaw │
│                               │  (stdin: ActionPayload JSON)    │
│                               ▼                                 │
│                         ┌───────────────┐                       │
│                         │  aegis binary  │                      │
│                         │  (subprocess)  │                      │
│                         └───────┬───────┘                       │
│                                 │                               │
└─────────────────────────────────┼───────────────────────────────┘
                                  │ Named pipe / IPC
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  Aegis Daemon (.NET)                                            │
│                                                                 │
│   ┌────────────────────┐    ┌─────────────────────────────┐     │
│   │  Policy Engine      │    │  Cookie Store               │     │
│   │  • OPA/Rego eval    │    │  • Store envelope → cookie  │     │
│   │  • Decision:        │    │  • Redeem cookie → envelope │     │
│   │    allow/deny/ask   │    │  • 5-min TTL, one-time use  │     │
│   └────────┬───────────┘    └──────────────┬──────────────┘     │
│            │                               │                     │
│            └───── Decision + Cookie ───────┘                     │
│                        │                                         │
└────────────────────────┼─────────────────────────────────────────┘
                         │
                         ▼  (returned to extension via subprocess stdout)
┌─────────────────────────────────────────────────────────────────┐
│  Back in OpenClaw Gateway                                       │
│                                                                 │
│   Aegis Extension returns hook result:                          │
│     • allow  → { block: false, executionMetadata: { cookie } }  │
│     • deny   → { block: true, blockReason: "..." }              │
│     • ask    → { requireApproval: { ... }, executionMetadata }   │
│                                                                 │
│   Tool executes (or is blocked / awaits approval)               │
│       │                                                         │
│       ▼                                                         │
│   after_tool_call hook ──► Aegis Extension                      │
│       │                     (emits audit completion event)       │
│       ▼                                                         │
│   MXC Sandbox (if present)                                      │
│     • Redeems cookie from Aegis daemon                          │
│     • Receives ExecutionEnvelope                                │
│     • Enforces: FS ACLs, network rules, timeout, sandbox        │
└─────────────────────────────────────────────────────────────────┘
```

### Decision Paths

| Decision | Hook Result | What Happens |
|----------|-------------|--------------|
| **allow** | `block: false` + `executionMetadata` (contains cookie) | Tool executes. MXC redeems cookie and applies the execution envelope. |
| **deny** | `block: true` + `blockReason` | Tool is blocked. The agent sees the denial reason. No cookie is issued. |
| **ask** | `requireApproval` + `executionMetadata` | OpenClaw prompts the human for approval. On approve, tool executes with the pre-issued cookie. On deny/timeout, tool is blocked. |

### Audit Event Lifecycle

Every tool call emits up to four structured JSONL events:

1. **`aegis.action.requested`** — Tool call intercepted, before policy evaluation.
2. **`aegis.action.decided`** — Policy decision returned (allow/deny/ask + reason).
3. **`aegis.action.started`** — Tool execution began (after approval if required).
4. **`aegis.action.completed`** — Tool execution finished (success/failure + duration).

Events are written to `.aegis/openclaw-events.jsonl` (configurable via `auditLogPath`).

---

## Installation

Install via the OpenClaw plugin CLI:

```bash
openclaw plugins install @org/openclaw-aegis
```

Or, in the monorepo, it is already included as a workspace package:

```jsonc
// openclaw.config.json
{
  "extensions": ["./extensions/aegis"]
}
```

---

## Prerequisites

| Dependency | Required | Notes |
|------------|----------|-------|
| **Aegis binary** on `PATH` | Yes | Or configure via `aegisBinaryPath`. The extension spawns `aegis decide --openclaw` as a subprocess. |
| **OPA binary** on `PATH` | Yes | Used by the Aegis daemon for Rego policy evaluation. |
| **MXC sandbox runtime** | No | Optional — the extension works without it for basic allow/deny decisions. Required for `ExecutionEnvelope` enforcement (FS ACLs, network rules, sandboxing). |

---

## Configuration Reference

All fields are optional. Defaults are applied when values are not provided.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable or disable the Aegis extension. When `false`, all hooks are skipped. |
| `aegisBinaryPath` | `string` | `"aegis"` | Path to the `aegis` binary. Use an absolute path if not on `PATH`. |
| `policyPath` | `string` | _(none)_ | Override the default `.aegis/policy.rego` path for policy files. |
| `auditLogPath` | `string` | `".aegis/openclaw-events.jsonl"` | Path for the JSONL audit log output file. |
| `approvalTimeoutMs` | `integer` | `1800000` (30 min) | How long to wait for human approval before timing out. |
| `approvalTimeoutBehavior` | `"allow"` \| `"deny"` | `"deny"` | What to do when an approval request times out. |
| `approvalSeverity` | `"info"` \| `"warning"` \| `"critical"` | `"warning"` | Default severity level shown in the approval prompt. |
| `healthCheckIntervalMs` | `integer` | `30000` (30 s) | Interval between daemon health-check pings. |
| `redactPatterns` | `string[]` | `[]` | List of regex patterns. Matching argument values are replaced with `[REDACTED]` in audit logs and approval descriptions. |

### Example configuration

```jsonc
{
  "aegis": {
    "enabled": true,
    "aegisBinaryPath": "/usr/local/bin/aegis",
    "policyPath": ".aegis/policy.rego",
    "auditLogPath": ".aegis/openclaw-events.jsonl",
    "approvalTimeoutMs": 300000,
    "approvalTimeoutBehavior": "deny",
    "approvalSeverity": "warning",
    "redactPatterns": ["password", "secret", "token"]
  }
}
```

---

## Policy Authoring Quickstart

### 1. Create a policy file

```bash
mkdir -p .aegis
touch .aegis/policy.rego
```

### 2. Write a minimal policy

```rego
package aegis

# Default deny — all tool calls require an explicit allow rule
default result = {
    "decision": "deny",
    "reason": "no matching allow rule"
}

# Allow read-only file operations
result = {"decision": "allow", "reason": "read-only file operation"} {
    input.action.name == "read_file"
}
```

### 3. Test it

```bash
# Evaluate the policy against a sample input
aegis policy test --input '{"action":{"name":"read_file","args":{}}}'
```

### 4. Explore example policies

See the [`policies/`](./policies/) directory for ready-to-use examples:

| File | Strategy |
|------|----------|
| [`default.rego`](./policies/default.rego) | Deny by default — only explicitly allowed tools can run. |
| [`permissive.rego`](./policies/permissive.rego) | Allow by default — only known-dangerous operations are blocked. |
| [`strict.rego`](./policies/strict.rego) | Require human approval for every tool call (except reads). |

---

## How It Works

### Allow Path

1. Agent requests a tool call (e.g., `read_file`).
2. OpenClaw fires the `before_tool_call` hook.
3. The Aegis extension spawns `aegis decide --openclaw` and writes the `ActionPayload` to stdin.
4. The Aegis daemon evaluates the Rego policy and returns `{ "action": "allow", "executionMetadata": { "cookie": "..." } }`.
5. The extension returns `{ block: false, executionMetadata }` to the hook pipeline.
6. The tool executes. If MXC is present, it redeems the cookie and applies the execution envelope.
7. `after_tool_call` fires — the extension emits an `aegis.action.completed` audit event.

### Deny Path

1. Agent requests a tool call (e.g., `bash` with `rm -rf /`).
2. The Aegis daemon evaluates the policy and returns `{ "action": "deny", "reason": "destructive command blocked" }`.
3. The extension returns `{ block: true, blockReason: "destructive command blocked" }`.
4. The tool is **not** executed. The agent sees the block reason.
5. Audit events are still emitted (requested + decided).

### Ask / Approval Path

1. Agent requests a tool call (e.g., `web_fetch`).
2. The Aegis daemon evaluates the policy and returns `{ "action": "require_approval", "reason": "network access requires approval" }`.
3. The extension returns a `requireApproval` hook result with the configured severity, timeout, and description.
4. OpenClaw shows an approval prompt to the human operator.
5. **If approved:** the tool executes with the pre-issued cookie. MXC enforces the envelope.
6. **If denied or timed out:** the tool is blocked. The `approvalTimeoutBehavior` config controls what happens on timeout (`"deny"` by default).
7. Audit events record the full lifecycle including the approval resolution.

### Cookie Lifecycle

- On an `allow` or `ask` decision, the Aegis daemon stores an `ExecutionEnvelope` under an opaque cookie (UUID).
- The cookie is passed through `executionMetadata` in the hook result.
- Cookies have a **5-minute TTL** and are **one-time use** — once redeemed by MXC, the cookie is invalidated.
- If the tool is denied or the approval times out, the cookie is never redeemed and expires naturally.

---

## Troubleshooting

### "Aegis daemon unreachable — fail-closed"

The extension could not reach the Aegis daemon. All tool calls will be **denied** (fail-closed behavior).

**Check:**
- Is the `aegis` binary on your `PATH`? Try running `aegis --version`.
- If using a custom path, verify `aegisBinaryPath` in your config.
- Is the Aegis daemon running? The extension attempts to start it automatically, but check `aegis --daemon` status.

### "All tool calls are being blocked"

**Check:**
- Your Rego policy may have `default result = { "decision": "deny" }` without any allow rules.
- Review your `.aegis/policy.rego` and add allow rules for the tools you want to permit.
- Try the [`permissive.rego`](./policies/permissive.rego) example to unblock most operations.

### "Approval timeout — tool was denied"

The human operator did not respond to the approval prompt before the timeout expired.

**Adjust:**
- Increase `approvalTimeoutMs` (default: 30 minutes / 1,800,000 ms).
- Change `approvalTimeoutBehavior` to `"allow"` if you want timed-out approvals to proceed (use with caution).

### "Extension error — fail-closed"

An unexpected error occurred in the extension itself. This triggers fail-closed behavior.

**Check:**
- Look for errors in the OpenClaw gateway logs.
- Verify the `aegis` binary is compatible with the installed extension version.
- Check that `auditLogPath` is writable.

### Audit log not being written

**Check:**
- Verify the `auditLogPath` directory exists and is writable.
- Default path is `.aegis/openclaw-events.jsonl` relative to the working directory.
- Check for `[aegis] Failed to write audit event` warnings in console output.
