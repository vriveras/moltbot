# MXC Sandbox Execution Extension for OpenClaw

> OS-level sandboxed tool execution via MXC — enforces Aegis policy constraints with AppContainer (Windows) and LXC (Linux).

---

## Overview

The MXC extension completes the Aegis governance pipeline by **enforcing** policy decisions at the operating system level. When Aegis approves a tool call and returns an `ExecutionEnvelope` describing sandbox constraints (filesystem ACLs, network rules, timeouts), this extension translates those constraints into an MXC `SandboxPolicy` and spawns the tool inside an isolated container.

**Without MXC:** Aegis says "no network" → the tool runs on the host with full network access anyway.
**With MXC:** Aegis says "no network" → the tool runs in an AppContainer that literally cannot reach the network.

### Key Capabilities

- **Sandbox backend** — Registers as `"mxc"` via OpenClaw's `registerSandboxBackend()` API, alongside Docker and SSH.
- **Signed ticket verification** — ECDSA P-256 signature verification ensures agents cannot fabricate or tamper with sandbox policies.
- **Fail-closed** — Missing binary, invalid ticket, or no metadata → tool call blocked. Never runs unsandboxed by accident.
- **Graceful degradation** — If the platform is unsupported or MXC isn't installed, the extension goes dormant. No errors for existing users.

---

## Architecture

### End-to-End Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│  OpenClaw Gateway                                                    │
│                                                                      │
│  1. Agent requests tool call                                         │
│       │                                                              │
│       ▼                                                              │
│  2. Aegis extension (before_tool_call hook)                          │
│       │  Evaluates OPA/Rego policy                                   │
│       │  Returns: allow + executionMetadata { aegisSignedTicket }     │
│       │                                                              │
│       ▼                                                              │
│  3. OpenClaw routes to sandbox backend (config: backend=mxc)         │
│       │                                                              │
│       ▼                                                              │
│  4. MXC backend — buildExecSpec()                                    │
│       │  ┌─────────────────────────────────────────────────┐         │
│       │  │ a. Verify signed ticket (ECDSA P-256)           │         │
│       │  │ b. Extract ExecutionEnvelope from ticket         │         │
│       │  │ c. Translate envelope → SandboxPolicy            │         │
│       │  │ d. createConfigFromPolicy() → ContainerConfig    │         │
│       │  │ e. Serialize to base64                           │         │
│       │  │ f. Return argv: [wxc-exec, --config-base64, …]  │         │
│       │  └─────────────────────────────────────────────────┘         │
│       │                                                              │
│       ▼                                                              │
│  5. OpenClaw spawns: wxc-exec --config-base64 <base64>               │
│       │                                                              │
│       ▼                                                              │
│  ┌────────────────────────────────────────┐                          │
│  │  AppContainer / LXC Sandbox            │                          │
│  │                                        │                          │
│  │  • Network: blocked or allowed         │                          │
│  │  • Filesystem: ACLs enforced           │                          │
│  │  • Timeout: enforced                   │                          │
│  │  • Tool command executes here          │                          │
│  │                                        │                          │
│  └────────────────┬───────────────────────┘                          │
│                   │                                                  │
│                   ▼                                                  │
│  6. Return { stdout, stderr, exitCode } → agent                     │
└──────────────────────────────────────────────────────────────────────┘
```

### Envelope → SandboxPolicy Mapping

| Aegis ExecutionEnvelope | MXC SandboxPolicy | Transform |
|---|---|---|
| `timeoutSeconds` | `timeoutMs` | × 1000 |
| `networkEnabled` | `network.allowOutbound` | direct |
| `allowLocalNetwork` | `network.allowLocalNetwork` | direct |
| `deniedPaths[]` | `filesystem.deniedPaths[]` | copy |
| `readonlyPaths[]` | `filesystem.readonlyPaths[]` | copy |
| `readwritePaths[]` | `filesystem.readwritePaths[]` | copy |

---

## Configuration

Add to your OpenClaw config:

```yaml
extensions:
  mxc:
    enabled: true
    # mxcBinaryPath: "C:\\path\\to\\wxc-exec.exe"  # optional override
    # aegisPublicKeyPath: "C:\\keys\\aegis.pem"     # optional override
    # defaultContainment: "process"                  # process | wslc | microvm
    # debug: false                                   # enable wxc-exec debug output

agents:
  defaults:
    sandbox:
      backend: mxc     # <-- activates MXC as the sandbox backend
```

### Config Reference

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Enable/disable the extension |
| `mxcBinaryPath` | string | auto-discover | Path to `wxc-exec.exe` (Windows) or `lxc-exec` (Linux) |
| `aegisPublicKeyPath` | string | auto-discover | Path to Aegis ECDSA public key PEM |
| `defaultContainment` | string | `"process"` | Containment type: `process` (AppContainer/LXC), `wslc`, or `microvm` |
| `debug` | boolean | `false` | Pass `--debug` flag to wxc-exec |

---

## Module Structure

```
extensions/mxc/
├── index.ts                     Entry point (definePluginEntry)
├── openclaw.plugin.json         Manifest with config schema
├── package.json                 Dependencies (@microsoft/mxc-sdk)
├── tsconfig.json                TypeScript config
├── src/
│   ├── plugin.ts                Plugin registration — guards + registerSandboxBackend
│   ├── mxc-backend.ts           SandboxBackendHandle — buildExecSpec, runShellCommand
│   ├── envelope-translator.ts   ExecutionEnvelope → SandboxPolicy (pure function)
│   ├── ticket-bridge.ts         ECDSA ticket verification (fail-closed)
│   ├── binary-resolver.ts       Find wxc-exec / lxc-exec
│   ├── config.ts                Config type + resolveConfig()
│   └── types.ts                 Shared types (AegisExecutionEnvelope, MxcExecutionContext)
└── test/
    ├── envelope-translator.test.ts   6 tests — field mapping + edge cases
    ├── ticket-bridge.test.ts         5 tests — signed ticket, fallback, fail-closed
    ├── mxc-backend.test.ts           7 tests — buildExecSpec, manager, debug flag
    ├── config.test.ts                4 tests — defaults, overrides, validation
    └── binary-resolver.test.ts       3 tests — override, missing, discovery
```

---

## How It Works

### 1. Plugin Registration (`plugin.ts`)

On startup, the extension runs three guard checks:

1. **`config.enabled`** — Is the extension enabled? (default: yes)
2. **`getPlatformSupport()`** — Does the OS support MXC? (Windows ≥ 26100 or Linux with LXC)
3. **`resolveMxcBinaryPath()`** — Is `wxc-exec` / `lxc-exec` available?

If any check fails, the extension logs a warning and returns — it becomes dormant. No errors, no side effects.

If all pass, it calls `registerSandboxBackend("mxc", { factory, manager })`.

### 2. Building Exec Specs (`mxc-backend.ts`)

When OpenClaw routes a tool call to the MXC backend, `buildExecSpec()` is called with:
```typescript
{ command: "npm test", workdir: "/workspace", env: {...}, usePty: false, executionMetadata: {...} }
```

The method:
1. **Extracts** the signed ticket or raw envelope from `executionMetadata`
2. **Verifies** the ECDSA signature (if signed ticket)
3. **Translates** the envelope to an MXC `SandboxPolicy`
4. **Creates** a `ContainerConfig` via `createConfigFromPolicy()`
5. **Serializes** to base64 and returns `{ argv: [wxcExec, "--config-base64", base64], env, stdinMode }`

OpenClaw then spawns this argv using its existing process supervisor.

### 3. Ticket Verification (`ticket-bridge.ts`)

The extension supports two metadata paths:

| Key | Source | Security |
|---|---|---|
| `aegisSignedTicket` | Aegis daemon (ECDSA-signed) | Tamper-proof — verified via `verifyTicket()` |
| `aegisEnvelope` | Direct/development | Trust-on-first-use — no signature check |

Priority: signed ticket > raw envelope > error (fail-closed).

If only `aegisCookie` is present (opaque cookie, no envelope), the extension throws with a clear message — cookie redemption is a P1 feature.

### 4. Envelope Translation (`envelope-translator.ts`)

A pure function with no side effects. Maps Aegis fields to MXC fields with defensive copies of arrays. The output is a `SandboxPolicy` that `createConfigFromPolicy()` from the MXC SDK turns into a full `ContainerConfig`.

---

## Error Handling

| Scenario | Behavior | Phase |
|---|---|---|
| Platform unsupported | Skip registration, log warning | Startup |
| MXC binary missing | Skip registration, log warning | Startup |
| `config.enabled = false` | Skip registration, silent | Startup |
| No `executionMetadata` | Throw `TicketVerificationError` | Runtime (tool blocked) |
| Bad ECDSA signature | Throw `TicketVerificationError` | Runtime (tool blocked) |
| Expired ticket | Throw `TicketVerificationError` | Runtime (tool blocked) |
| Only `aegisCookie` (no envelope) | Throw with redemption message | Runtime (tool blocked) |
| `wxc-exec` crashes | Error bubbles to OpenClaw pipeline | Runtime (tool fails) |

**Principle:** Startup errors → graceful dormancy. Runtime errors → fail-closed (tool blocked).

---

## Prerequisites

1. **MXC binary** — Build the MXC Rust workspace or ensure `wxc-exec.exe` (Windows) / `lxc-exec` (Linux) is on PATH.
2. **Aegis extension** — Must be enabled and configured so tool calls include `executionMetadata`.
3. **Platform** — Windows ≥ build 26100 (for AppContainer) or Linux with LXC support.

### Quick Start

```bash
# 1. Build MXC (if not already)
cd mxc-aegis/src && cargo build --release

# 2. Ensure wxc-exec is on PATH
export PATH="$PATH:$(pwd)/target/release"

# 3. Configure OpenClaw
# In your openclaw config, set:
#   extensions.mxc.enabled = true
#   agents.defaults.sandbox.backend = "mxc"

# 4. Run OpenClaw — tool calls with Aegis approval now execute in MXC sandboxes
node openclaw.mjs
```

---

## Relationship to Other Extensions

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Aegis      │────▶│   MXC       │────▶│  wxc-exec   │
│  (policy)    │     │  (backend)  │     │  (sandbox)  │
│              │     │             │     │             │
│  Decides:    │     │  Translates │     │  Enforces:  │
│  allow/deny  │     │  envelope → │     │  AppContainer│
│  + envelope  │     │  container  │     │  or LXC     │
└─────────────┘     └─────────────┘     └─────────────┘
     Hook               Backend              Binary
 (before_tool_call)  (registerSandbox)    (OS-level)
```

- **Aegis** and **MXC** are fully decoupled — they communicate only through `executionMetadata`.
- **Aegis** is not required if you provide `aegisEnvelope` directly (development mode).
- **MXC** is not required if you only need policy decisions without enforcement.
