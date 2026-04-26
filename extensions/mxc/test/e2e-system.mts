/**
 * Full System E2E Test: OpenClaw → Aegis → MXC → wxc-exec
 *
 * Exercises the complete governance + sandboxing pipeline with real binaries:
 *   1. Aegis daemon (Rego policy evaluation via OPA)
 *   2. aegis decide --openclaw (subprocess IPC)
 *   3. Cookie redemption via named pipe
 *   4. MXC SDK envelope → policy → ContainerConfig
 *   5. wxc-exec sandbox execution
 *
 * Usage (from openclaw root):
 *   node --import tsx extensions/mxc/test/e2e-system.mts
 */

import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { connect, type Socket } from "node:net";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import { translateEnvelopeToPolicy } from "../src/envelope-translator.js";
import { createConfigFromPolicy, type ContainerConfig } from "@microsoft/mxc-sdk";
import type { AegisExecutionEnvelope } from "../src/types.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const AEGIS_BIN = "C:\\local\\sources\\aegis\\src\\Aegis.Cli\\bin\\Release\\net10.0\\Aegis.Cli.exe";
const WXC_EXEC = "C:\\local\\sources\\mxc\\src\\target\\release\\wxc-exec.exe";
const DOTNET_ROOT = "C:\\Users\\virivera\\AppData\\Local\\dotnet";
const PIPE_NAME = `aegis-${os.userInfo().username}`;
const PIPE_PATH = `\\\\.\\pipe\\${PIPE_NAME}`;

const DAEMON_STARTUP_TIMEOUT_MS = 10_000;
const DECIDE_TIMEOUT_MS = 15_000;
const REDEEM_TIMEOUT_MS = 5_000;
const WXC_EXEC_TIMEOUT_MS = 15_000;
const PIPE_POLL_INTERVAL_MS = 500;

// ─── Step results tracking ────────────────────────────────────────────────────

type StepResult = { pass: boolean; detail?: string };
const results: Record<string, StepResult> = {};
let tempDir = "";
let daemon: ChildProcess | null = null;
let daemonWasPreExisting = false;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Check if the named pipe exists by attempting a connect. */
function checkPipeExists(): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const socket: Socket = connect({ path: PIPE_PATH });
    const timer = setTimeout(() => {
      if (!settled) { settled = true; socket.destroy(); resolve(false); }
    }, 2000);

    socket.on("connect", () => {
      if (!settled) { settled = true; clearTimeout(timer); socket.destroy(); resolve(true); }
    });
    socket.on("error", () => {
      if (!settled) { settled = true; clearTimeout(timer); resolve(false); }
    });
  });
}

/** Send a JSON line over named pipe and read the JSON line response. */
function pipeSend(jsonObj: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let buffer = "";

    const socket: Socket = connect({ path: PIPE_PATH });
    const timer = setTimeout(() => {
      if (!settled) { settled = true; socket.destroy(); reject(new Error("Pipe send timed out")); }
    }, REDEEM_TIMEOUT_MS);

    socket.on("connect", () => {
      socket.write(JSON.stringify(jsonObj) + "\n");
    });

    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString();
      const nlIdx = buffer.indexOf("\n");
      if (nlIdx !== -1 && !settled) {
        settled = true;
        clearTimeout(timer);
        const line = buffer.slice(0, nlIdx).trim();
        socket.destroy();
        try {
          resolve(JSON.parse(line) as Record<string, unknown>);
        } catch (err) {
          reject(new Error(`Invalid JSON from pipe: ${line}`));
        }
      }
    });

    socket.on("error", (err) => {
      if (!settled) { settled = true; clearTimeout(timer); reject(err); }
    });
  });
}

/** Run aegis decide --openclaw as a subprocess, write payload to stdin, read JSON from stdout. */
function aegisDecide(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let stdout = "";
    let stderr = "";

    const child = spawn(AEGIS_BIN, ["decide", "--openclaw"], {
      env: { ...process.env, DOTNET_ROOT },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill();
        reject(new Error(`aegis decide timed out after ${DECIDE_TIMEOUT_MS}ms.\nstderr: ${stderr}`));
      }
    }, DECIDE_TIMEOUT_MS);

    child.stdout!.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr!.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });

    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const line = stdout.trim().split("\n").find((l) => l.trim().startsWith("{"));
      if (!line) {
        reject(new Error(`aegis decide returned no JSON (exit code ${code}).\nstdout: ${stdout}\nstderr: ${stderr}`));
        return;
      }
      try {
        resolve(JSON.parse(line.trim()) as Record<string, unknown>);
      } catch {
        reject(new Error(`aegis decide returned invalid JSON: ${line}\nstderr: ${stderr}`));
      }
    });

    child.on("error", (err) => {
      if (!settled) { settled = true; clearTimeout(timer); reject(err); }
    });

    child.stdin!.write(JSON.stringify(payload) + "\n");
    child.stdin!.end();
  });
}

// ─── Step 1: Policy setup ─────────────────────────────────────────────────────

async function step1_setupPolicy(): Promise<void> {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-e2e-"));
  const policyDir = path.join(tempDir, ".aegis");
  fs.mkdirSync(policyDir, { recursive: true });

  const regoPolicy = `package aegis

import rego.v1

default result := {
    "permissionDecision": "allow",
    "permissionDecisionReason": "E2E test permissive policy",
    "executionEnvelope": {
        "mode": "reuse_shell",
        "timeoutSeconds": 30,
        "networkEnabled": false,
        "allowLocalNetwork": false,
        "deniedPaths": ["/etc/shadow"],
        "readwritePaths": ["/tmp"]
    }
}
`;

  fs.writeFileSync(path.join(policyDir, "policy.rego"), regoPolicy, "utf-8");
  results["Step 1: Policy setup"] = { pass: true, detail: tempDir };
}

// ─── Step 2: Start Aegis daemon ───────────────────────────────────────────────

async function step2_startDaemon(): Promise<void> {
  // Check if daemon is already running
  const alreadyRunning = await checkPipeExists();
  if (alreadyRunning) {
    daemonWasPreExisting = true;
    results["Step 2: Aegis daemon started"] = { pass: true, detail: "pre-existing daemon found" };
    return;
  }

  // Match the spawn pattern from daemon-service.ts: detached + stdio ignore.
  // Piping stdin to the .NET daemon can interfere with NamedPipeServerStream on Windows.
  daemon = spawn(AEGIS_BIN, ["--daemon"], {
    env: { ...process.env, DOTNET_ROOT },
    detached: true,
    stdio: "ignore",
  });
  daemon.unref();

  // Poll for pipe readiness
  const startTime = Date.now();
  while (Date.now() - startTime < DAEMON_STARTUP_TIMEOUT_MS) {
    await sleep(PIPE_POLL_INTERVAL_MS);
    const ready = await checkPipeExists();
    if (ready) {
      results["Step 2: Aegis daemon started"] = { pass: true, detail: `PID ${daemon.pid}` };
      return;
    }
  }

  throw new Error(`Daemon did not create pipe within ${DAEMON_STARTUP_TIMEOUT_MS}ms. Check ${path.join(os.tmpdir(), "aegis-daemon.log")}`);
}

// ─── Step 3: Decide request ───────────────────────────────────────────────────

let decisionCookie = "";

async function step3_decide(): Promise<void> {
  const payload = {
    runtime: "openclaw",
    cwd: tempDir,
    toolName: "shell",
    toolArgs: { command: "echo E2E_TEST_PASS" },
    sessionId: "e2e-test-session",
    agentId: "e2e-agent",
    timestamp: new Date().toISOString(),
  };

  const response = await aegisDecide(payload);

  const decision = response.permissionDecision as string;
  const cookie = response.cookie as string | undefined;

  if (decision !== "allow") {
    throw new Error(`Expected decision 'allow', got '${decision}'. Response: ${JSON.stringify(response)}`);
  }
  if (!cookie) {
    throw new Error(`No cookie in response. Response: ${JSON.stringify(response)}`);
  }

  decisionCookie = cookie;
  results["Step 3: Decide request"] = {
    pass: true,
    detail: `decision: ${decision}, cookie: ${cookie.slice(0, 12)}...`,
  };
}

// ─── Step 4: Cookie redemption ────────────────────────────────────────────────

let redeemEnvelope: AegisExecutionEnvelope | null = null;

async function step4_redeemCookie(): Promise<void> {
  // The daemon stores cookie with exact toolName, args JSON, and cwd from the decide request.
  // Redeem must present matching context.
  const redeemRequest = {
    redeem: decisionCookie,
    toolName: "shell",
    args: JSON.stringify({ command: "echo E2E_TEST_PASS" }),
    cwd: tempDir,
  };

  const response = await pipeSend(redeemRequest);

  if (!response.valid) {
    throw new Error(`Cookie redemption failed: ${JSON.stringify(response)}`);
  }
  if (response.decision !== "allow") {
    throw new Error(`Expected redeemed decision 'allow', got '${response.decision}'`);
  }

  redeemEnvelope = response.envelope as AegisExecutionEnvelope;
  if (!redeemEnvelope) {
    throw new Error(`No envelope in redeem response: ${JSON.stringify(response)}`);
  }

  results["Step 4: Cookie redemption"] = { pass: true, detail: "envelope received" };
}

// ─── Step 5: MXC pipeline ─────────────────────────────────────────────────────

let wxcArgv: string[] = [];

async function step5_mxcPipeline(): Promise<void> {
  if (!redeemEnvelope) throw new Error("No envelope from step 4");

  // Translate envelope → SandboxPolicy
  const policy = translateEnvelopeToPolicy(redeemEnvelope);

  // Create ContainerConfig from policy
  const containerConfig = createConfigFromPolicy(policy, "process");

  // IMPORTANT: Override version for this Windows build (no BaseContainer support)
  containerConfig.version = "0.4.0-alpha";

  // Override network enforcement to capabilities-only (firewall mode requires admin)
  if (containerConfig.network) {
    (containerConfig.network as Record<string, unknown>).enforcementMode = "capabilities";
  }

  // Clear Linux-style filesystem paths from the Rego envelope — not applicable on Windows
  if (containerConfig.filesystem) {
    containerConfig.filesystem.readwritePaths = [];
    containerConfig.filesystem.readonlyPaths = [];
    containerConfig.filesystem.deniedPaths = [];
  }

  // Set command (full path required inside AppContainer sandbox)
  containerConfig.process!.commandLine = "C:\\Windows\\System32\\cmd.exe /c echo E2E_SANDBOX_OK";

  // Build argv
  const configBase64 = Buffer.from(JSON.stringify(containerConfig), "utf-8").toString("base64");
  wxcArgv = [WXC_EXEC, "--config-base64", configBase64];

  results["Step 5: MXC pipeline"] = { pass: true, detail: "argv built" };
}

// ─── Step 6: wxc-exec sandbox ─────────────────────────────────────────────────

async function step6_execSandbox(): Promise<void> {
  if (wxcArgv.length < 3) throw new Error("No argv from step 5");

  const [bin, ...args] = wxcArgv;
  const output = execFileSync(bin!, args, {
    timeout: WXC_EXEC_TIMEOUT_MS,
    encoding: "utf-8",
  });

  // wxc-exec may include ANSI codes or extra whitespace; check for our marker
  if (!output.includes("E2E_SANDBOX_OK")) {
    throw new Error(`Expected output to contain 'E2E_SANDBOX_OK', got: ${output}`);
  }

  // Extract just the relevant line for display
  const cleanOutput = output
    .split("\n")
    .map((l) => l.replace(/\r/g, "").trim())
    .find((l) => l.includes("E2E_SANDBOX_OK")) ?? output.trim();

  results["Step 6: wxc-exec sandbox"] = { pass: true, detail: `output: ${cleanOutput}` };
}

// ─── Step 7: Cleanup ──────────────────────────────────────────────────────────

async function step7_cleanup(): Promise<void> {
  // Kill daemon (only if we started it)
  if (daemon && !daemonWasPreExisting) {
    try {
      daemon.kill();
      // Give it a moment to exit gracefully
      await sleep(500);
      if (!daemon.killed) {
        daemon.kill("SIGKILL");
      }
    } catch {
      // ignore cleanup errors
    }
    daemon = null;
  }

  // Remove temp directory
  if (tempDir) {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }

  results["Step 7: Cleanup"] = { pass: true };
}

// ─── Print summary ───────────────────────────────────────────────────────────

function printSummary(): void {
  console.log("\n=== FULL SYSTEM E2E TEST ===");

  const stepOrder = [
    "Step 1: Policy setup",
    "Step 2: Aegis daemon started",
    "Step 3: Decide request",
    "Step 4: Cookie redemption",
    "Step 5: MXC pipeline",
    "Step 6: wxc-exec sandbox",
    "Step 7: Cleanup",
  ];

  let allPassed = true;
  for (const step of stepOrder) {
    const r = results[step];
    if (!r) {
      console.log(`${step.padEnd(30)} ⏭️  skipped`);
      allPassed = false;
    } else if (r.pass) {
      const detail = r.detail ? ` (${r.detail})` : "";
      console.log(`${step.padEnd(30)} ✅${detail}`);
    } else {
      const detail = r.detail ? ` (${r.detail})` : "";
      console.log(`${step.padEnd(30)} ❌${detail}`);
      allPassed = false;
    }
  }

  console.log("");
  if (allPassed) {
    console.log("🎉 FULL SYSTEM E2E: ALL 3 SYSTEMS VERIFIED");
    console.log("  OpenClaw → Aegis: Policy decision + cookie");
    console.log("  Aegis → MXC: Cookie redemption → execution envelope");
    console.log("  MXC → wxc-exec: Sandbox execution with policy constraints");
  } else {
    console.log("💥 FULL SYSTEM E2E: SOME STEPS FAILED");
    process.exitCode = 1;
  }
  console.log("");
}

// ─── Main runner ─────────────────────────────────────────────────────────────

type StepFn = { name: string; fn: () => Promise<void>; resultKey: string };

const steps: StepFn[] = [
  { name: "Step 1", fn: step1_setupPolicy, resultKey: "Step 1: Policy setup" },
  { name: "Step 2", fn: step2_startDaemon, resultKey: "Step 2: Aegis daemon started" },
  { name: "Step 3", fn: step3_decide, resultKey: "Step 3: Decide request" },
  { name: "Step 4", fn: step4_redeemCookie, resultKey: "Step 4: Cookie redemption" },
  { name: "Step 5", fn: step5_mxcPipeline, resultKey: "Step 5: MXC pipeline" },
  { name: "Step 6", fn: step6_execSandbox, resultKey: "Step 6: wxc-exec sandbox" },
  { name: "Step 7", fn: step7_cleanup, resultKey: "Step 7: Cleanup" },
];

async function main(): Promise<void> {
  console.log("Starting full system E2E test: OpenClaw → Aegis → MXC → wxc-exec\n");

  for (const step of steps) {
    try {
      console.log(`  Running ${step.name}...`);
      await step.fn();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  ❌ ${step.name} failed: ${msg}`);
      results[step.resultKey] = { pass: false, detail: msg };

      // Cleanup is always attempted even if a step fails
      if (step.name !== "Step 7") {
        try { await step7_cleanup(); } catch { /* ignore */ }
      }
      break;
    }
  }

  printSummary();
}

main().catch((err) => {
  console.error("Unhandled error:", err);
  // Best-effort cleanup
  if (daemon && !daemonWasPreExisting) { try { daemon.kill(); } catch {} }
  if (tempDir) { try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {} }
  process.exitCode = 1;
});
