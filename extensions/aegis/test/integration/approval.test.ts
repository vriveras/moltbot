import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { EventEmitter } from "node:events";
import type { ChildProcess } from "node:child_process";

// --- Module-level mocks (hoisted before imports) ---

const spawnMock = vi.hoisted(() =>
  vi.fn<(cmd: string, args: string[], opts: unknown) => ChildProcess>(),
);

vi.mock("node:child_process", () => ({
  spawn: spawnMock,
}));

const appendFileMock = vi.hoisted(() => vi.fn());

vi.mock("node:fs", () => ({
  appendFile: appendFileMock,
}));

// --- Real imports ---

import { AegisIpcClient } from "../../src/ipc-client.js";
import { AegisAuditEmitter } from "../../src/audit-emitter.js";
import { registerAegisHooks } from "../../src/hook-handler.js";
import {
  buildApprovalRequest,
  handleApprovalResolution,
} from "../../src/approval-bridge.js";
import type { AegisPluginConfig } from "../../src/config.js";

// --- Helpers ---

type HookHandler = (
  event: Record<string, unknown>,
  ctx: Record<string, unknown>,
) => Promise<Record<string, unknown> | void>;

function createFakeChild(): ChildProcess & {
  _stdout: EventEmitter;
  _stderr: EventEmitter;
  _stdin: { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn> };
  emitClose: (code: number | null) => void;
} {
  const proc = new EventEmitter() as ChildProcess & {
    _stdout: EventEmitter;
    _stderr: EventEmitter;
    _stdin: { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn> };
    emitClose: (code: number | null) => void;
    killed: boolean;
    kill: ReturnType<typeof vi.fn>;
  };
  proc._stdout = new EventEmitter();
  proc._stderr = new EventEmitter();
  proc._stdin = { write: vi.fn(), end: vi.fn() };
  (proc as unknown as Record<string, unknown>).stdout = proc._stdout;
  (proc as unknown as Record<string, unknown>).stderr = proc._stderr;
  (proc as unknown as Record<string, unknown>).stdin = proc._stdin;
  proc.killed = false;
  proc.kill = vi.fn(() => {
    proc.killed = true;
    return true;
  });
  proc.emitClose = (code) => proc.emit("close", code);
  return proc;
}

function makeEvent(overrides?: Record<string, unknown>) {
  return {
    toolName: "bash",
    params: { command: "echo hello" },
    runId: "run-1",
    toolCallId: "tc-1",
    ...overrides,
  };
}

function makeCtx(overrides?: Record<string, unknown>) {
  return {
    agentId: "agent-1",
    sessionKey: "key-1",
    sessionId: "session-1",
    runId: "run-ctx",
    toolCallId: "tc-ctx",
    ...overrides,
  };
}

function silenceAppendFile() {
  appendFileMock.mockImplementation(
    (_path: string, _data: string, cb: (err: Error | null) => void) => {
      cb(null);
    },
  );
}

function mockDaemonResponse(json: string) {
  const child = createFakeChild();
  spawnMock.mockImplementation(() => {
    process.nextTick(() => {
      child._stdout.emit("data", Buffer.from(json + "\n"));
    });
    return child;
  });
  return child;
}

function setupPipeline(configOverrides?: Partial<AegisPluginConfig>) {
  const handlers: Record<string, HookHandler> = {};

  const api = {
    on: vi.fn((eventName: string, handler: HookHandler) => {
      handlers[eventName] = handler;
    }),
    registerService: vi.fn(),
  };

  const config: AegisPluginConfig = {
    enabled: true,
    aegisBinaryPath: "aegis",
    auditLogPath: "test-audit.jsonl",
    ...configOverrides,
  };

  const client = new AegisIpcClient({
    aegisBinaryPath: config.aegisBinaryPath ?? "aegis",
    readTimeoutMs: 5_000,
    connectTimeoutMs: 5_000,
  });

  const emitter = new AegisAuditEmitter({
    auditLogPath: config.auditLogPath,
    redactKeyPatterns: config.redactKeyPatterns,
    redactValuePatterns: config.redactValuePatterns,
  });

  const getConfig = () => config;
  const getClient = () => client;

  registerAegisHooks(
    api as unknown as Parameters<typeof registerAegisHooks>[0],
    getClient,
    emitter,
    getConfig,
  );

  return {
    beforeHandler: handlers["before_tool_call"]!,
    config,
  };
}

// --- Tests ---

describe("Approval flow integration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Ask → approve → cookie threaded
  test("ask + approve: pre-issued cookie is threaded through approval resolution", async () => {
    silenceAppendFile();
    mockDaemonResponse(
      JSON.stringify({
        permissionDecision: "ask",
        permissionDecisionReason: "requires human review",
        cookie: "askcookie456",
      }),
    );

    const { beforeHandler } = setupPipeline();
    const result = await beforeHandler(makeEvent(), makeCtx());

    const r = result as Record<string, unknown>;
    // C1 fix: executionMetadata is NOT attached on ask path (cookie leak prevention)
    expect(r.executionMetadata).toBeUndefined();

    // Approval resolution with daemon's pre-issued cookie
    const resolution = handleApprovalResolution("allow-once", "askcookie456");
    expect(resolution).toEqual({ proceed: true, cookie: "askcookie456" });
  });

  // 2. Ask → deny → tool blocked
  test("ask + deny: user denies approval → proceed:false", async () => {
    silenceAppendFile();
    mockDaemonResponse(
      JSON.stringify({
        permissionDecision: "ask",
        permissionDecisionReason: "risky operation",
        cookie: "deny-cookie",
      }),
    );

    const { beforeHandler } = setupPipeline();
    const result = await beforeHandler(makeEvent(), makeCtx());

    const r = result as Record<string, unknown>;
    expect(r.executionMetadata).toBeUndefined();

    const resolution = handleApprovalResolution("deny", "deny-cookie");
    expect(resolution).toEqual({ proceed: false });
  });

  // 3. Ask → timeout → tool blocked
  test("ask + timeout: approval times out → proceed:false", async () => {
    silenceAppendFile();
    mockDaemonResponse(
      JSON.stringify({
        permissionDecision: "ask",
        permissionDecisionReason: "timeout test",
        cookie: "timeout-cookie",
      }),
    );

    const { beforeHandler } = setupPipeline();
    const result = await beforeHandler(makeEvent(), makeCtx());

    const r = result as Record<string, unknown>;
    expect(r.executionMetadata).toBeUndefined();

    const resolution = handleApprovalResolution("timeout", "timeout-cookie");
    expect(resolution).toEqual({ proceed: false });
  });

  // 4. Ask → cancelled → tool blocked
  test("ask + cancelled: approval cancelled → proceed:false", async () => {
    silenceAppendFile();
    mockDaemonResponse(
      JSON.stringify({
        permissionDecision: "ask",
        permissionDecisionReason: "cancel test",
        cookie: "cancel-cookie",
      }),
    );

    const { beforeHandler } = setupPipeline();
    const result = await beforeHandler(makeEvent(), makeCtx());

    const r = result as Record<string, unknown>;
    expect(r.executionMetadata).toBeUndefined();

    const resolution = handleApprovalResolution("cancelled", "cancel-cookie");
    expect(resolution).toEqual({ proceed: false });
  });

  // 5. Approval request format validation
  test("approval request contains tool name, reason, and config-driven severity/timeout", async () => {
    silenceAppendFile();
    mockDaemonResponse(
      JSON.stringify({
        permissionDecision: "ask",
        permissionDecisionReason: "network-access policy",
      }),
    );

    const { beforeHandler } = setupPipeline({
      approvalSeverity: "critical",
      approvalTimeoutMs: 120_000,
      approvalTimeoutBehavior: "allow",
    });

    const result = await beforeHandler(
      makeEvent({ toolName: "curl" }),
      makeCtx(),
    );

    const r = result as Record<string, unknown>;
    const approval = r.requireApproval as Record<string, unknown>;
    expect(approval.title).toContain("curl");
    expect(approval.description).toContain("network-access policy");
    expect(approval.severity).toBe("critical");
    expect(approval.timeoutMs).toBe(120_000);
    expect(approval.timeoutBehavior).toBe("allow");
  });

  // 6. Redaction in approval description (via buildApprovalRequest)
  test("buildApprovalRequest redacts args whose keys match redactPatterns", () => {
    const request = buildApprovalRequest(
      "bash",
      { command: "test", password: "hunter2", secret: "s3cret", safe: "visible" },
      "needs review",
      {
        enabled: true,
        redactKeyPatterns: ["password", "secret"],
      },
    );

    expect(request.description).toContain("[REDACTED]");
    expect(request.description).not.toContain("hunter2");
    expect(request.description).not.toContain("s3cret");
    expect(request.description).toContain("visible");
  });
});
