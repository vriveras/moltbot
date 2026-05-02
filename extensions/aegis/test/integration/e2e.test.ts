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

// --- Real imports (use mocked I/O boundaries) ---

import { AegisIpcClient } from "../../src/ipc-client.js";
import { AegisAuditEmitter } from "../../src/audit-emitter.js";
import { registerAegisHooks } from "../../src/hook-handler.js";
import { registerAegisAfterHooks } from "../../src/after-hook-handler.js";
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

/** Capture audit event lines written via mocked appendFile. */
function captureAuditLines(): string[] {
  const lines: string[] = [];
  appendFileMock.mockImplementation(
    (_path: string, data: string, cb: (err: Error | null) => void) => {
      lines.push(data);
      cb(null);
    },
  );
  return lines;
}

function parseAuditLine(line: string): Record<string, unknown> {
  return JSON.parse(line.trimEnd()) as Record<string, unknown>;
}

/**
 * Mock child_process.spawn to return a fake child that emits the given JSON
 * response on stdout.  The emission is scheduled via process.nextTick so that
 * the IPC client's event listeners are wired before the data arrives.
 */
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

function mockDaemonSpawnFailure() {
  spawnMock.mockImplementation(() => {
    throw new Error("ENOENT: aegis binary not found");
  });
}

/**
 * Wire the full plugin pipeline with real components and mocked I/O.
 * Returns captured hook handlers so tests can invoke them directly.
 */
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
    failBehavior: config.failBehavior,
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

  registerAegisAfterHooks(
    api as unknown as Parameters<typeof registerAegisAfterHooks>[0],
    emitter,
    getConfig,
  );

  return {
    beforeHandler: handlers["before_tool_call"]!,
    afterHandler: handlers["after_tool_call"]!,
    client,
    emitter,
  };
}

// --- Tests ---

describe("End-to-end integration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Allow flow end-to-end
  test("allow flow: subprocess allow → block:false with cookie + audit events", async () => {
    const auditLines = captureAuditLines();
    mockDaemonResponse(
      JSON.stringify({
        permissionDecision: "allow",
        permissionDecisionReason: "policy matched",
        cookie: "cookie123",
      }),
    );

    const { beforeHandler } = setupPipeline();
    const result = await beforeHandler(makeEvent(), makeCtx());

    // Hook result
    expect(result).toEqual(
      expect.objectContaining({
        block: false,
        executionMetadata: expect.objectContaining({
          aegisCookie: "cookie123",
          aegisEnvelope: { mode: "reuse_shell" },
        }),
      }),
    );

    // Audit events
    expect(auditLines).toHaveLength(2);
    const requested = parseAuditLine(auditLines[0]!);
    const decided = parseAuditLine(auditLines[1]!);

    expect(requested.eventType).toBe("aegis.action.requested");
    expect(requested.runtime).toBe("openclaw");

    expect(decided.eventType).toBe("aegis.action.decided");
    const decision = decided.decision as Record<string, unknown>;
    expect(decision.decision).toBe("allow");
    expect(decision.reason).toBe("policy matched");
  });

  // 2. Deny flow end-to-end
  test("deny flow: subprocess deny → block:true with reason + audit events", async () => {
    const auditLines = captureAuditLines();
    mockDaemonResponse(
      JSON.stringify({
        permissionDecision: "deny",
        permissionDecisionReason: "destructive command blocked",
      }),
    );

    const { beforeHandler } = setupPipeline();
    const result = await beforeHandler(makeEvent(), makeCtx());

    expect(result).toEqual({
      block: true,
      blockReason: "destructive command blocked",
    });

    expect(auditLines).toHaveLength(2);
    const decided = parseAuditLine(auditLines[1]!);
    const decision = decided.decision as Record<string, unknown>;
    expect(decision.decision).toBe("deny");
    expect(decision.reason).toBe("destructive command blocked");
  });

  // 3. Ask flow end-to-end
  test("ask flow: subprocess ask → requireApproval with cookie + audit events", async () => {
    const auditLines = captureAuditLines();
    mockDaemonResponse(
      JSON.stringify({
        permissionDecision: "ask",
        permissionDecisionReason: "requires human review",
        cookie: "askcookie456",
      }),
    );

    const { beforeHandler } = setupPipeline();
    const result = await beforeHandler(
      makeEvent({ toolName: "rm" }),
      makeCtx(),
    );

    expect(result).toBeDefined();
    const r = result as Record<string, unknown>;
    const approval = r.requireApproval as Record<string, unknown>;
    expect(approval.title).toContain("rm");
    // C1 fix: executionMetadata NOT attached on ask path (cookie leak prevention)
    expect(r.executionMetadata).toBeUndefined();

    expect(auditLines).toHaveLength(2);
    const decided = parseAuditLine(auditLines[1]!);
    const decision = decided.decision as Record<string, unknown>;
    expect(decision.decision).toBe("ask");
  });

  // 4. Daemon failure end-to-end — fail-open allow
  test("daemon failure: spawn throws → block:false fail-open", async () => {
    const auditLines = captureAuditLines();
    mockDaemonSpawnFailure();

    const { beforeHandler } = setupPipeline();
    const result = await beforeHandler(makeEvent(), makeCtx());

    expect(result).toEqual(expect.objectContaining({ block: false }));
    const r = result as Record<string, unknown>;
    const meta = r.executionMetadata as Record<string, unknown>;
    expect(meta.aegisEnvelope).toEqual({ mode: "reuse_shell" });

    // IPC client resolves with FAIL_OPEN allow — audit events are still emitted
    expect(auditLines).toHaveLength(2);
    const decided = parseAuditLine(auditLines[1]!);
    const decision = decided.decision as Record<string, unknown>;
    expect(decision.decision).toBe("allow");
    expect(decision.reason).toBe("Aegis daemon unreachable — fail-open");
  });

  // 5. Full lifecycle (before + after hooks)
  test("full lifecycle: before + after hooks produce requested, decided, completed events", async () => {
    const auditLines = captureAuditLines();
    mockDaemonResponse(
      JSON.stringify({
        permissionDecision: "allow",
        permissionDecisionReason: "policy matched",
        cookie: "lifecycle-cookie",
      }),
    );

    const { beforeHandler, afterHandler } = setupPipeline();

    // Before hook
    const result = await beforeHandler(makeEvent(), makeCtx());
    expect(result).toEqual(
      expect.objectContaining({ block: false }),
    );

    // After hook (tool execution completed successfully)
    await afterHandler(
      makeEvent({ error: undefined, durationMs: 150 }),
      makeCtx(),
    );

    // Verify all audit events in order
    expect(auditLines).toHaveLength(3);
    const eventTypes = auditLines.map(
      (line) => parseAuditLine(line).eventType,
    );
    expect(eventTypes).toEqual([
      "aegis.action.requested",
      "aegis.action.decided",
      "aegis.action.completed",
    ]);

    // Completed event has result fields
    const completed = parseAuditLine(auditLines[2]!);
    const completedResult = completed.result as Record<string, unknown>;
    expect(completedResult.success).toBe(true);
    expect(completedResult.durationMs).toBe(150);
  });

  // 6. Fail-closed end-to-end — daemon spawn failure with failBehavior=deny
  test("fail-closed: daemon unavailable with failBehavior=deny returns block:true + deny audit", async () => {
    const auditLines = captureAuditLines();
    mockDaemonSpawnFailure();

    const { beforeHandler } = setupPipeline({ failBehavior: "deny" });
    const result = await beforeHandler(makeEvent(), makeCtx());

    expect(result).toEqual({
      block: true,
      blockReason: "Aegis daemon unreachable — fail-closed",
    });

    // Audit should still record the deny decision
    expect(auditLines).toHaveLength(2);
    const decided = parseAuditLine(auditLines[1]!);
    const decision = decided.decision as Record<string, unknown>;
    expect(decision.decision).toBe("deny");
    expect(decision.reason).toContain("fail-closed");
  });

  // 7. After-hook with tool execution error
  test("after hook with error: emits completed event with success=false", async () => {
    const auditLines = captureAuditLines();
    mockDaemonResponse(
      JSON.stringify({
        permissionDecision: "allow",
        permissionDecisionReason: "ok",
      }),
    );

    const { beforeHandler, afterHandler } = setupPipeline();

    await beforeHandler(makeEvent(), makeCtx());

    // After hook with error
    await afterHandler(
      makeEvent({ error: "Command failed with exit code 1", durationMs: 50 }),
      makeCtx(),
    );

    expect(auditLines).toHaveLength(3);
    const completed = parseAuditLine(auditLines[2]!);
    expect(completed.eventType).toBe("aegis.action.completed");
    const result = completed.result as Record<string, unknown>;
    expect(result.success).toBe(false);
    expect(result.durationMs).toBe(50);
  });

  // 8. Config disabled — no hooks fire, no audit events
  test("disabled config: before and after hooks are no-ops", async () => {
    const auditLines = captureAuditLines();
    mockDaemonResponse(JSON.stringify({ permissionDecision: "allow" }));

    const { beforeHandler, afterHandler } = setupPipeline({ enabled: false });

    const beforeResult = await beforeHandler(makeEvent(), makeCtx());
    expect(beforeResult).toBeUndefined();

    await afterHandler(makeEvent({ durationMs: 10 }), makeCtx());

    // No audit events should be written
    expect(auditLines).toHaveLength(0);
  });
});
