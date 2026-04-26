import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import type { AegisIpcClient } from "../src/ipc-client.js";
import type { AegisAuditEmitter } from "../src/audit-emitter.js";
import type { AegisPluginConfig } from "../src/config.js";
import type { AegisDaemonResponse } from "../src/decision.js";
import { registerAegisHooks } from "../src/hook-handler.js";

// --- Helpers ---

type BeforeToolCallHandler = (
  event: Record<string, unknown>,
  ctx: Record<string, unknown>,
) => Promise<Record<string, unknown> | void>;

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

function setup(opts?: {
  config?: Partial<AegisPluginConfig>;
  decideResult?: AegisDaemonResponse | Error;
}) {
  let capturedHandler: BeforeToolCallHandler | undefined;

  const api = {
    on: vi.fn((eventName: string, handler: BeforeToolCallHandler) => {
      if (eventName === "before_tool_call") {
        capturedHandler = handler;
      }
    }),
  };

  const decideMock = vi.fn<(payload: unknown) => Promise<AegisDaemonResponse>>();
  if (opts?.decideResult instanceof Error) {
    decideMock.mockRejectedValue(opts.decideResult);
  } else if (opts?.decideResult) {
    decideMock.mockResolvedValue(opts.decideResult);
  } else {
    decideMock.mockResolvedValue({ permissionDecision: "allow" });
  }

  const client: AegisIpcClient = { decide: decideMock } as unknown as AegisIpcClient;
  const getClient = () => client;

  const emitter = {
    emitRequested: vi.fn(),
    emitDecided: vi.fn(),
    emitStarted: vi.fn(),
    emitCompleted: vi.fn(),
    emitApprovalResolved: vi.fn(),
    dispose: vi.fn(),
  } as unknown as AegisAuditEmitter;

  const config: AegisPluginConfig = { enabled: true, ...opts?.config };
  const getConfig = () => config;

  registerAegisHooks(
    api as unknown as Parameters<typeof registerAegisHooks>[0],
    getClient,
    emitter,
    getConfig,
  );

  return {
    handler: capturedHandler!,
    api,
    decideMock,
    emitter: emitter as unknown as Record<string, ReturnType<typeof vi.fn>>,
    config,
    getConfig,
  };
}

// --- Tests ---

describe("registerAegisHooks", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Allow path
  test("returns block:false with executionMetadata when daemon allows", async () => {
    const { handler } = setup({
      decideResult: {
        permissionDecision: "allow",
        cookie: "cookie-123",
      },
    });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toEqual(
      expect.objectContaining({
        block: false,
        executionMetadata: { aegisCookie: "cookie-123" },
      }),
    );
  });

  // 2. Deny path
  test("returns block:true with blockReason when daemon denies", async () => {
    const { handler } = setup({
      decideResult: { permissionDecision: "deny", permissionDecisionReason: "policy violation" },
    });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toEqual({
      block: true,
      blockReason: "policy violation",
    });
  });

  // 3. Ask path
  test("returns requireApproval with correct fields when daemon requires approval", async () => {
    const { handler } = setup({
      config: {
        approvalSeverity: "critical",
        approvalTimeoutMs: 60_000,
        approvalTimeoutBehavior: "allow",
      },
      decideResult: {
        permissionDecision: "ask",
        permissionDecisionReason: "risky command",
        cookie: "cookie-ask",
      },
    });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toBeDefined();
    const r = result as Record<string, unknown>;
    const approval = r.requireApproval as Record<string, unknown>;
    expect(approval.title).toBe("Aegis: Approval required for bash");
    expect(approval.description).toContain("Policy reason: risky command");
    expect(approval.description).toContain("Tool: bash");
    expect(approval.severity).toBe("critical");
    expect(approval.timeoutMs).toBe(60_000);
    expect(approval.timeoutBehavior).toBe("allow");
  });

  // 4. Daemon unreachable (fail-closed)
  test("returns block:true when daemon is unreachable (IPC client returns deny)", async () => {
    const { handler } = setup({
      decideResult: {
        permissionDecision: "deny",
        permissionDecisionReason: "Aegis daemon unreachable — fail-closed",
      },
    });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toEqual({
      block: true,
      blockReason: "Aegis daemon unreachable — fail-closed",
    });
  });

  // 5. Config disabled — returns undefined (passthrough)
  test("returns undefined when config.enabled is false", async () => {
    const { handler } = setup({ config: { enabled: false } });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toBeUndefined();
  });

  // 6. Audit events emitted on allow
  test("emits requested and decided audit events on allow", async () => {
    const { handler, emitter } = setup({
      decideResult: { permissionDecision: "allow" },
    });

    await handler(makeEvent(), makeCtx());

    expect(emitter.emitRequested).toHaveBeenCalledTimes(1);
    expect(emitter.emitDecided).toHaveBeenCalledTimes(1);
    expect(emitter.emitDecided).toHaveBeenCalledWith(
      expect.objectContaining({ toolName: "bash" }),
      expect.objectContaining({ permissionDecision: "allow" }),
    );
  });

  // 7. Audit events emitted on deny
  test("emits requested and decided audit events on deny", async () => {
    const { handler, emitter } = setup({
      decideResult: { permissionDecision: "deny", permissionDecisionReason: "blocked" },
    });

    await handler(makeEvent(), makeCtx());

    expect(emitter.emitRequested).toHaveBeenCalledTimes(1);
    expect(emitter.emitDecided).toHaveBeenCalledTimes(1);
    expect(emitter.emitDecided).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ permissionDecision: "deny", permissionDecisionReason: "blocked" }),
    );
  });

  // 8. Unhandled exception in handler — fail-open allow (default failBehavior)
  test("returns fail-open allow when IPC client throws (default failBehavior)", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { handler } = setup({
      decideResult: new Error("unexpected IPC failure"),
    });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toEqual({ block: false });
    expect(errorSpy).toHaveBeenCalledWith(
      "[aegis] before_tool_call error:",
      expect.any(Error),
    );
    errorSpy.mockRestore();
  });

  // 8b. Unhandled exception — fail-closed when failBehavior is "deny"
  test("returns block:true when failBehavior is deny and IPC throws", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { handler } = setup({
      config: { failBehavior: "deny" as const },
      decideResult: new Error("daemon gone"),
    });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toEqual({
      block: true,
      blockReason: "Aegis extension error — fail-closed",
    });
    expect(errorSpy).toHaveBeenCalledWith(
      "[aegis] before_tool_call error:",
      expect.any(Error),
    );
    errorSpy.mockRestore();
  });

  // 8c. Unrecognized decision — fail-closed when failBehavior is "deny"
  test("returns block:true for unrecognized decision when failBehavior is deny", async () => {
    const { handler } = setup({
      config: { failBehavior: "deny" as const },
      decideResult: { permissionDecision: "something-weird" as never },
    });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toEqual({ block: true });
  });

  // 9. Payload construction
  test("constructs ActionPayload with correct fields from event and context", async () => {
    const { handler, decideMock } = setup({
      decideResult: { permissionDecision: "allow" },
    });

    await handler(
      makeEvent({ toolName: "write_file", params: { path: "/tmp/x" }, runId: "r-2", toolCallId: "tc-2" }),
      makeCtx({ agentId: "a-2", sessionId: "s-2", sessionKey: "k-2" }),
    );

    expect(decideMock).toHaveBeenCalledWith(
      expect.objectContaining({
        runtime: "openclaw",
        cwd: expect.any(String),
        toolName: "write_file",
        toolArgs: { path: "/tmp/x" },
        agentId: "a-2",
        sessionId: "s-2",
        runId: "r-2",
        toolCallId: "tc-2",
        timestamp: expect.any(String),
      }),
    );
    // sessionKey must NOT be present
    const actualPayload = decideMock.mock.calls[0][0] as Record<string, unknown>;
    expect(actualPayload).not.toHaveProperty("sessionKey");
  });

  // 10. Missing cookie on allow — executionMetadata is undefined
  test("returns undefined executionMetadata when allow response has no cookie", async () => {
    const { handler } = setup({
      decideResult: { permissionDecision: "allow" },
    });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toBeDefined();
    const r = result as Record<string, unknown>;
    expect(r.block).toBe(false);
    expect(r.executionMetadata).toBeUndefined();
  });

  // 11. Deny without explicit reason falls back to default message
  test("uses default blockReason when deny response has no reason", async () => {
    const { handler } = setup({
      decideResult: { permissionDecision: "deny" },
    });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toEqual({
      block: true,
      blockReason: "Denied by Aegis policy",
    });
  });

  // 12. Allow — no modifiedParams (removed from wire format)
  test("allow response returns block:false without params spread", async () => {
    const { handler } = setup({
      decideResult: {
        permissionDecision: "allow",
      },
    });

    const result = await handler(makeEvent(), makeCtx());

    expect(result).toEqual(
      expect.objectContaining({
        block: false,
      }),
    );
  });

  // 13. ask uses config defaults when response omits optional fields
  test("ask uses config defaults for missing severity/timeout", async () => {
    const { handler } = setup({
      decideResult: {
        permissionDecision: "ask",
        permissionDecisionReason: "needs review",
      },
    });

    const result = await handler(
      makeEvent({ toolName: "rm" }),
      makeCtx(),
    );

    const r = result as Record<string, unknown>;
    const approval = r.requireApproval as Record<string, unknown>;
    expect(approval.title).toBe("Aegis: Approval required for rm");
    expect(approval.severity).toBe("warning");
    expect(approval.timeoutMs).toBe(1_800_000);
    expect(approval.timeoutBehavior).toBe("deny");
  });

  // 14. No audit events when config is disabled
  test("does not call audit emitter when config.enabled is false", async () => {
    const { handler, emitter } = setup({ config: { enabled: false } });

    await handler(makeEvent(), makeCtx());

    expect(emitter.emitRequested).not.toHaveBeenCalled();
    expect(emitter.emitDecided).not.toHaveBeenCalled();
  });

  // 15. Event params default to empty object when undefined
  test("payload toolArgs defaults to empty object when event.params is undefined", async () => {
    const { handler, decideMock } = setup({
      decideResult: { permissionDecision: "allow" },
    });

    await handler(
      makeEvent({ params: undefined }),
      makeCtx(),
    );

    expect(decideMock).toHaveBeenCalledWith(
      expect.objectContaining({ toolArgs: {} }),
    );
  });

  // 16. onResolution callback invoked with allow-once emits approval resolved
  test("ask path onResolution emits approval resolved event on approval", async () => {
    const { handler, emitter } = setup({
      decideResult: {
        permissionDecision: "ask",
        permissionDecisionReason: "needs review",
        cookie: "cookie-ask",
      },
    });

    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
    const result = await handler(makeEvent(), makeCtx());

    const r = result as Record<string, unknown>;
    const approval = r.requireApproval as Record<string, unknown>;
    const onResolution = approval.onResolution as (r: unknown) => Promise<void>;
    expect(onResolution).toBeInstanceOf(Function);

    await onResolution("allow-once");

    expect(emitter.emitApprovalResolved).toHaveBeenCalledWith(
      "tc-1",
      "bash",
      "allow-once",
      "session-1",
    );
    expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining("Approval granted"));

    infoSpy.mockRestore();
  });

  // 17. onResolution callback with deny logs denial
  test("ask path onResolution logs denial and emits event on deny", async () => {
    const { handler, emitter } = setup({
      decideResult: {
        permissionDecision: "ask",
        permissionDecisionReason: "review needed",
      },
    });

    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
    const result = await handler(makeEvent(), makeCtx());

    const r = result as Record<string, unknown>;
    const approval = r.requireApproval as Record<string, unknown>;
    const onResolution = approval.onResolution as (r: unknown) => Promise<void>;

    await onResolution("deny");

    expect(emitter.emitApprovalResolved).toHaveBeenCalledWith(
      "tc-1",
      "bash",
      "deny",
      "session-1",
    );
    expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining("Approval denied"));

    infoSpy.mockRestore();
  });
});
