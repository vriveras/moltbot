import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

// --- Mocks ---

const appendFileMock = vi.hoisted(() => vi.fn());

vi.mock("node:fs", () => ({
  appendFile: appendFileMock,
}));

import { AegisAuditEmitter } from "../src/audit-emitter.js";

// --- Helpers ---

function makePayload(overrides?: Record<string, unknown>) {
  return {
    toolName: "bash",
    params: { command: "echo hello" } as Record<string, unknown>,
    sessionId: "session-1",
    sessionKey: "key-1",
    runId: "run-42",
    timestamp: "2025-01-15T12:00:00.000Z",
    ...overrides,
  };
}

/** Capture all lines written via the mocked appendFile. */
function captureLines(): string[] {
  const lines: string[] = [];
  appendFileMock.mockImplementation(
    (_path: string, data: string, cb: (err: Error | null) => void) => {
      lines.push(data);
      cb(null);
    },
  );
  return lines;
}

/** Parse a single captured JSONL line (trims trailing newline). */
function parseLine(line: string): Record<string, unknown> {
  return JSON.parse(line.trimEnd()) as Record<string, unknown>;
}

// --- Tests ---

describe("AegisAuditEmitter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. emitRequested schema
  test("emitRequested writes event with correct schema", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitRequested(makePayload());

    expect(lines).toHaveLength(1);
    const event = parseLine(lines[0]!);
    expect(event.eventType).toBe("aegis.action.requested");
    expect(event.runtime).toBe("openclaw");
    expect(event.sessionId).toBe("session-1");
    // timestamp is ISO 8601
    expect(typeof event.timestamp).toBe("string");
    expect(() => new Date(event.timestamp as string)).not.toThrow();
    // action fields
    const action = event.action as Record<string, unknown>;
    expect(action.kind).toBe("tool_call");
    expect(action.name).toBe("bash");
    expect(action.args).toEqual({ command: "echo hello" });
    // context
    const context = event.context as Record<string, unknown>;
    expect(context.traceId).toBe("run-42");
  });

  // 2. emitDecided schema
  test("emitDecided writes event with decision fields", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitDecided(makePayload(), {
      action: "deny",
      reason: "blocked",
      policyId: "pol-1",
    });

    expect(lines).toHaveLength(1);
    const event = parseLine(lines[0]!);
    expect(event.eventType).toBe("aegis.action.decided");
    const decision = event.decision as Record<string, unknown>;
    expect(decision.decision).toBe("deny");
    expect(decision.reason).toBe("blocked");
    expect(decision.ruleName).toBe("pol-1");
  });

  // 3. emitCompleted schema
  test("emitCompleted writes event with result fields", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitCompleted(makePayload(), { durationMs: 120 });

    expect(lines).toHaveLength(1);
    const event = parseLine(lines[0]!);
    expect(event.eventType).toBe("aegis.action.completed");
    const result = event.result as Record<string, unknown>;
    expect(result.success).toBe(true);
    expect(result.durationMs).toBe(120);
  });

  // 4. emitCompleted with error marks success false
  test("emitCompleted marks success false when error is present", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitCompleted(makePayload(), { error: "boom", durationMs: 50 });

    const event = parseLine(lines[0]!);
    const result = event.result as Record<string, unknown>;
    expect(result.success).toBe(false);
  });

  // 5. JSONL format — multiple events, each valid JSON, newline-terminated
  test("multiple events produce valid JSONL (one JSON object per line)", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitRequested(makePayload());
    emitter.emitDecided(makePayload(), { action: "allow" });
    emitter.emitCompleted(makePayload(), { durationMs: 10 });

    expect(lines).toHaveLength(3);
    for (const line of lines) {
      // Each line ends with newline
      expect(line.endsWith("\n")).toBe(true);
      // Each line is valid JSON
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  // 6. Error handling — appendFile callback error does not propagate
  test("appendFile callback error logs warning but does not throw", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    appendFileMock.mockImplementation(
      (_path: string, _data: string, cb: (err: Error | null) => void) => {
        cb(new Error("disk full"));
      },
    );

    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    // Should not throw
    expect(() => emitter.emitRequested(makePayload())).not.toThrow();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("disk full"),
    );

    warnSpy.mockRestore();
  });

  // 7. Redaction — sensitive values are replaced with [REDACTED]
  test("redactPatterns replaces matching string arg values", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({
      auditLogPath: "test.jsonl",
      redactPatterns: ["sk-[a-zA-Z0-9]+", "password=\\S+"],
    });

    const payload = makePayload({
      params: {
        command: "curl -H 'Authorization: Bearer sk-abc123'",
        safe: "normal-value",
        creds: "password=s3cret",
        numeric: 42,
      },
    });

    emitter.emitRequested(payload);

    const event = parseLine(lines[0]!);
    const action = event.action as Record<string, unknown>;
    const args = action.args as Record<string, unknown>;
    expect(args.command).toBe("[REDACTED]");
    expect(args.safe).toBe("normal-value");
    expect(args.creds).toBe("[REDACTED]");
    // Non-string values pass through unchanged
    expect(args.numeric).toBe(42);
  });

  // 8. sessionKey fallback when sessionId is missing
  test("uses sessionKey as fallback when sessionId is undefined", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitRequested(
      makePayload({ sessionId: undefined, sessionKey: "fallback-key" }),
    );

    const event = parseLine(lines[0]!);
    expect(event.sessionId).toBe("fallback-key");
  });

  // 9. emitStarted schema
  test("emitStarted writes event with context", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitStarted(makePayload());

    const event = parseLine(lines[0]!);
    expect(event.eventType).toBe("aegis.action.started");
    expect(event.context).toBeDefined();
  });
});
