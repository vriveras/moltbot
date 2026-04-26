import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { unlinkSync } from "node:fs";

// --- Mocks ---

const appendFileMock = vi.hoisted(() => vi.fn());

vi.mock("node:fs", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:fs")>();
  return {
    ...original,
    appendFile: appendFileMock,
  };
});

import { AegisAuditEmitter } from "../../src/audit-emitter.js";

// --- Helpers ---

function makePayload(index: number) {
  return {
    runtime: "openclaw" as const,
    cwd: process.cwd(),
    toolName: "bash",
    toolArgs: { command: `echo ${index}` },
    sessionId: "perf-session",
    runId: `run-${index}`,
    timestamp: new Date().toISOString(),
  };
}

function makeDecision() {
  return {
    permissionDecision: "allow" as const,
    permissionDecisionReason: "policy matched",
  };
}

function percentile(sorted: number[], p: number): number {
  return sorted[Math.floor(sorted.length * p)]!;
}

// --- Tests ---

describe("audit emission throughput", () => {
  let auditLogPath: string;

  beforeEach(() => {
    vi.clearAllMocks();
    auditLogPath = join(tmpdir(), `aegis-perf-audit-${Date.now()}.jsonl`);
    // Default: appendFile succeeds instantly via callback
    appendFileMock.mockImplementation(
      (_path: string, _data: string, cb: (err: Error | null) => void) => {
        cb(null);
      },
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    try {
      unlinkSync(auditLogPath);
    } catch {
      // file may not exist if mock intercepted all writes
    }
  });

  it("should emit 1000 events with p95 < 5ms per event", () => {
    const emitter = new AegisAuditEmitter({ auditLogPath });
    const latencies: number[] = [];
    const eventTypes = ["requested", "decided", "completed"] as const;

    for (let i = 0; i < 1000; i++) {
      const payload = makePayload(i);
      const start = performance.now();

      const eventType = eventTypes[i % eventTypes.length]!;
      switch (eventType) {
        case "requested":
          emitter.emitRequested(payload);
          break;
        case "decided":
          emitter.emitDecided(payload, makeDecision());
          break;
        case "completed":
          emitter.emitCompleted(payload, { durationMs: i });
          break;
      }

      const elapsed = performance.now() - start;
      latencies.push(elapsed);
    }

    latencies.sort((a, b) => a - b);

    const p50 = percentile(latencies, 0.5);
    const p95 = percentile(latencies, 0.95);
    const p99 = percentile(latencies, 0.99);
    const total = latencies.reduce((sum, v) => sum + v, 0);

    // eslint-disable-next-line no-console
    console.log(
      `[perf] audit emission throughput (1000 events): ` +
        `p50=${p50.toFixed(3)}ms  p95=${p95.toFixed(3)}ms  ` +
        `p99=${p99.toFixed(3)}ms  total=${total.toFixed(2)}ms`,
    );

    expect(p95).toBeLessThan(5);
    expect(appendFileMock).toHaveBeenCalledTimes(1000);

    emitter.dispose();
  });

  it("should not block tool execution (non-blocking writes)", () => {
    // Simulate a slow fs.appendFile that takes 200ms to call back
    appendFileMock.mockImplementation(
      (_path: string, _data: string, cb: (err: Error | null) => void) => {
        setTimeout(() => cb(null), 200);
      },
    );

    const emitter = new AegisAuditEmitter({ auditLogPath });
    const payload = makePayload(0);

    const start = performance.now();
    emitter.emitRequested(payload);
    emitter.emitDecided(payload, makeDecision());
    emitter.emitCompleted(payload, { durationMs: 42 });
    const elapsed = performance.now() - start;

    // eslint-disable-next-line no-console
    console.log(
      `[perf] non-blocking emit (3 calls with 200ms delayed cb): ` +
        `elapsed=${elapsed.toFixed(3)}ms`,
    );

    // All three emit calls should return in well under 50ms total,
    // even though the callback is delayed by 200ms each.
    // The emitter uses fire-and-forget appendFile with a callback.
    expect(elapsed).toBeLessThan(50);
    expect(appendFileMock).toHaveBeenCalledTimes(3);

    emitter.dispose();
  });
});
