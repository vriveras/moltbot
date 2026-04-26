import { beforeEach, describe, expect, it, vi } from "vitest";
import { EventEmitter } from "node:events";
import type { ChildProcess } from "node:child_process";

// --- Mocks ---

const spawnMock = vi.hoisted(() =>
  vi.fn<(cmd: string, args: string[], opts: unknown) => ChildProcess>(),
);

vi.mock("node:child_process", () => ({
  spawn: spawnMock,
}));

import { AegisIpcClient } from "../../src/ipc-client.js";

// --- Helpers ---

const CANNED_RESPONSE = JSON.stringify({
  permissionDecision: "allow",
  permissionDecisionReason: "policy matched",
  cookie: "perf-cookie-001",
}) + "\n";

/** Build a fake ChildProcess that immediately emits a canned allow response. */
function createAutoRespondChild(): ChildProcess {
  const proc = new EventEmitter() as ChildProcess & {
    killed: boolean;
    kill: ReturnType<typeof vi.fn>;
  };
  const stdout = new EventEmitter();
  const stderr = new EventEmitter();
  const stdin = {
    write: vi.fn(() => {
      // Emit response on next microtick after stdin write
      queueMicrotask(() => {
        stdout.emit("data", Buffer.from(CANNED_RESPONSE));
      });
    }),
    end: vi.fn(),
  };

  (proc as unknown as Record<string, unknown>).stdout = stdout;
  (proc as unknown as Record<string, unknown>).stderr = stderr;
  (proc as unknown as Record<string, unknown>).stdin = stdin;
  proc.killed = false;
  proc.kill = vi.fn(() => {
    proc.killed = true;
    return true;
  });
  return proc;
}

function makePayload() {
  return {
    runtime: "openclaw" as const,
    cwd: process.cwd(),
    toolName: "bash",
    toolArgs: { command: "echo hi" },
    sessionId: "perf-session",
    timestamp: new Date().toISOString(),
  };
}

function percentile(sorted: number[], p: number): number {
  return sorted[Math.floor(sorted.length * p)]!;
}

// --- Tests ---

describe("subprocess proxy latency", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  it("should complete 100 sequential decide calls under 150ms p95", async () => {
    spawnMock.mockImplementation(() => createAutoRespondChild());

    const client = new AegisIpcClient({
      aegisBinaryPath: "/usr/bin/aegis",
      readTimeoutMs: 5_000,
      connectTimeoutMs: 5_000,
    });

    const latencies: number[] = [];
    const payload = makePayload();

    for (let i = 0; i < 100; i++) {
      const start = performance.now();
      const result = await client.decide(payload);
      const elapsed = performance.now() - start;
      latencies.push(elapsed);

      // Sanity: the mock should return allow
      expect(result.permissionDecision).toBe("allow");
    }

    latencies.sort((a, b) => a - b);

    const p50 = percentile(latencies, 0.5);
    const p95 = percentile(latencies, 0.95);
    const p99 = percentile(latencies, 0.99);
    const max = latencies[latencies.length - 1]!;

    // eslint-disable-next-line no-console
    console.log(
      `[perf] subprocess proxy latency (100 calls): ` +
        `p50=${p50.toFixed(2)}ms  p95=${p95.toFixed(2)}ms  ` +
        `p99=${p99.toFixed(2)}ms  max=${max.toFixed(2)}ms`,
    );

    expect(p95).toBeLessThan(150);

    client.dispose();
  });
});
