import { beforeEach, describe, expect, test, vi } from "vitest";
import { EventEmitter } from "node:events";
import type { ChildProcess } from "node:child_process";

// --- Mocks ---

const spawnMock = vi.hoisted(() =>
  vi.fn<(cmd: string, args: string[], opts: unknown) => ChildProcess>(),
);

const connectMock = vi.hoisted(() =>
  vi.fn<(opts: { path: string }) => EventEmitter>(),
);

vi.mock("node:child_process", () => ({
  spawn: spawnMock,
}));

vi.mock("node:net", () => ({
  connect: connectMock,
}));

import { AegisIpcClient, getDaemonPipePath } from "../src/ipc-client.js";

// --- Helpers ---

/** Build a fake socket for healthCheck pipe-connect tests. */
function createFakeSocket(): EventEmitter & { destroy: ReturnType<typeof vi.fn> } {
  const socket = new EventEmitter() as EventEmitter & {
    destroy: ReturnType<typeof vi.fn>;
  };
  socket.destroy = vi.fn();
  return socket;
}

/** Build a fake ChildProcess with evented stdout/stderr/stdin. */
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

function makePayload() {
  return {
    runtime: "openclaw" as const,
    cwd: process.cwd(),
    toolName: "bash",
    toolArgs: { command: "echo hi" },
    sessionId: "test-session",
    timestamp: new Date().toISOString(),
  };
}

function makeClient(overrides?: Partial<ConstructorParameters<typeof AegisIpcClient>[0]>) {
  return new AegisIpcClient({
    aegisBinaryPath: "/usr/bin/aegis",
    readTimeoutMs: 500,
    connectTimeoutMs: 500,
    ...overrides,
  });
}

// --- Tests ---

describe("AegisIpcClient", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  // 1. Successful decide — allow response
  test("decide returns parsed allow response from subprocess stdout", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    // Simulate daemon writing allow response
    child._stdout.emit(
      "data",
      Buffer.from('{"permissionDecision":"allow","permissionDecisionReason":"policy matched"}\n'),
    );

    const result = await promise;
    expect(result.permissionDecision).toBe("allow");
    expect(result.permissionDecisionReason).toBe("policy matched");
  });

  // 2. Deny response
  test("decide returns parsed deny response from subprocess stdout", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    child._stdout.emit(
      "data",
      Buffer.from('{"permissionDecision":"deny","permissionDecisionReason":"blocked by policy"}\n'),
    );

    const result = await promise;
    expect(result.permissionDecision).toBe("deny");
    expect(result.permissionDecisionReason).toBe("blocked by policy");
  });

  // 3. Subprocess spawn failure — fail-open allow
  test("decide returns fail-open allow when spawn throws", async () => {
    spawnMock.mockImplementation(() => {
      throw new Error("ENOENT");
    });

    const client = makeClient();
    const result = await client.decide(makePayload());

    expect(result.permissionDecision).toBe("allow");
    expect(result.permissionDecisionReason).toContain("fail-open");
  });

  // 4. Subprocess timeout — fail-open allow
  test("decide returns fail-open allow on timeout", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient({ readTimeoutMs: 100 });
    const promise = client.decide(makePayload());

    // Advance past the timeout without writing to stdout
    vi.advanceTimersByTime(200);

    const result = await promise;
    expect(result.permissionDecision).toBe("allow");
    expect(result.permissionDecisionReason).toContain("fail-open");
  });

  // 5. Malformed stdout — fail-open allow
  test("decide returns fail-open allow on malformed JSON stdout", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    child._stdout.emit("data", Buffer.from("not-valid-json\n"));

    const result = await promise;
    expect(result.permissionDecision).toBe("allow");
    expect(result.permissionDecisionReason).toContain("fail-open");
  });

  // 6. Subprocess error event — fail-open allow
  test("decide returns fail-open allow on child process error event", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    child.emit("error", new Error("spawn EACCES"));

    const result = await promise;
    expect(result.permissionDecision).toBe("allow");
    expect(result.permissionDecisionReason).toContain("fail-open");
  });

  // 7. healthCheck success — daemon pipe reachable
  test("healthCheck resolves true when daemon pipe is reachable", async () => {
    const socket = createFakeSocket();
    connectMock.mockReturnValue(socket);

    const client = makeClient();
    const promise = client.healthCheck();

    socket.emit("connect");

    const result = await promise;
    expect(result).toBe(true);
    expect(connectMock).toHaveBeenCalledWith(
      expect.objectContaining({ path: expect.any(String) }),
    );
    expect(socket.destroy).toHaveBeenCalled();
  });

  // 8. healthCheck failure — pipe connection error
  test("healthCheck resolves false when daemon pipe connection fails", async () => {
    const socket = createFakeSocket();
    connectMock.mockReturnValue(socket);

    const client = makeClient();
    const promise = client.healthCheck();

    socket.emit("error", new Error("ENOENT"));

    const result = await promise;
    expect(result).toBe(false);
  });

  // 9. healthCheck — connect throws
  test("healthCheck resolves false when connect throws", async () => {
    connectMock.mockImplementation(() => {
      throw new Error("ENOENT");
    });

    const client = makeClient();
    const result = await client.healthCheck();
    expect(result).toBe(false);
  });

  // 10. healthCheck — timeout
  test("healthCheck resolves false on connection timeout", async () => {
    const socket = createFakeSocket();
    connectMock.mockReturnValue(socket);

    const client = makeClient({ connectTimeoutMs: 100 });
    const promise = client.healthCheck();

    // Advance past the timeout without emitting connect
    vi.advanceTimersByTime(200);

    const result = await promise;
    expect(result).toBe(false);
    expect(socket.destroy).toHaveBeenCalled();
  });

  // 11. dispose cleans up active child processes
  test("dispose kills all tracked child processes", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();

    // Start a decide call so the child is tracked in activeChildren
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    client.decide(makePayload());

    client.dispose();

    expect(child.kill).toHaveBeenCalled();
  });

  // 12. decide returns fail-closed deny when failBehavior is deny and spawn throws
  test("decide returns fail-closed deny when failBehavior is deny and spawn throws", async () => {
    spawnMock.mockImplementation(() => {
      throw new Error("ENOENT");
    });

    const client = makeClient({ failBehavior: "deny" });
    const result = await client.decide(makePayload());

    expect(result.permissionDecision).toBe("deny");
    expect(result.permissionDecisionReason).toContain("fail-closed");
  });

  // 13. decide returns fail-closed deny when failBehavior is deny and timeout occurs
  test("decide returns fail-closed deny when failBehavior is deny and timeout occurs", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient({ failBehavior: "deny", readTimeoutMs: 100 });
    const promise = client.decide(makePayload());

    vi.advanceTimersByTime(200);

    const result = await promise;
    expect(result.permissionDecision).toBe("deny");
    expect(result.permissionDecisionReason).toContain("fail-closed");
  });

  // 14. decide writes payload JSON to child stdin
  test("decide writes JSON payload to subprocess stdin", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const payload = makePayload();
    const promise = client.decide(payload);

    // Verify stdin received the payload
    expect(child._stdin.write).toHaveBeenCalledWith(
      JSON.stringify(payload) + "\n",
    );
    expect(child._stdin.end).toHaveBeenCalled();

    // Settle the promise
    child._stdout.emit("data", Buffer.from('{"permissionDecision":"allow"}\n'));
    await promise;
  });

  // 15. close with non-zero exit code returns fail response
  test("decide returns fail-open on non-zero exit code with no prior stdout", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    child.emitClose(1);

    const result = await promise;
    expect(result.permissionDecision).toBe("allow");
    expect(result.permissionDecisionReason).toContain("fail-open");
  });

  // 16. close with code=0 but empty stdout returns fail response
  test("decide returns fail-open on close with code=0 but empty stdout", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    child.emitClose(0);

    const result = await promise;
    expect(result.permissionDecision).toBe("allow");
    expect(result.permissionDecisionReason).toContain("fail-open");
  });

  // 17. getDaemonPipePath returns correct path per platform
  test("getDaemonPipePath returns a non-empty string path", () => {
    const path = getDaemonPipePath();
    expect(typeof path).toBe("string");
    expect(path.length).toBeGreaterThan(0);
    if (process.platform === "win32") {
      expect(path).toMatch(/^\\\\.\\pipe\\/);
    } else {
      expect(path).toMatch(/^\/tmp\/CoreFxPipe_/);
    }
  });

  // 18. stdout overflow returns fail response
  test("decide returns fail-open when stdout exceeds 1MB", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    // Send >1MB of data without a newline
    const bigChunk = Buffer.alloc(1_048_577, 65); // 'A' x (1MB + 1)
    child._stdout.emit("data", bigChunk);

    const result = await promise;
    expect(result.permissionDecision).toBe("allow");
    expect(result.permissionDecisionReason).toContain("fail-open");
  });

  // 19. validateResponse rejects non-string cookie
  test("decide returns fail-open when response has non-string cookie", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    child._stdout.emit(
      "data",
      Buffer.from('{"permissionDecision":"allow","cookie":12345}\n'),
    );

    const result = await promise;
    expect(result.permissionDecision).toBe("allow");
    expect(result.permissionDecisionReason).toContain("fail-open");
  });
});
