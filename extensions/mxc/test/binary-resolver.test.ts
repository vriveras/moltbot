import { describe, expect, test, vi } from "vitest";

// Mock node:fs and node:os for controlled testing
const existsSyncMock = vi.hoisted(() => vi.fn());

vi.mock("node:fs", () => ({
  existsSync: existsSyncMock,
}));

import { resolveMxcBinaryPath } from "../src/binary-resolver.js";

describe("resolveMxcBinaryPath", () => {
  test("config override returns the override path when file exists", () => {
    existsSyncMock.mockReturnValue(true);
    const result = resolveMxcBinaryPath("C:\\custom\\wxc-exec.exe");
    expect(result).toBe("C:\\custom\\wxc-exec.exe");
  });

  test("config override throws when file does not exist", () => {
    existsSyncMock.mockReturnValue(false);
    expect(() => resolveMxcBinaryPath("C:\\missing\\wxc-exec.exe")).toThrow(
      /not found at configured path/,
    );
  });

  test("missing binary with no override throws descriptive error", () => {
    existsSyncMock.mockReturnValue(false);
    // Without override, it tries to discover — all paths will fail
    expect(() => resolveMxcBinaryPath()).toThrow(/not found/);
  });
});
