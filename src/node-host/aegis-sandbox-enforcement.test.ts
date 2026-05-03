import { describe, expect, it, vi } from "vitest";
import {
  enforceAegisSandbox,
  redeemCookie,
  AegisEnforcementError,
  getDaemonPipePath,
} from "./aegis-sandbox-enforcement.js";
import { translateEnvelopeToPolicy, type AegisExecutionEnvelope } from "../shared/aegis-envelope.js";
import type { ResolvedAegisEnforcementConfig } from "./aegis-config.js";

vi.mock("../logger.js", () => ({
  logWarn: vi.fn(),
}));

const mockConfig: ResolvedAegisEnforcementConfig = {
  aegisBinaryPath: "/nonexistent/aegis",
  mxcBinaryPath: "/nonexistent/wxc-exec",
  enabled: true,
};

// ---------------------------------------------------------------------------
// enforceAegisSandbox — cookie validation (fail-closed)
// ---------------------------------------------------------------------------

describe("enforceAegisSandbox", () => {
  it("throws when aegisCookie is missing from executionMetadata", async () => {
    await expect(
      enforceAegisSandbox({
        executionMetadata: {},
        argv: ["echo", "hello"],
        cwd: "/tmp",
        config: mockConfig,
      }),
    ).rejects.toThrow(AegisEnforcementError);
  });

  it("throws when aegisCookie is an empty string", async () => {
    await expect(
      enforceAegisSandbox({
        executionMetadata: { aegisCookie: "" },
        argv: ["echo", "hello"],
        cwd: "/tmp",
        config: mockConfig,
      }),
    ).rejects.toThrow(AegisEnforcementError);
  });

  it("throws when aegisCookie is not a string", async () => {
    await expect(
      enforceAegisSandbox({
        executionMetadata: { aegisCookie: 42 },
        argv: ["echo", "hello"],
        cwd: "/tmp",
        config: mockConfig,
      }),
    ).rejects.toThrow("aegisCookie is missing or not a string");
  });

  it("throws AegisEnforcementError when daemon is unavailable (fail-closed)", async () => {
    await expect(
      enforceAegisSandbox({
        executionMetadata: { aegisCookie: "valid-looking-cookie" },
        argv: ["echo", "hello"],
        cwd: "/tmp",
        config: mockConfig,
      }),
    ).rejects.toThrow(AegisEnforcementError);
  });
});

// ---------------------------------------------------------------------------
// redeemCookie — daemon connection error paths
// ---------------------------------------------------------------------------

describe("redeemCookie", () => {
  it("rejects with AegisEnforcementError when daemon pipe does not exist", async () => {
    await expect(
      redeemCookie({
        cookie: "test-cookie",
        toolName: "system.run",
        args: "echo hello",
        cwd: "/tmp",
        pipePath: "\\\\.\\pipe\\aegis-nonexistent-test-pipe-12345",
      }),
    ).rejects.toThrow(AegisEnforcementError);
  });

  it("includes a meaningful message on connection failure", async () => {
    await expect(
      redeemCookie({
        cookie: "test-cookie",
        toolName: "system.run",
        args: "echo hello",
        pipePath: "\\\\.\\pipe\\aegis-nonexistent-test-pipe-12345",
      }),
    ).rejects.toThrow(/Aegis daemon/);
  });
});

// ---------------------------------------------------------------------------
// translateEnvelopeToPolicy — pure function, thorough coverage
// ---------------------------------------------------------------------------

describe("translateEnvelopeToPolicy", () => {
  it("returns a minimal policy with version for an empty envelope", () => {
    const policy = translateEnvelopeToPolicy({});
    expect(policy.version).toBe("0.5.0-alpha");
    expect(policy.timeoutMs).toBeUndefined();
    expect(policy.network).toBeUndefined();
    expect(policy.filesystem).toBeUndefined();
  });

  it("converts timeoutSeconds to timeoutMs", () => {
    const policy = translateEnvelopeToPolicy({ timeoutSeconds: 30 });
    expect(policy.timeoutMs).toBe(30_000);
  });

  it("converts fractional timeoutSeconds", () => {
    const policy = translateEnvelopeToPolicy({ timeoutSeconds: 1.5 });
    expect(policy.timeoutMs).toBe(1500);
  });

  it("omits timeoutMs when timeoutSeconds is 0", () => {
    const policy = translateEnvelopeToPolicy({ timeoutSeconds: 0 });
    expect(policy.timeoutMs).toBeUndefined();
  });

  it("omits timeoutMs when timeoutSeconds is negative", () => {
    const policy = translateEnvelopeToPolicy({ timeoutSeconds: -5 });
    expect(policy.timeoutMs).toBeUndefined();
  });

  it("omits timeoutMs when timeoutSeconds is undefined", () => {
    const policy = translateEnvelopeToPolicy({ timeoutSeconds: undefined });
    expect(policy.timeoutMs).toBeUndefined();
  });

  // -- network --

  it("maps networkEnabled to network.allowOutbound", () => {
    const policy = translateEnvelopeToPolicy({ networkEnabled: true });
    expect(policy.network).toEqual({
      allowOutbound: true,
      allowLocalNetwork: false,
    });
  });

  it("defaults allowOutbound to false when only allowLocalNetwork is set", () => {
    const policy = translateEnvelopeToPolicy({ allowLocalNetwork: true });
    expect(policy.network).toEqual({
      allowOutbound: false,
      allowLocalNetwork: true,
    });
  });

  it("sets both network flags", () => {
    const policy = translateEnvelopeToPolicy({
      networkEnabled: true,
      allowLocalNetwork: true,
    });
    expect(policy.network).toEqual({
      allowOutbound: true,
      allowLocalNetwork: true,
    });
  });

  it("omits network when neither networkEnabled nor allowLocalNetwork is set", () => {
    const policy = translateEnvelopeToPolicy({ timeoutSeconds: 10 });
    expect(policy.network).toBeUndefined();
  });

  it("includes network when networkEnabled is explicitly false", () => {
    const policy = translateEnvelopeToPolicy({ networkEnabled: false });
    expect(policy.network).toEqual({
      allowOutbound: false,
      allowLocalNetwork: false,
    });
  });

  // -- filesystem --

  it("maps deniedPaths to filesystem.deniedPaths", () => {
    const policy = translateEnvelopeToPolicy({ deniedPaths: ["/secrets"] });
    expect(policy.filesystem?.deniedPaths).toEqual(["/secrets"]);
    expect(policy.filesystem?.readonlyPaths).toBeUndefined();
    expect(policy.filesystem?.readwritePaths).toBeUndefined();
  });

  it("maps readonlyPaths to filesystem.readonlyPaths", () => {
    const policy = translateEnvelopeToPolicy({ readonlyPaths: ["/usr"] });
    expect(policy.filesystem?.readonlyPaths).toEqual(["/usr"]);
  });

  it("maps readwritePaths to filesystem.readwritePaths", () => {
    const policy = translateEnvelopeToPolicy({ readwritePaths: ["/workspace"] });
    expect(policy.filesystem?.readwritePaths).toEqual(["/workspace"]);
  });

  it("includes all filesystem arrays when all are provided", () => {
    const envelope: AegisExecutionEnvelope = {
      deniedPaths: ["/secrets"],
      readonlyPaths: ["/usr"],
      readwritePaths: ["/workspace"],
    };
    const policy = translateEnvelopeToPolicy(envelope);
    expect(policy.filesystem).toEqual({
      deniedPaths: ["/secrets"],
      readonlyPaths: ["/usr"],
      readwritePaths: ["/workspace"],
    });
  });

  it("omits filesystem when all path arrays are empty", () => {
    const policy = translateEnvelopeToPolicy({
      deniedPaths: [],
      readonlyPaths: [],
      readwritePaths: [],
    });
    expect(policy.filesystem).toBeUndefined();
  });

  it("omits filesystem when path arrays are undefined", () => {
    const policy = translateEnvelopeToPolicy({
      deniedPaths: undefined,
      readonlyPaths: undefined,
    });
    expect(policy.filesystem).toBeUndefined();
  });

  it("copies path arrays (does not alias input)", () => {
    const denied = ["/secrets"];
    const policy = translateEnvelopeToPolicy({ deniedPaths: denied });
    denied.push("/other");
    expect(policy.filesystem?.deniedPaths).toEqual(["/secrets"]);
  });

  // -- combined envelope --

  it("translates a full envelope correctly", () => {
    const envelope: AegisExecutionEnvelope = {
      timeoutSeconds: 60,
      networkEnabled: true,
      allowLocalNetwork: false,
      deniedPaths: ["/etc/shadow"],
      readonlyPaths: ["/usr/lib"],
      readwritePaths: ["/home/user/project"],
    };
    const policy = translateEnvelopeToPolicy(envelope);
    expect(policy).toEqual({
      version: "0.5.0-alpha",
      timeoutMs: 60_000,
      network: {
        allowOutbound: true,
        allowLocalNetwork: false,
      },
      filesystem: {
        deniedPaths: ["/etc/shadow"],
        readonlyPaths: ["/usr/lib"],
        readwritePaths: ["/home/user/project"],
      },
    });
  });
});
