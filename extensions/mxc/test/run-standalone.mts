/**
 * Standalone test runner for MXC extension.
 * Runs all 24 test scenarios without vitest using Node's built-in test runner.
 *
 * Usage (from openclaw root):
 *   node --import tsx extensions/mxc/test/run-standalone.mts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

// ─── Module 1: config ────────────────────────────────────────────────────────

import { resolveConfig } from "../src/config.js";

describe("resolveConfig", () => {
  it("default config from empty/null input", () => {
    const config = resolveConfig(null);
    assert.strictEqual(config.enabled, true);
    assert.strictEqual(config.defaultContainment, "process");
    assert.strictEqual(config.debug, false);
    assert.strictEqual(config.mxcBinaryPath, undefined);
    assert.strictEqual(config.aegisPublicKeyPath, undefined);

    const config2 = resolveConfig({});
    assert.strictEqual(config2.enabled, true);
    assert.strictEqual(config2.defaultContainment, "process");
    assert.strictEqual(config2.debug, false);
  });

  it("all config overrides applied correctly", () => {
    const config = resolveConfig({
      enabled: false,
      mxcBinaryPath: "C:\\custom\\wxc-exec.exe",
      aegisPublicKeyPath: "C:\\keys\\aegis.pem",
      defaultContainment: "wslc",
      debug: true,
    });

    assert.strictEqual(config.enabled, false);
    assert.strictEqual(config.mxcBinaryPath, "C:\\custom\\wxc-exec.exe");
    assert.strictEqual(config.aegisPublicKeyPath, "C:\\keys\\aegis.pem");
    assert.strictEqual(config.defaultContainment, "wslc");
    assert.strictEqual(config.debug, true);
  });

  it("empty strings for paths are treated as undefined", () => {
    const config = resolveConfig({
      mxcBinaryPath: "   ",
      aegisPublicKeyPath: "",
    });
    assert.strictEqual(config.mxcBinaryPath, undefined);
    assert.strictEqual(config.aegisPublicKeyPath, undefined);
  });

  it("invalid containment value falls back to process", () => {
    const config = resolveConfig({ defaultContainment: "invalid" });
    assert.strictEqual(config.defaultContainment, "process");
  });
});

// ─── Module 2: envelope-translator ──────────────────────────────────────────

import { translateEnvelopeToPolicy } from "../src/envelope-translator.js";
import type { AegisExecutionEnvelope } from "../src/types.js";

describe("translateEnvelopeToPolicy", () => {
  it("full envelope → all SandboxPolicy fields populated", () => {
    const envelope: AegisExecutionEnvelope = {
      timeoutSeconds: 60,
      networkEnabled: true,
      allowLocalNetwork: true,
      deniedPaths: ["/etc/shadow"],
      readonlyPaths: ["/usr/lib"],
      readwritePaths: ["/tmp"],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    assert.strictEqual(policy.version, "0.5.0-alpha");
    assert.strictEqual(policy.timeoutMs, 60_000);
    assert.deepStrictEqual(policy.network, {
      allowOutbound: true,
      allowLocalNetwork: true,
    });
    assert.deepStrictEqual(policy.filesystem, {
      deniedPaths: ["/etc/shadow"],
      readonlyPaths: ["/usr/lib"],
      readwritePaths: ["/tmp"],
    });
  });

  it("empty envelope → minimal policy with version only", () => {
    const policy = translateEnvelopeToPolicy({});

    assert.strictEqual(policy.version, "0.5.0-alpha");
    assert.strictEqual(policy.timeoutMs, undefined);
    assert.strictEqual(policy.network, undefined);
    assert.strictEqual(policy.filesystem, undefined);
  });

  it("timeout conversion: seconds to milliseconds", () => {
    const policy = translateEnvelopeToPolicy({ timeoutSeconds: 30 });
    assert.strictEqual(policy.timeoutMs, 30_000);
  });

  it("timeout of 0 is omitted", () => {
    const policy = translateEnvelopeToPolicy({ timeoutSeconds: 0 });
    assert.strictEqual(policy.timeoutMs, undefined);
  });

  it("network flags default to false when not specified", () => {
    const policy = translateEnvelopeToPolicy({ networkEnabled: false });
    assert.deepStrictEqual(policy.network, {
      allowOutbound: false,
      allowLocalNetwork: false,
    });
  });

  it("filesystem paths are defensive copies", () => {
    const original = ["/tmp"];
    const policy = translateEnvelopeToPolicy({ readwritePaths: original });
    original.push("/var");
    assert.deepStrictEqual(policy.filesystem!.readwritePaths, ["/tmp"]);
  });
});

// ─── Module 3: ticket-bridge ─────────────────────────────────────────────────

import {
  extractExecutionContext,
  TicketVerificationError,
} from "../src/ticket-bridge.js";

describe("extractExecutionContext", () => {
  it("raw aegisEnvelope fallback → returns context", () => {
    const envelope: AegisExecutionEnvelope = {
      networkEnabled: true,
      timeoutSeconds: 30,
    };
    const ctx = extractExecutionContext({ aegisEnvelope: envelope });

    assert.deepStrictEqual(ctx.envelope, envelope);
    assert.strictEqual(ctx.ticketToolName, undefined);
    assert.strictEqual(ctx.ticketArgsHash, undefined);
  });

  it("aegisCookie only → throws with cookie redemption message", () => {
    assert.throws(
      () => extractExecutionContext({ aegisCookie: "cookie-abc" }),
      (err: unknown) => {
        assert.ok(err instanceof TicketVerificationError);
        assert.ok(/cookie redemption/i.test((err as Error).message));
        return true;
      },
    );
  });

  it("empty metadata → throws TicketVerificationError with expected message", () => {
    assert.throws(
      () => extractExecutionContext({}),
      (err: unknown) => {
        assert.ok(err instanceof TicketVerificationError);
        assert.ok(
          /No aegisSignedTicket or aegisEnvelope/.test(
            (err as Error).message,
          ),
        );
        return true;
      },
    );
  });

  it("invalid signed ticket → throws TicketVerificationError", () => {
    // verifyTicket will return {valid:false, error:...} for a bogus signature
    assert.throws(
      () =>
        extractExecutionContext({
          aegisSignedTicket: {
            ticket: "dGVzdA==",
            signature: "bad",
            publicKey: "a2V5",
          },
        }),
      (err: unknown) => {
        assert.ok(err instanceof TicketVerificationError);
        return true;
      },
    );
  });
});

// ─── Module 4: mxc-backend ──────────────────────────────────────────────────

import {
  createMxcSandboxBackendHandle,
  mxcSandboxBackendManager,
} from "../src/mxc-backend.js";

describe("createMxcSandboxBackendHandle", () => {
  const baseParams = {
    binaryPath: "C:\\test\\wxc-exec.exe",
    config: {
      enabled: true,
      defaultContainment: "process" as const,
      debug: false,
    },
    runtimeId: "session-1-scope-1",
    workdir: "C:\\workspace",
  };

  it("buildExecSpec with aegisEnvelope metadata → argv has config-base64", async () => {
    const handle = createMxcSandboxBackendHandle(baseParams);
    const spec = await handle.buildExecSpec({
      command: "echo hello",
      env: {},
      usePty: false,
      executionMetadata: { aegisEnvelope: { timeoutSeconds: 30 } },
    });

    assert.strictEqual(spec.argv[0], "C:\\test\\wxc-exec.exe");
    assert.strictEqual(spec.argv[1], "--config-base64");
    assert.strictEqual(spec.argv.length, 3);
    // Third element should be valid base64
    assert.doesNotThrow(() => Buffer.from(spec.argv[2], "base64"));
    assert.strictEqual(spec.stdinMode, "pipe-closed");
  });

  it("buildExecSpec without metadata → throws", async () => {
    const handle = createMxcSandboxBackendHandle(baseParams);
    await assert.rejects(
      () =>
        handle.buildExecSpec({
          command: "echo hello",
          env: {},
          usePty: false,
        }),
      (err: unknown) => {
        assert.ok(/executionMetadata/.test((err as Error).message));
        return true;
      },
    );
  });

  it("buildExecSpec with debug=true → argv includes --debug", async () => {
    const handle = createMxcSandboxBackendHandle({
      ...baseParams,
      config: { ...baseParams.config, debug: true },
    });
    const spec = await handle.buildExecSpec({
      command: "echo hello",
      env: {},
      usePty: false,
      executionMetadata: { aegisEnvelope: { timeoutSeconds: 30 } },
    });

    assert.ok(spec.argv.includes("--debug"));
  });

  it("handle has correct id, runtimeId, workdir, runtimeLabel", () => {
    const handle = createMxcSandboxBackendHandle(baseParams);
    assert.strictEqual(handle.id, "mxc");
    assert.strictEqual(handle.runtimeId, "session-1-scope-1");
    assert.strictEqual(handle.workdir, "C:\\workspace");
    assert.strictEqual(handle.runtimeLabel, "mxc-session-1-scope-1");
  });

  it("usePty=true → stdinMode is pipe-open", async () => {
    const handle = createMxcSandboxBackendHandle(baseParams);
    const spec = await handle.buildExecSpec({
      command: "bash",
      env: {},
      usePty: true,
      executionMetadata: { aegisEnvelope: { timeoutSeconds: 30 } },
    });

    assert.strictEqual(spec.stdinMode, "pipe-open");
  });
});

describe("mxcSandboxBackendManager", () => {
  it("describeRuntime returns running=true", async () => {
    const info = await mxcSandboxBackendManager.describeRuntime({
      entry: {} as never,
      config: {} as never,
    });
    assert.strictEqual(info.running, true);
    assert.strictEqual(info.configLabelMatch, true);
  });

  it("removeRuntime completes without error", async () => {
    const result = await mxcSandboxBackendManager.removeRuntime({
      entry: {} as never,
      config: {} as never,
    });
    assert.strictEqual(result, undefined);
  });
});

// ─── Module 5: binary-resolver ───────────────────────────────────────────────

import { resolveMxcBinaryPath } from "../src/binary-resolver.js";

describe("resolveMxcBinaryPath", () => {
  it("config override with existing file → returns that path", () => {
    // process.execPath is guaranteed to exist (it's the node binary)
    const result = resolveMxcBinaryPath(process.execPath);
    assert.strictEqual(result, process.execPath);
  });

  it("config override with non-existing path → throws /not found at configured path/", () => {
    assert.throws(
      () => resolveMxcBinaryPath("C:\\nonexistent\\wxc-exec.exe"),
      (err: unknown) => {
        assert.ok(/not found at configured path/.test((err as Error).message));
        return true;
      },
    );
  });

  it("no override with no binary installed → throws /not found/", () => {
    assert.throws(
      () => resolveMxcBinaryPath(),
      (err: unknown) => {
        assert.ok(/not found/.test((err as Error).message));
        return true;
      },
    );
  });
});
