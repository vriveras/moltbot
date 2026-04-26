import { describe, expect, test } from "vitest";
import { translateEnvelopeToPolicy } from "../src/envelope-translator.js";
import type { AegisExecutionEnvelope } from "../src/types.js";

describe("translateEnvelopeToPolicy", () => {
  test("full envelope → all SandboxPolicy fields populated", () => {
    const envelope: AegisExecutionEnvelope = {
      timeoutSeconds: 60,
      networkEnabled: true,
      allowLocalNetwork: true,
      deniedPaths: ["/etc/shadow"],
      readonlyPaths: ["/usr/lib"],
      readwritePaths: ["/tmp"],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    expect(policy.version).toBe("0.5.0-alpha");
    expect(policy.timeoutMs).toBe(60_000);
    expect(policy.network).toEqual({
      allowOutbound: true,
      allowLocalNetwork: true,
    });
    expect(policy.filesystem).toEqual({
      deniedPaths: ["/etc/shadow"],
      readonlyPaths: ["/usr/lib"],
      readwritePaths: ["/tmp"],
    });
  });

  test("empty envelope → minimal policy with version only", () => {
    const policy = translateEnvelopeToPolicy({});

    expect(policy.version).toBe("0.5.0-alpha");
    expect(policy.timeoutMs).toBeUndefined();
    expect(policy.network).toBeUndefined();
    expect(policy.filesystem).toBeUndefined();
  });

  test("timeout conversion: seconds to milliseconds", () => {
    const policy = translateEnvelopeToPolicy({ timeoutSeconds: 30 });
    expect(policy.timeoutMs).toBe(30_000);
  });

  test("timeout of 0 is omitted", () => {
    const policy = translateEnvelopeToPolicy({ timeoutSeconds: 0 });
    expect(policy.timeoutMs).toBeUndefined();
  });

  test("network flags default to false when not specified", () => {
    const policy = translateEnvelopeToPolicy({ networkEnabled: false });
    expect(policy.network).toEqual({
      allowOutbound: false,
      allowLocalNetwork: false,
    });
  });

  test("filesystem paths are defensive copies", () => {
    const original = ["/tmp"];
    const policy = translateEnvelopeToPolicy({ readwritePaths: original });
    original.push("/var");
    expect(policy.filesystem!.readwritePaths).toEqual(["/tmp"]);
  });
});
