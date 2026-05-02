import { describe, expect, it, vi, beforeEach } from "vitest";
import {
  translateEnvelopeToPolicy,
  type AegisExecutionEnvelope,
} from "../shared/aegis-envelope.js";

vi.mock("../logger.js", () => ({
  logWarn: vi.fn(),
}));

/**
 * Red Team adversarial tests for OpenClaw Aegis enforcement layer.
 * Tests envelope translation, path injection, and policy bypass vectors.
 */
describe("Red Team: Envelope Field Injection via translateEnvelopeToPolicy", () => {
  // =========================================================================
  // ATTACK VECTOR 2: Path traversal in readwritePaths
  // =========================================================================

  it("passes path traversal sequences through unmodified", () => {
    const envelope: AegisExecutionEnvelope = {
      readwritePaths: [
        "C:\\workspace\\..\\..\\..\\Windows\\System32",
        "/home/user/../../../../etc/shadow",
      ],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    // FINDING: No path canonicalization — traversal sequences pass through
    expect(policy.filesystem?.readwritePaths).toContain(
      "C:\\workspace\\..\\..\\..\\Windows\\System32"
    );
    expect(policy.filesystem?.readwritePaths).toContain(
      "/home/user/../../../../etc/shadow"
    );
  });

  it("passes UNC paths through to MXC policy", () => {
    const envelope: AegisExecutionEnvelope = {
      readwritePaths: [
        "\\\\evil-server\\share\\payload",
        "\\\\?\\UNC\\evil.com\\c$",
        "\\\\.\\pipe\\some-pipe",
      ],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    expect(policy.filesystem?.readwritePaths).toHaveLength(3);
    expect(policy.filesystem?.readwritePaths).toContain("\\\\evil-server\\share\\payload");
  });

  it("passes null bytes in paths through unvalidated", () => {
    const envelope: AegisExecutionEnvelope = {
      readwritePaths: ["C:\\workspace\x00\\..\\Windows\\System32"],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    expect(policy.filesystem?.readwritePaths![0]).toContain("\x00");
  });

  it("passes Windows device paths through", () => {
    const envelope: AegisExecutionEnvelope = {
      readwritePaths: [
        "\\\\.\\PhysicalDrive0",
        "\\\\.\\C:",
        "\\\\.\\GLOBALROOT\\Device\\HarddiskVolume1",
      ],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    expect(policy.filesystem?.readwritePaths).toHaveLength(3);
  });

  it("passes NTFS Alternate Data Streams through", () => {
    const envelope: AegisExecutionEnvelope = {
      readwritePaths: ["C:\\workspace\\file.txt:hidden_payload"],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    expect(policy.filesystem?.readwritePaths).toContain(
      "C:\\workspace\\file.txt:hidden_payload"
    );
  });

  it("passes daemon named pipe path as readwritePath", () => {
    const envelope: AegisExecutionEnvelope = {
      readwritePaths: ["\\\\.\\pipe\\aegis-testuser"],
      networkEnabled: false,
    };
    const policy = translateEnvelopeToPolicy(envelope);

    // FINDING: Sandboxed process could access daemon pipe
    expect(policy.filesystem?.readwritePaths).toContain("\\\\.\\pipe\\aegis-testuser");
    expect(policy.network?.allowOutbound).toBe(false);
  });

  // =========================================================================
  // ATTACK VECTOR 5: 8.3 short names bypass deniedPaths
  // =========================================================================

  it("8.3 short names pass through without normalization", () => {
    const envelope: AegisExecutionEnvelope = {
      readwritePaths: ["C:\\PROGRA~1\\SECRET~1"],
      deniedPaths: ["C:\\Program Files\\SecretApp"],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    // FINDING: String comparison would not catch this equivalence
    expect(policy.filesystem?.readwritePaths).toContain("C:\\PROGRA~1\\SECRET~1");
    expect(policy.filesystem?.deniedPaths).toContain("C:\\Program Files\\SecretApp");
  });

  // =========================================================================
  // ATTACK VECTOR 9: Network bypass attempts
  // =========================================================================

  it("UNC in readwritePaths could bypass network=false", () => {
    const envelope: AegisExecutionEnvelope = {
      networkEnabled: false,
      readwritePaths: ["\\\\evil-server\\c$\\Windows\\System32"],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    // FINDING: Network is blocked but SMB access via UNC might still work
    // if BFS grants the UNC path access at the filesystem layer
    expect(policy.network?.allowOutbound).toBe(false);
    expect(policy.filesystem?.readwritePaths).toContain(
      "\\\\evil-server\\c$\\Windows\\System32"
    );
  });

  it("localhost UNC could access local services despite network=false", () => {
    const envelope: AegisExecutionEnvelope = {
      networkEnabled: false,
      allowLocalNetwork: false,
      readwritePaths: ["\\\\127.0.0.1\\admin$", "\\\\localhost\\c$"],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    expect(policy.network?.allowOutbound).toBe(false);
    expect(policy.network?.allowLocalNetwork).toBe(false);
    expect(policy.filesystem?.readwritePaths).toHaveLength(2);
  });

  // =========================================================================
  // ATTACK VECTOR 7: Environment variable manipulation via timeout
  // =========================================================================

  it("negative timeoutSeconds produces no timeout (infinite execution)", () => {
    const envelope: AegisExecutionEnvelope = {
      timeoutSeconds: -999,
    };
    const policy = translateEnvelopeToPolicy(envelope);

    // Negative timeout is treated as undefined — no timeout enforced
    expect(policy.timeoutMs).toBeUndefined();
  });

  it("zero timeoutSeconds means no timeout", () => {
    const envelope: AegisExecutionEnvelope = {
      timeoutSeconds: 0,
    };
    const policy = translateEnvelopeToPolicy(envelope);

    expect(policy.timeoutMs).toBeUndefined();
  });

  it("extremely large timeout essentially disables enforcement", () => {
    const envelope: AegisExecutionEnvelope = {
      timeoutSeconds: 999999999,
    };
    const policy = translateEnvelopeToPolicy(envelope);

    // ~31 years — effectively infinite
    expect(policy.timeoutMs).toBe(999999999000);
  });

  // =========================================================================
  // ATTACK VECTOR 4: Policy bypass via malformed envelope fields
  // =========================================================================

  it("empty string paths create filesystem policy entry", () => {
    const envelope: AegisExecutionEnvelope = {
      readwritePaths: ["", "   ", "\t\n"],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    // FINDING: Empty/whitespace paths are not filtered
    expect(policy.filesystem?.readwritePaths).toHaveLength(3);
    expect(policy.filesystem?.readwritePaths).toContain("");
  });

  it("very long paths accepted without limits", () => {
    const longPath = "C:\\" + "a".repeat(32000);
    const envelope: AegisExecutionEnvelope = {
      readwritePaths: [longPath],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    expect(policy.filesystem?.readwritePaths![0].length).toBeGreaterThan(32000);
  });

  it("special characters in paths pass through", () => {
    const envelope: AegisExecutionEnvelope = {
      readwritePaths: [
        "C:\\work space\\<>|\"*?",  // Invalid Windows path chars
        "/tmp/$(whoami)/pwned",     // Shell injection in path
        "/tmp/`id`/pwned",          // Backtick injection
      ],
    };
    const policy = translateEnvelopeToPolicy(envelope);

    expect(policy.filesystem?.readwritePaths).toHaveLength(3);
  });

  // =========================================================================
  // Defense verification: array isolation (no aliasing)
  // =========================================================================

  it("modifying input arrays does not affect policy (copy defense)", () => {
    const paths = ["/workspace"];
    const envelope: AegisExecutionEnvelope = { readwritePaths: paths };
    const policy = translateEnvelopeToPolicy(envelope);

    paths.push("/etc/shadow"); // Mutate original

    expect(policy.filesystem?.readwritePaths).toEqual(["/workspace"]);
    expect(policy.filesystem?.readwritePaths).not.toContain("/etc/shadow");
  });
});
