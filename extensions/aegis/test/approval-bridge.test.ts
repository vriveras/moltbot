import { describe, expect, test, vi } from "vitest";
import {
  buildApprovalRequest,
  handleApprovalResolution,
} from "../src/approval-bridge.js";
import type { AegisPluginConfig } from "../src/config.js";

// --- Helpers ---

function makeConfig(overrides?: Partial<AegisPluginConfig>): AegisPluginConfig {
  return {
    enabled: true,
    ...overrides,
  };
}

// --- Tests ---

describe("buildApprovalRequest", () => {
  // 1. Output fields
  test("produces correct title, description, severity, timeoutMs, and timeoutBehavior", () => {
    const result = buildApprovalRequest(
      "bash",
      { command: "rm -rf /" },
      "dangerous command",
      makeConfig({
        approvalSeverity: "critical",
        approvalTimeoutMs: 60_000,
        approvalTimeoutBehavior: "allow",
      }),
    );

    expect(result.title).toBe("Aegis: Approval required for bash");
    expect(result.description).toContain("Policy reason: dangerous command");
    expect(result.description).toContain("Tool: bash");
    expect(result.description).toContain('"command":"rm -rf /"');
    expect(result.severity).toBe("critical");
    expect(result.timeoutMs).toBe(60_000);
    expect(result.timeoutBehavior).toBe("allow");
  });

  // 2. Redaction
  test("redacts args whose keys match redactKeyPatterns", () => {
    const result = buildApprovalRequest(
      "bash",
      { password: "s3cret", apiKey: "abc-123", safe: "visible" },
      "needs review",
      makeConfig({ redactKeyPatterns: ["password", "key"] }),
    );

    expect(result.description).toContain("[REDACTED]");
    expect(result.description).not.toContain("s3cret");
    expect(result.description).not.toContain("abc-123");
    expect(result.description).toContain("visible");
  });

  // 3. Default values
  test("uses default severity, timeoutMs, and timeoutBehavior when config omits them", () => {
    const result = buildApprovalRequest(
      "write_file",
      { path: "/etc/hosts" },
      "policy check",
      makeConfig(),
    );

    expect(result.severity).toBe("warning");
    expect(result.timeoutMs).toBe(1_800_000);
    expect(result.timeoutBehavior).toBe("deny");
  });

  // 4. Empty redactKeyPatterns — no redaction
  test("does not redact when redactKeyPatterns is empty", () => {
    const result = buildApprovalRequest(
      "bash",
      { secret: "visible-value" },
      "check",
      makeConfig({ redactKeyPatterns: [] }),
    );

    expect(result.description).toContain("visible-value");
  });

  // 5. Redaction is case-insensitive on key matching
  test("redaction pattern matching is case-insensitive", () => {
    const result = buildApprovalRequest(
      "bash",
      { Password: "hidden", API_KEY: "also-hidden", normal: "ok" },
      "check",
      makeConfig({ redactKeyPatterns: ["password", "key"] }),
    );

    expect(result.description).not.toContain("hidden");
    expect(result.description).not.toContain("also-hidden");
    expect(result.description).toContain("ok");
  });

  // 6. Empty args produces valid description
  test("handles empty args object gracefully", () => {
    const result = buildApprovalRequest(
      "noop",
      {},
      "no args",
      makeConfig(),
    );

    expect(result.description).toContain("Args: {}");
    expect(result.title).toBe("Aegis: Approval required for noop");
  });

  // 6b. Oversized redact value pattern is skipped
  test("skips oversized redact value patterns exceeding 500 chars", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const oversizedPattern = "a".repeat(501);
    const result = buildApprovalRequest(
      "bash",
      { command: "echo hello" },
      "check",
      makeConfig({ redactValuePatterns: [oversizedPattern] }),
    );

    expect(result).toBeDefined();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("Skipping oversized redact pattern"),
    );
    warnSpy.mockRestore();
  });
});

describe("handleApprovalResolution", () => {
  // 7. allow-once with cookie
  test("allow-once returns proceed:true with pre-issued cookie", () => {
    const result = handleApprovalResolution("allow-once", "cookie-abc");

    expect(result).toEqual({ proceed: true, cookie: "cookie-abc" });
  });

  // 8. allow-always with cookie
  test("allow-always returns proceed:true with pre-issued cookie", () => {
    const result = handleApprovalResolution("allow-always", "cookie-xyz");

    expect(result).toEqual({ proceed: true, cookie: "cookie-xyz" });
  });

  // 9. deny
  test("deny returns proceed:false", () => {
    const result = handleApprovalResolution("deny", "cookie-ignored");

    expect(result).toEqual({ proceed: false });
  });

  // 10. timeout
  test("timeout returns proceed:false", () => {
    const result = handleApprovalResolution("timeout", "cookie-ignored");

    expect(result).toEqual({ proceed: false });
  });

  // 11. cancelled
  test("cancelled returns proceed:false", () => {
    const result = handleApprovalResolution("cancelled", undefined);

    expect(result).toEqual({ proceed: false });
  });

  // 12. unknown value — fail-closed
  test("unknown resolution string returns proceed:false (fail-closed)", () => {
    const result = handleApprovalResolution("something-unexpected", "cookie-x");

    expect(result).toEqual({ proceed: false });
  });

  // 13. No cookie on approval — proceed:true with undefined cookie
  test("allow-once with undefined cookie returns proceed:true and cookie:undefined", () => {
    const result = handleApprovalResolution("allow-once", undefined);

    expect(result).toEqual({ proceed: true, cookie: undefined });
  });

  // 14. allow-always with undefined cookie
  test("allow-always with undefined cookie returns proceed:true and cookie:undefined", () => {
    const result = handleApprovalResolution("allow-always", undefined);

    expect(result).toEqual({ proceed: true, cookie: undefined });
  });
});
