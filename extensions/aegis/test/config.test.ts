import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolve as pathResolve } from "node:path";

import { resolveConfig, DEFAULT_CONFIG } from "../src/config.js";

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  warnSpy.mockRestore();
});

// ---------------------------------------------------------------------------
// H5 – aegisBinaryPath (shell-injection guard)
// ---------------------------------------------------------------------------
describe("H5: aegisBinaryPath validation", () => {
  it("accepts a valid path", () => {
    const cfg = resolveConfig({ aegisBinaryPath: "/usr/bin/aegis" });
    expect(cfg.aegisBinaryPath).toBe("/usr/bin/aegis");
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("rejects an empty string", () => {
    const cfg = resolveConfig({ aegisBinaryPath: "" });
    expect(cfg.aegisBinaryPath).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("empty"));
  });

  it("rejects a whitespace-only string", () => {
    const cfg = resolveConfig({ aegisBinaryPath: "   " });
    expect(cfg.aegisBinaryPath).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("empty"));
  });

  it.each([
    [";", "aegis;rm -rf /"],
    ["|", "aegis|cat"],
    ["&", "cmd&whoami"],
    ["$", "$HOME/aegis"],
    ["`", "aegis`id`"],
  ])("rejects shell metacharacter '%s'", (_char, path) => {
    const cfg = resolveConfig({ aegisBinaryPath: path });
    expect(cfg.aegisBinaryPath).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("metacharacters"));
  });
});

// ---------------------------------------------------------------------------
// H4 – auditLogPath (path-traversal guard)
// ---------------------------------------------------------------------------
describe("H4: auditLogPath validation", () => {
  it("accepts a valid relative path and resolves it", () => {
    const cfg = resolveConfig({ auditLogPath: ".aegis/events.jsonl" });
    expect(cfg.auditLogPath).toBe(pathResolve(".aegis/events.jsonl"));
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("rejects a leading '..' traversal", () => {
    const cfg = resolveConfig({ auditLogPath: "../../../etc/shadow" });
    expect(cfg.auditLogPath).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("'..'"));
  });

  it("rejects '..' in the middle of the path", () => {
    const cfg = resolveConfig({ auditLogPath: ".aegis/../../../etc/passwd" });
    expect(cfg.auditLogPath).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("'..'"));
  });

  it("rejects Windows-style '..' traversal", () => {
    const cfg = resolveConfig({ auditLogPath: ".aegis\\..\\..\\etc\\passwd" });
    expect(cfg.auditLogPath).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("'..'"));
  });
});

// ---------------------------------------------------------------------------
// C3 – redact pattern migration
// ---------------------------------------------------------------------------
describe("C3: redact pattern migration", () => {
  it("migrates legacy redactPatterns to redactKeyPatterns", () => {
    const cfg = resolveConfig({ redactPatterns: ["password"] });
    expect(cfg.redactKeyPatterns).toEqual(["password"]);
  });

  it("gives explicit redactKeyPatterns priority over legacy", () => {
    const cfg = resolveConfig({
      redactPatterns: ["old"],
      redactKeyPatterns: ["new"],
    });
    expect(cfg.redactKeyPatterns).toEqual(["new"]);
  });

  it("keeps redactValuePatterns separate from key patterns", () => {
    const cfg = resolveConfig({ redactValuePatterns: ["Bearer .*"] });
    expect(cfg.redactValuePatterns).toEqual(["Bearer .*"]);
    expect(cfg.redactKeyPatterns).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Defaults and type coercion
// ---------------------------------------------------------------------------
describe("defaults and type coercion", () => {
  it("returns DEFAULT_CONFIG values for null input", () => {
    const cfg = resolveConfig(null);
    expect(cfg.enabled).toBe(DEFAULT_CONFIG.enabled);
    expect(cfg.failBehavior).toBe(DEFAULT_CONFIG.failBehavior);
    expect(cfg.approvalTimeoutMs).toBe(DEFAULT_CONFIG.approvalTimeoutMs);
    expect(cfg.approvalSeverity).toBe(DEFAULT_CONFIG.approvalSeverity);
  });

  it("returns DEFAULT_CONFIG values for non-object input", () => {
    const cfg = resolveConfig("not-an-object");
    expect(cfg.enabled).toBe(DEFAULT_CONFIG.enabled);
    expect(cfg.failBehavior).toBe(DEFAULT_CONFIG.failBehavior);
  });

  it("uses default for invalid failBehavior", () => {
    const cfg = resolveConfig({ failBehavior: "crash" });
    expect(cfg.failBehavior).toBe(DEFAULT_CONFIG.failBehavior);
  });

  it("uses default for invalid approvalSeverity", () => {
    const cfg = resolveConfig({ approvalSeverity: "extreme" });
    expect(cfg.approvalSeverity).toBe(DEFAULT_CONFIG.approvalSeverity);
  });

  it("uses default for non-number approvalTimeoutMs", () => {
    const cfg = resolveConfig({ approvalTimeoutMs: "fast" });
    expect(cfg.approvalTimeoutMs).toBe(DEFAULT_CONFIG.approvalTimeoutMs);
  });

  it("respects enabled: false", () => {
    const cfg = resolveConfig({ enabled: false });
    expect(cfg.enabled).toBe(false);
  });
});
