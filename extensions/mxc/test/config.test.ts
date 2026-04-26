import { describe, expect, test } from "vitest";
import { resolveConfig } from "../src/config.js";

describe("resolveConfig", () => {
  test("default config from empty/null input", () => {
    const config = resolveConfig(null);
    expect(config).toEqual({
      enabled: true,
      mxcBinaryPath: undefined,
      aegisPublicKeyPath: undefined,
      defaultContainment: "process",
      debug: false,
    });

    const config2 = resolveConfig({});
    expect(config2.enabled).toBe(true);
    expect(config2.defaultContainment).toBe("process");
    expect(config2.debug).toBe(false);
  });

  test("all config overrides applied correctly", () => {
    const config = resolveConfig({
      enabled: false,
      mxcBinaryPath: "C:\\custom\\wxc-exec.exe",
      aegisPublicKeyPath: "C:\\keys\\aegis.pem",
      defaultContainment: "wslc",
      debug: true,
    });

    expect(config.enabled).toBe(false);
    expect(config.mxcBinaryPath).toBe("C:\\custom\\wxc-exec.exe");
    expect(config.aegisPublicKeyPath).toBe("C:\\keys\\aegis.pem");
    expect(config.defaultContainment).toBe("wslc");
    expect(config.debug).toBe(true);
  });

  test("empty strings for paths are treated as undefined", () => {
    const config = resolveConfig({
      mxcBinaryPath: "   ",
      aegisPublicKeyPath: "",
    });
    expect(config.mxcBinaryPath).toBeUndefined();
    expect(config.aegisPublicKeyPath).toBeUndefined();
  });

  test("invalid containment value falls back to process", () => {
    const config = resolveConfig({ defaultContainment: "invalid" });
    expect(config.defaultContainment).toBe("process");
  });
});
