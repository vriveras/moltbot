import type { OpenClawPluginApi, OpenClawPluginService } from "openclaw/plugin-sdk/plugin-entry";
import { registerSandboxBackend } from "openclaw/plugin-sdk/sandbox";
import { getPlatformSupport } from "@microsoft/mxc-sdk";
import { resolveConfig } from "./config.js";
import { createMxcSandboxBackendFactory, mxcSandboxBackendManager } from "./mxc-backend.js";
import { resolveMxcBinaryPath } from "./binary-resolver.js";

export function registerMxcPlugin(api: OpenClawPluginApi): void {
  const config = resolveConfig(api.pluginConfig);

  if (!config.enabled) {
    return;
  }

  // Platform check — skip registration if unsupported
  const platform = getPlatformSupport();
  if (!platform.isSupported) {
    console.warn(
      `[mxc] Sandbox backend not available: ${platform.reason}. Extension will be dormant.`,
    );
    return;
  }

  // Binary check — fail fast if wxc-exec / lxc-exec not found
  try {
    resolveMxcBinaryPath(config.mxcBinaryPath);
  } catch (err) {
    console.warn(
      `[mxc] Binary not found: ${err instanceof Error ? err.message : err}. ` +
      `Install MXC or set mxcBinaryPath. Extension will be dormant.`,
    );
    return;
  }

  // Register the backend
  const unregister = registerSandboxBackend("mxc", {
    factory: createMxcSandboxBackendFactory(config),
    manager: mxcSandboxBackendManager,
  });

  // Cleanup service — unregisters backend on shutdown
  const cleanupService: OpenClawPluginService = {
    id: "mxc-sandbox-cleanup",
    start() { /* no-op */ },
    stop() {
      unregister();
    },
  };
  api.registerService(cleanupService);
}
