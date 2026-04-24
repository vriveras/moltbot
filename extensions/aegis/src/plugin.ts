import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import { resolveConfig } from "./config.js";
import { AegisIpcClient } from "./ipc-client.js";
import { AegisAuditEmitter } from "./audit-emitter.js";
import { registerAegisHooks } from "./hook-handler.js";
import { registerAegisAfterHooks } from "./after-hook-handler.js";
import { createAegisDaemonService } from "./daemon-service.js";

export function registerAegisPlugin(api: OpenClawPluginApi): void {
  const getConfig = () => resolveConfig(api.pluginConfig);
  const config = getConfig();

  const client = new AegisIpcClient({
    aegisBinaryPath: config.aegisBinaryPath ?? "aegis",
  });
  const getClient = () => client;

  const emitter = new AegisAuditEmitter({
    auditLogPath: config.auditLogPath,
    redactPatterns: config.redactPatterns,
  });

  registerAegisHooks(api, getClient, emitter, getConfig);
  registerAegisAfterHooks(api, emitter, getConfig);

  const daemonService = createAegisDaemonService(getConfig, getClient);
  api.registerService(daemonService);
}
