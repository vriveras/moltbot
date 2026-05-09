import type {
  OpenClawPluginApi,
  OpenClawPluginService,
} from "openclaw/plugin-sdk/plugin-entry";
import { resolveConfig } from "./config.js";
import { AegisIpcClient } from "./ipc-client.js";
import { AegisAuditEmitter } from "./audit-emitter.js";
import { registerAegisHooks } from "./hook-handler.js";
import { registerAegisAfterHooks } from "./after-hook-handler.js";
import { createAegisDaemonService } from "./daemon-service.js";
import { DEFAULT_FAIL_BEHAVIOR } from "./constants.js";
import { resolveBundledAegisBinary } from "./binary-resolver.js";

export function registerAegisPlugin(api: OpenClawPluginApi): void {
  const getConfig = () => resolveConfig(api.pluginConfig);
  const config = getConfig();

  const client = new AegisIpcClient({
    aegisBinaryPath: config.aegisBinaryPath ?? resolveBundledAegisBinary() ?? "aegis",
    failBehavior: config.failBehavior,
    getFailBehavior: () => getConfig().failBehavior ?? DEFAULT_FAIL_BEHAVIOR,
  });
  const getClient = () => client;

  const emitter = new AegisAuditEmitter({
    auditLogPath: config.auditLogPath,
    redactKeyPatterns: config.redactKeyPatterns,
    redactValuePatterns: config.redactValuePatterns,
  });

  registerAegisHooks(api, getClient, emitter, getConfig);
  registerAegisAfterHooks(api, emitter, getConfig);

  const daemonService = createAegisDaemonService();
  api.registerService(daemonService);

  // Register cleanup service for client and emitter
  const cleanupService: OpenClawPluginService = {
    id: "aegis-cleanup",
    start() {
      // No startup action needed
    },
    stop(ctx) {
      ctx.logger.info("Aegis cleanup service stopping");
      client.dispose();
      emitter.dispose();
    },
  };
  api.registerService(cleanupService);
}
