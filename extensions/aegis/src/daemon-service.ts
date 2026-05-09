import { spawn } from "node:child_process";
import type { OpenClawPluginService } from "openclaw/plugin-sdk/plugin-entry";
import type { AegisPluginConfig } from "./config.js";
import type { AegisIpcClient } from "./ipc-client.js";
import { DEFAULT_HEALTH_CHECK_INTERVAL_MS } from "./constants.js";
import { resolveBundledAegisBinary } from "./binary-resolver.js";

export type AegisDaemonServiceOptions = {
  config: AegisPluginConfig;
};

export function createAegisDaemonService(
  getConfig: () => AegisPluginConfig,
  getClient: () => AegisIpcClient,
): OpenClawPluginService {
  let healthCheckInterval: ReturnType<typeof setInterval> | undefined;

  return {
    id: "aegis-daemon",

    async start(ctx) {
      ctx.logger.info("Aegis daemon service starting");

      const config = getConfig();
      const client = getClient();

      const alreadyRunning = await client.healthCheck();
      if (!alreadyRunning) {
        const binaryPath = config.aegisBinaryPath ?? resolveBundledAegisBinary() ?? "aegis";

        // Validate binary path
        if (binaryPath.includes("..") || /[;&|$`]/.test(binaryPath)) {
          ctx.logger.warn(`Aegis binary path rejected (suspicious characters): ${binaryPath}`);
          return;
        }

        try {
          const child = spawn(binaryPath, ["--daemon"], {
            detached: true,
            stdio: "ignore",
          });
          // Handle async spawn errors (e.g., ENOENT) to prevent uncaught exceptions
          child.on("error", (err) => {
            ctx.logger.warn(`Failed to spawn aegis daemon: ${err.message}`);
          });
          child.unref();
        } catch (err) {
          ctx.logger.warn(`Failed to spawn aegis daemon: ${err instanceof Error ? err.message : String(err)}`);
        }

        // Poll for daemon readiness up to 3 seconds
        const pollIntervalMs = 500;
        const maxWaitMs = 3_000;
        let elapsed = 0;
        let reachable = false;
        while (elapsed < maxWaitMs) {
          await new Promise<void>((r) => setTimeout(r, pollIntervalMs));
          elapsed += pollIntervalMs;
          reachable = await client.healthCheck();
          if (reachable) break;
        }

        if (!reachable) {
          const failBehavior = config.failBehavior ?? "allow";
          ctx.logger.warn(
            `Aegis daemon not reachable after 3s — IPC calls will fail-${failBehavior === "deny" ? "closed" : "open"}`,
          );
        }
      }

      const intervalMs =
        config.healthCheckIntervalMs ?? DEFAULT_HEALTH_CHECK_INTERVAL_MS;
      healthCheckInterval = setInterval(async () => {
        try {
          const ok = await client.healthCheck();
          if (!ok) {
            ctx.logger.warn("Aegis daemon not reachable — restarting");
            try {
              const restartPath = config.aegisBinaryPath ?? resolveBundledAegisBinary() ?? "aegis";
              const child = spawn(restartPath, ["--daemon"], { detached: true, stdio: "ignore" });
              child.on("error", () => {});
              child.unref();
            } catch { /* best effort */ }
          }
        } catch (err) {
          ctx.logger.warn(`Aegis daemon health check error: ${err}`);
        }
      }, intervalMs);
    },

    stop(ctx) {
      if (healthCheckInterval != null) {
        clearInterval(healthCheckInterval);
        healthCheckInterval = undefined;
      }
      ctx.logger.info("Aegis daemon service stopped");
    },
  };
}
