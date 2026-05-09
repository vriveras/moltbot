import type { OpenClawPluginService } from "openclaw/plugin-sdk/plugin-entry";

export function createAegisDaemonService(): OpenClawPluginService {
  return {
    id: "aegis-daemon",
    async start(ctx) {
      ctx.logger.info("Aegis running in CLI mode (no daemon)");
    },
    stop() {},
  };
}
