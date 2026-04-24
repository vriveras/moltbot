import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import type { AegisAuditEmitter } from "./audit-emitter.js";
import type { AegisPluginConfig } from "./config.js";
import type { OpenClawActionPayload } from "./action-request.js";

export function registerAegisAfterHooks(
  api: OpenClawPluginApi,
  emitter: AegisAuditEmitter,
  getConfig: () => AegisPluginConfig,
): void {
  api.on("after_tool_call", async (event, ctx) => {
    try {
      const config = getConfig();
      if (config.enabled === false) return;

      const payload: OpenClawActionPayload = {
        toolName: event.toolName,
        params: event.params ?? {},
        agentId: ctx.agentId,
        sessionKey: ctx.sessionKey,
        sessionId: ctx.sessionId,
        runId: event.runId ?? ctx.runId,
        toolCallId: event.toolCallId ?? ctx.toolCallId,
        timestamp: new Date().toISOString(),
      };

      emitter.emitCompleted(payload, {
        error: event.error,
        durationMs: event.durationMs,
      });
    } catch (err) {
      console.warn(`[aegis] after_tool_call audit error: ${err}`);
    }
  });
}
