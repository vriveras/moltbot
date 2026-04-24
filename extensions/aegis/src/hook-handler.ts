import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import type { AegisIpcClient } from "./ipc-client.js";
import type { AegisAuditEmitter } from "./audit-emitter.js";
import type { AegisPluginConfig } from "./config.js";
import type { OpenClawActionPayload } from "./action-request.js";

export function registerAegisHooks(
  api: OpenClawPluginApi,
  getClient: () => AegisIpcClient,
  emitter: AegisAuditEmitter,
  getConfig: () => AegisPluginConfig,
): void {
  api.on("before_tool_call", async (event, ctx) => {
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

      const response = await getClient().decide(payload);

      emitter.emitRequested(payload);
      emitter.emitDecided(payload, response);

      if (response.action === "allow") {
        return {
          ...(response.modifiedParams ? { params: response.modifiedParams } : {}),
          block: false,
          executionMetadata: response.executionMetadata
            ? { ...response.executionMetadata }
            : undefined,
        };
      }

      if (response.action === "deny") {
        return {
          block: true,
          blockReason: response.reason ?? "Denied by Aegis policy",
        };
      }

      if (response.action === "require_approval") {
        return {
          requireApproval: {
            title:
              response.approvalTitle ??
              `Aegis: Approval required for ${event.toolName}`,
            description:
              response.approvalDescription ??
              `Policy requires approval: ${response.reason ?? "unknown"}\n\nTool: ${event.toolName}\nArgs: ${JSON.stringify(event.params)}`,
            severity:
              response.approvalSeverity ??
              config.approvalSeverity ??
              "warning",
            timeoutMs: config.approvalTimeoutMs ?? 1_800_000,
            timeoutBehavior: config.approvalTimeoutBehavior ?? "deny",
            onResolution: async (_resolution) => {
              // Approval resolution audit is handled by the approval bridge.
            },
          },
          executionMetadata: response.executionMetadata
            ? { ...response.executionMetadata }
            : undefined,
        };
      }
    } catch {
      return {
        block: true,
        blockReason: "Aegis extension error — fail-closed",
      };
    }
  });
}
