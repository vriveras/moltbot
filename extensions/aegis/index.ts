import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerAegisPlugin } from "./src/plugin.js";

export default definePluginEntry({
  id: "aegis",
  name: "Aegis Governance",
  description:
    "Runtime governance for OpenClaw tool execution — policy-as-code, audit trail, and approval workflows powered by Aegis.",
  register: registerAegisPlugin,
});
