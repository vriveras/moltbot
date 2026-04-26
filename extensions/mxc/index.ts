import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerMxcPlugin } from "./src/plugin.js";

export default definePluginEntry({
  id: "mxc",
  name: "MXC Sandbox Execution",
  description:
    "OS-level sandboxed tool execution via MXC — enforces Aegis policy constraints with AppContainer (Windows) and LXC (Linux).",
  register: registerMxcPlugin,
});
