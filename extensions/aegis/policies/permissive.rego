package aegis

# =============================================================================
# Permissive Policy
# =============================================================================
# Allow most tool calls by default, but deny known-dangerous operations and
# require human approval for sensitive actions like network access.
#
# Good for development and trusted environments where you want guardrails
# without blocking common workflows.
# =============================================================================

# Permissive default — allow unless a deny or ask rule matches
default result = {
    "decision": "allow",
    "reason": "permissive policy — allowed by default"
}

# ---------------------------------------------------------------------------
# Deny rules — block known-dangerous operations
# ---------------------------------------------------------------------------

# Deny destructive shell commands: rm -rf
result = {"decision": "deny", "reason": "destructive command blocked: rm -rf"} {
    input.action.name == "bash"
    contains(input.action.args.command, "rm -rf")
}

# Deny destructive shell commands: format
result = {"decision": "deny", "reason": "destructive command blocked: format"} {
    input.action.name == "bash"
    contains(input.action.args.command, "format ")
}

# Deny destructive shell commands: dd (raw disk writes)
result = {"decision": "deny", "reason": "destructive command blocked: dd"} {
    input.action.name == "bash"
    contains(input.action.args.command, "dd if=")
}

# Deny destructive shell commands: mkfs (filesystem creation)
result = {"decision": "deny", "reason": "destructive command blocked: mkfs"} {
    input.action.name == "bash"
    contains(input.action.args.command, "mkfs")
}

# Deny shell commands that modify critical system files
result = {"decision": "deny", "reason": "system file modification blocked"} {
    input.action.name == "bash"
    contains(input.action.args.command, "/etc/passwd")
}

# Deny PowerShell destructive commands: Remove-Item -Recurse -Force
result = {"decision": "deny", "reason": "destructive command blocked: recursive delete"} {
    input.action.name == "powershell"
    contains(input.action.args.command, "Remove-Item")
    contains(input.action.args.command, "-Recurse")
    contains(input.action.args.command, "-Force")
}

# ---------------------------------------------------------------------------
# Ask rules — require human approval for sensitive operations
# ---------------------------------------------------------------------------

# Require approval for network access (web fetches)
result = {"decision": "ask", "reason": "network access requires approval"} {
    input.action.name == "web_fetch"
}

# Require approval for running arbitrary shell commands with curl
result = {"decision": "ask", "reason": "outbound network request requires approval"} {
    input.action.name == "bash"
    contains(input.action.args.command, "curl ")
}

# Require approval for running arbitrary shell commands with wget
result = {"decision": "ask", "reason": "outbound network request requires approval"} {
    input.action.name == "bash"
    contains(input.action.args.command, "wget ")
}

# Require approval for package installations
result = {"decision": "ask", "reason": "package installation requires approval"} {
    input.action.name == "bash"
    contains(input.action.args.command, "npm install")
}

result = {"decision": "ask", "reason": "package installation requires approval"} {
    input.action.name == "bash"
    contains(input.action.args.command, "pip install")
}
