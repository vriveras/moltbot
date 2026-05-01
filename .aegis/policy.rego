package aegis

import rego.v1

# ===== Default: allow all (testing mode) =====
default result := {
    "permissionDecision": "allow",
    "ruleName": "default-allow-all",
}

# ===== Safe tools: always allow =====
safe_tools := {
    "report_intent", "view", "glob", "grep",
    "ide-get_diagnostics", "ide-get_selection",
}

result := {"permissionDecision": "allow", "ruleName": "allow-safe-tools"} if {
    input.action.kind == "tool_call"
    input.action.name in safe_tools
}

# ===== File reads: always allow =====
result := {"permissionDecision": "allow", "ruleName": "allow-file-read"} if {
    input.action.kind == "file_read"
}

# ===== Git readonly: allow in sandbox, no network =====
git_readonly_commands := {"status", "log", "diff", "show"}

git_subcommand := cmd if {
    args := object.get(input.action, "args", {})
    command := object.get(args, "command", "")
    parts := split(trim_space(command), " ")
    some i
    parts[i] == "git"
    some j
    j > i
    not startswith(parts[j], "-")
    cmd := parts[j]
}

result := {
    "permissionDecision": "allow",
    "ruleName": "allow-git-readonly",
    "executionEnvelope": {"networkEnabled": false},
} if {
    input.action.kind == "tool_call"
    input.action.name == "powershell"
    git_subcommand in git_readonly_commands
}

# ===== Destructive commands: deny =====
destructive_patterns := ["rm -rf", "Remove-Item.*-Recurse", "format c:", "mkfs"]

is_destructive if {
    args := object.get(input.action, "args", {})
    command := object.get(args, "command", "")
    some pattern in destructive_patterns
    regex.match(pattern, command)
}

result := {
    "permissionDecision": "deny",
    "permissionDecisionReason": "Destructive commands are blocked by policy.",
    "ruleName": "deny-destructive",
} if {
    input.action.kind == "tool_call"
    input.action.name == "powershell"
    is_destructive
}
