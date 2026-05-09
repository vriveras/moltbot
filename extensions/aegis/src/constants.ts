export const DEFAULT_READ_TIMEOUT_MS = 30_000;

export const DEFAULT_APPROVAL_TIMEOUT_MS = 1_800_000;

export const DEFAULT_APPROVAL_TIMEOUT_BEHAVIOR = "deny" as const;

export const DEFAULT_APPROVAL_SEVERITY = "warning" as const;

export const DEFAULT_FAIL_BEHAVIOR = "allow" as const;

/** Shared default key patterns for redacting sensitive argument names. */
export const DEFAULT_REDACT_KEY_PATTERNS: string[] = [
  "password",
  "token",
  "secret",
  "key",
  "auth",
  "credential",
];

/** Default regex patterns for redacting sensitive values in arguments. */
export const DEFAULT_REDACT_VALUE_PATTERNS: string[] = [
  "Bearer\\s+[A-Za-z0-9\\-._~+/]+=*",
  "sk-[A-Za-z0-9]{20,}",
  "ghp_[A-Za-z0-9]{36}",
  "eyJ[A-Za-z0-9\\-_]+\\.eyJ[A-Za-z0-9\\-_]+",
];
