/**
 * Shared redaction utilities for both audit and approval flows.
 * Combines key-name substring matching with regex value matching.
 */

const MAX_REDACTION_DEPTH = 10;

/**
 * Redacts sensitive data from args by checking:
 * 1. Key names against string patterns (case-insensitive substring match)
 * 2. String values against regex patterns
 *
 * @param args - The arguments object to redact
 * @param keyPatterns - String patterns to match against key names (e.g., ["password", "token"])
 * @param valueRegexPatterns - Regex patterns to test string values against
 * @param depth - Current recursion depth (internal, do not set manually)
 * @returns Redacted copy of the arguments
 */
export function redactArgs(
  args: unknown,
  keyPatterns: string[],
  valueRegexPatterns: RegExp[] = [],
  depth = 0,
): unknown {
  // Prevent infinite recursion on circular references
  if (depth > MAX_REDACTION_DEPTH) {
    return "[MAX_DEPTH]";
  }

  // Handle null/undefined
  if (args == null) {
    return args;
  }

  // Handle arrays recursively
  if (Array.isArray(args)) {
    return args.map((item) =>
      redactArgs(item, keyPatterns, valueRegexPatterns, depth + 1),
    );
  }

  // Handle objects recursively
  if (typeof args === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(args)) {
      // Check if key name matches any pattern (case-insensitive substring)
      const keyMatches =
        keyPatterns.length > 0 &&
        keyPatterns.some((pattern) =>
          key.toLowerCase().includes(pattern.toLowerCase()),
        );

      if (keyMatches) {
        result[key] = "[REDACTED]";
      } else {
        // Recurse into nested values
        result[key] = redactArgs(
          value,
          keyPatterns,
          valueRegexPatterns,
          depth + 1,
        );
      }
    }
    return result;
  }

  // For string values, check against regex patterns
  if (typeof args === "string" && valueRegexPatterns.length > 0) {
    for (const pattern of valueRegexPatterns) {
      pattern.lastIndex = 0; // Reset regex state
      if (pattern.test(args)) {
        return "[REDACTED]";
      }
    }
  }

  // Primitive values that don't match any pattern
  return args;
}

export function compileValuePatterns(rawPatterns: string[]): RegExp[] {
  const compiled: RegExp[] = [];
  for (const p of rawPatterns) {
    try {
      if (p.length > 500) {
        console.warn(`[aegis] Skipping oversized redact pattern (${p.length} chars)`);
        continue;
      }
      compiled.push(new RegExp(p));
    } catch {
      console.warn(`[aegis] Skipping invalid redact pattern: ${p}`);
    }
  }
  return compiled;
}
