/**
 * Explanation content for payloads, kept separate from the payload data and
 * from the UI. Each entry is plain data (no JSX), joined to a payload by its
 * id. The goal is to make a payload understandable in seconds, so every field
 * is deliberately short and conceptual. Nothing here is a step by step exploit
 * recipe: "why it works" describes the underlying flaw at a high level, and
 * "when to use it" frames the check for authorized testing.
 *
 * owasp, control, and mitigation are the governance layer this project is
 * named for: which OWASP Top 10 (2021) category the flaw falls under, which
 * control family addresses it (NIST SP 800-53 / ISO/IEC 27001:2022 Annex A),
 * and the one concrete fix. These three fields are required, not optional,
 * for every entry, because an empty field here is the exact gap this tool
 * exists to close.
 */

export type PayloadExplanation = {
  summary: string; // one or two lines, the gist
  why: string; // high level reason the class of flaw exists
  when: string; // practical context for an authorized test
  owasp: string; // OWASP Top 10 2021 category
  control: string; // one mapped control, NIST or ISO 27001
  mitigation: string; // one line, the practical fix
};

export const explanations: Record<string, PayloadExplanation> = {
  /* ------------------------------ XSS ------------------------------ */
  "xss-script-basic": {
    summary: "A script tag that shows a harmless alert box if it executes.",
    why: "When an app places input into the page without escaping it, the browser parses that input as markup and runs any script inside it.",
    when: "A first, quick check on a reflected field to see if output is escaped. The alert is only a visible signal.",
    owasp: "A03:2021 - Injection (Cross-Site Scripting)",
    control: "NIST SP 800-53 SI-10 (Information Input Validation) / ISO/IEC 27001:2022 Annex A.8.28 (Secure Coding)",
    mitigation: "Apply context-aware output encoding (HTML entity encoding) to every untrusted value at the point it is rendered into HTML, not on input.",
  },
  "xss-img-onerror": {
    summary: "A broken image that runs its error handler.",
    why: "Even when literal script tags are removed, HTML event handlers still run code, so a failed image load can trigger script.",
    when: "Use when a plain script tag is stripped, to see if event handler attributes are filtered too.",
    owasp: "A03:2021 - Injection (Cross-Site Scripting)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Encode attribute values on output and strip or disallow inline event handler attributes; back this with a Content-Security-Policy that blocks inline scripts.",
  },
  "xss-svg-onload": {
    summary: "An SVG element that runs code as soon as it loads.",
    why: "SVG is active markup whose load handler fires on its own, so no user interaction is needed for it to run.",
    when: "Useful where image tags are blocked, including values that get reflected from a cookie.",
    owasp: "A03:2021 - Injection (Cross-Site Scripting)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Never reflect cookie or other stored values directly into markup; encode on output and restrict active content (SVG, object) via CSP.",
  },
  "xss-url-encoded": {
    summary: "The script test with its angle brackets percent encoded.",
    why: "A filter may check the raw request while the server decodes it later, so encoded characters can slip past and then become real markup.",
    when: "Use to probe whether a filter validates input before or after decoding.",
    owasp: "A03:2021 - Injection (Cross-Site Scripting)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Validate and encode after every decoding step has been applied, at the final point of use, instead of filtering the raw, still-encoded input.",
  },
  "xss-html-entity": {
    summary: "The script test written with HTML entities.",
    why: "If an app turns entities back into characters when rendering, an inert looking value can become live markup on output.",
    when: "Use to test whether entity decoding happens at output, a common stored issue source.",
    owasp: "A03:2021 - Injection (Cross-Site Scripting)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Encode once, at the final render point; never decode entities from stored or untrusted data before inserting it into HTML.",
  },
  "xss-unicode-escape": {
    summary: "The script test written with JavaScript unicode escapes.",
    why: "In a JSON or script string context, an app that unescapes input can rebuild the characters that form a tag.",
    when: "Use when your input lands inside a script or JSON body rather than plain HTML.",
    owasp: "A03:2021 - Injection (Cross-Site Scripting)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Use context-specific escaping for JavaScript and JSON string literals, and avoid building script blocks by concatenating untrusted strings.",
  },
  "xss-mixed-case": {
    summary: "The word script written in mixed case.",
    why: "A blocklist matching only the exact lowercase keyword misses variants, while browsers treat tag names case insensitively.",
    when: "Use to test whether a filter's keyword matching is case sensitive.",
    owasp: "A03:2021 - Injection (Cross-Site Scripting)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Replace keyword blocklists with context-aware output encoding; a blocklist is not a substitute for encoding and is trivially bypassed by case or obfuscation.",
  },
  "xss-fromcharcode": {
    summary: "Builds the alert text from character codes, not a literal word.",
    why: "Filters that look for specific literal strings do not see a keyword assembled at runtime.",
    when: "Use to check whether filtering depends on spotting literal keywords.",
    owasp: "A03:2021 - Injection (Cross-Site Scripting)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Do not rely on string pattern matching as a defense; enforce output encoding and a CSP with no unsafe-inline or unsafe-eval.",
  },
  "xss-var-split": {
    summary: "Calls the alert through an intermediate variable.",
    why: "A pattern match for a direct call can miss the same call reached indirectly.",
    when: "Use against filters that only match obvious, direct call patterns.",
    owasp: "A03:2021 - Injection (Cross-Site Scripting)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Same as above: pattern-based filtering is bypassable by indirection, so enforce output encoding and CSP as the actual control, not the filter.",
  },

  /* -------------------------- SQL Injection -------------------------- */
  "sqli-single-quote": {
    summary: "A single quote on its own, the smallest possible probe.",
    why: "A quote can break out of a string in a query built by concatenation, and the resulting error shows input reaches the query.",
    when: "Always try this first. An error or odd behavior means the field is worth deeper, authorized testing.",
    owasp: "A03:2021 - Injection (SQL Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Use parameterized queries or prepared statements everywhere; never build SQL by concatenating untrusted input.",
  },
  "sqli-or-1-1": {
    summary: "An always true condition, the textbook login bypass demo.",
    why: "If input is concatenated into a WHERE clause, an always true condition can make the clause pass regardless of the real values.",
    when: "Use on login or lookup fields to show a query trusts input. For teaching and authorized tests only.",
    owasp: "A03:2021 - Injection (SQL Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Parameterize every query, including authentication checks; input should never be able to alter query logic regardless of its content.",
  },
  "sqli-or-comment": {
    summary: "An always true condition followed by a comment marker.",
    why: "The comment marker makes the database ignore the rest of the original query, leaving only the injected condition.",
    when: "Use when trailing query parts, like a password check, need to be neutralized to show impact.",
    owasp: "A03:2021 - Injection (SQL Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Parameterized queries remove this entire class, since user input is bound as data and cannot introduce new SQL syntax such as a comment marker.",
  },
  "sqli-admin-comment": {
    summary: "Ends a username early and comments out what follows.",
    why: "Closing the username value and commenting the remainder can make the query skip a following password condition.",
    when: "Use against login forms to illustrate authentication logic that trusts input.",
    owasp: "A03:2021 - Injection (SQL Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Parameterize the authentication query and enforce least-privilege database accounts, so even a successful bypass has limited reach.",
  },
  "sqli-double-quote": {
    summary: "The always true test using double quotes.",
    why: "Some queries wrap values in double quotes, so a matching quote is needed to break out of the string.",
    when: "Use when a single quote does nothing, to learn which quoting style the backend uses.",
    owasp: "A03:2021 - Injection (SQL Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Parameterized queries close this regardless of quoting style; the choice of quote character is irrelevant once input is bound as data, not syntax.",
  },
  "sqli-union-null": {
    summary: "A UNION that selects a single placeholder column.",
    why: "UNION appends a second query's result, and matching the column count is the first structural step to understand a query.",
    when: "Use conceptually to learn how many columns a query returns during an authorized assessment.",
    owasp: "A03:2021 - Injection (SQL Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Parameterized queries prevent UNION-based extraction entirely; least-privilege database accounts also limit what a successful UNION could read.",
  },
  "sqli-time-sleep": {
    summary: "Asks the database to pause, revealing injection by timing.",
    why: "When a page shows no data or error, a deliberate delay that changes response time still confirms input reaches the database.",
    when: "Use for blind cases where output gives nothing away. Sent through a header field here.",
    owasp: "A03:2021 - Injection (SQL Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Parameterized queries remove the injection point itself; query timeouts and rate limiting reduce the impact of any remaining blind channel.",
  },

  /* ------------------------ Command Injection ------------------------ */
  "cmd-semicolon-id": {
    summary: "Chains a harmless id command after a semicolon.",
    why: "If input is passed to a shell, a separator lets a second command run after the intended one. id only prints the user.",
    when: "Use to check whether a parameter is handed to a shell. The command is read only.",
    owasp: "A03:2021 - Injection (OS Command Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Avoid invoking a shell with user input at all; call the underlying binary directly with an argument array (no shell interpolation), and allowlist expected values.",
  },
  "cmd-and-whoami": {
    summary: "Runs whoami only if the first command succeeds.",
    why: "The AND separator chains commands conditionally, so a benign follow up confirms the shell parsed your input.",
    when: "Use as a safe confirmation that command separators are honored.",
    owasp: "A03:2021 - Injection (OS Command Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Same as above: use non-shell process execution APIs (argument arrays) so separators like && are inert, plus strict input allowlisting.",
  },
  "cmd-pipe-whoami": {
    summary: "Pipes output into a second, harmless command.",
    why: "A pipe passes one command's output to another, so seeing its result shows the pipe was interpreted.",
    when: "Use to test whether pipe characters pass through input handling.",
    owasp: "A03:2021 - Injection (OS Command Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Avoid shell invocation with user input; where a shell is unavoidable, use strict allowlisting of characters and reject any metacharacter.",
  },
  "cmd-subshell": {
    summary: "Runs id inside a command substitution.",
    why: "Substitution executes an inner command and inserts its output, so a benign inner command proves input reached a shell.",
    when: "Use where input may be embedded in a larger command string, such as a request body.",
    owasp: "A03:2021 - Injection (OS Command Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Use non-shell execution APIs so substitution syntax has no special meaning, and validate request body fields against a strict allowlist before use.",
  },
  "cmd-backtick": {
    summary: "The older backtick form of command substitution.",
    why: "Backticks do the same substitution as the modern form, so both are worth trying since a filter may block only one.",
    when: "Use alongside the parenthesis form to cover legacy shell syntax.",
    owasp: "A03:2021 - Injection (OS Command Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Do not filter by syntax variant; remove shell invocation entirely so no substitution form, old or new, has any effect.",
  },
  "cmd-sleep": {
    summary: "A short, harmless delay for blind detection.",
    why: "When there is no visible output, a measurable pause still confirms the command ran.",
    when: "Use for blind command cases, mirroring the timing idea from SQL testing.",
    owasp: "A03:2021 - Injection (OS Command Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Remove shell invocation with user input; additionally, enforce execution timeouts and resource limits on any subprocess the application starts.",
  },
  "cmd-win-amp": {
    summary: "The Windows separator running a harmless whoami.",
    why: "On Windows shells the ampersand chains commands, so it is the separator to try when a target is not Unix based.",
    when: "Use against Windows or cmd.exe style targets where Unix separators may not apply.",
    owasp: "A03:2021 - Injection (OS Command Injection)",
    control: "NIST SP 800-53 SI-10 / ISO/IEC 27001:2022 Annex A.8.28",
    mitigation: "Use non-shell process execution APIs on every platform; cmd.exe separators are only a risk if a shell is invoked with untrusted input at all.",
  },
};
