import { db, scansTable, findingsTable } from "../db";
import { eq } from "drizzle-orm";

const SCAN_PHASES = [
  "Initializing", "DNS Reconnaissance", "Port Discovery",
  "Service Detection", "Vulnerability Scanning",
  "Injection Testing", "Authentication Testing",
  "OWASP Analysis", "Generating Report", "Completed",
];

const SIMULATED_FINDINGS = [
  {
    title: "SQL Injection Vulnerability",
    description: "User-supplied data is incorporated into database queries without proper sanitization, allowing attackers to manipulate SQL statements.",
    severity: "critical",
    owaspCategory: "A03:2021 - Injection",
    evidence: "Parameter 'id' is vulnerable: ?id=1' OR '1'='1 returns all records",
    remediation: "Use parameterized queries or prepared statements. Implement input validation and escape all user-supplied data.",
  },
  {
    title: "Cross-Site Scripting (XSS)",
    description: "Reflected XSS vulnerability found in search parameter. User input is reflected in the page response without proper encoding.",
    severity: "high",
    owaspCategory: "A03:2021 - Injection",
    evidence: "Payload <script>alert(1)</script> executed in browser context",
    remediation: "Encode all output, implement Content Security Policy (CSP) headers, use modern frameworks with auto-escaping.",
  },
  {
    title: "Missing HTTP Security Headers",
    description: "Critical security headers are absent from HTTP responses, leaving the application vulnerable to clickjacking and MIME sniffing attacks.",
    severity: "medium",
    owaspCategory: "A05:2021 - Security Misconfiguration",
    evidence: "X-Frame-Options, X-Content-Type-Options, and Content-Security-Policy headers are missing",
    remediation: "Add X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security, and Content-Security-Policy headers.",
  },
  {
    title: "Broken Authentication - Weak Password Policy",
    description: "The application allows weak passwords and does not enforce account lockout after multiple failed login attempts.",
    severity: "high",
    owaspCategory: "A07:2021 - Identification and Authentication Failures",
    evidence: "Successfully authenticated with password '123456'. No lockout after 50+ failed attempts.",
    remediation: "Enforce minimum password complexity, implement account lockout after 5 failed attempts, add CAPTCHA for repeated failures.",
  },
  {
    title: "Sensitive Data Exposure in API Response",
    description: "API endpoints return sensitive user data including password hashes and internal system details.",
    severity: "critical",
    owaspCategory: "A02:2021 - Cryptographic Failures",
    evidence: 'Response body contains: {"password": "$2b$10$...", "internal_id": "..."}',
    remediation: "Implement proper data filtering on API responses. Never return password hashes or internal identifiers. Use DTOs.",
  },
  {
    title: "Directory Traversal",
    description: "File inclusion vulnerability allows attackers to access files outside the intended web root directory.",
    severity: "high",
    owaspCategory: "A01:2021 - Broken Access Control",
    evidence: "../../../etc/passwd successfully retrieved via file parameter",
    remediation: "Validate and sanitize all file path inputs. Use allowlists for permitted file access. Implement proper access controls.",
  },
  {
    title: "Outdated TLS Configuration",
    description: "Server accepts connections using deprecated TLS 1.0 and 1.1 protocols which have known vulnerabilities.",
    severity: "medium",
    owaspCategory: "A02:2021 - Cryptographic Failures",
    evidence: "Server accepts TLS 1.0 handshake with RC4 cipher suite",
    remediation: "Disable TLS 1.0 and 1.1. Configure minimum TLS 1.2. Disable weak cipher suites like RC4 and DES.",
  },
  {
    title: "Server Information Disclosure",
    description: "HTTP response headers reveal server software version and operating system details useful to attackers.",
    severity: "low",
    owaspCategory: "A05:2021 - Security Misconfiguration",
    evidence: "Server: Apache/2.4.29 (Ubuntu) OpenSSL/1.1.0g",
    remediation: "Configure server to suppress version information in HTTP headers. Set ServerTokens Prod in Apache.",
  },
  {
    title: "CSRF Token Missing",
    description: "State-changing operations do not implement CSRF protection.",
    severity: "medium",
    owaspCategory: "A01:2021 - Broken Access Control",
    evidence: "POST /api/user/delete accepts requests without CSRF token from cross-origin pages",
    remediation: "Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute.",
  },
  {
    title: "Insecure Direct Object Reference (IDOR)",
    description: "Object references are predictable and authorization is not enforced, allowing access to other users' data.",
    severity: "high",
    owaspCategory: "A01:2021 - Broken Access Control",
    evidence: "Changing user_id parameter from 123 to 124 returns another user's profile data",
    remediation: "Implement proper authorization checks on every object access. Use indirect reference maps or UUIDs.",
  },
  {
    title: "Open Redirect Vulnerability",
    description: "Application redirects users to external URLs without validation.",
    severity: "medium",
    owaspCategory: "A10:2021 - Server-Side Request Forgery",
    evidence: "?redirect=https://evil.com causes redirect to attacker-controlled site",
    remediation: "Validate and whitelist all redirect destinations. Never redirect to user-supplied URLs directly.",
  },
  {
    title: "Insecure Cookie Configuration",
    description: "Session cookies are missing HttpOnly and Secure flags, exposing them to theft.",
    severity: "medium",
    owaspCategory: "A07:2021 - Identification and Authentication Failures",
    evidence: "Set-Cookie: session=abc123 (no HttpOnly, no Secure, no SameSite)",
    remediation: "Set HttpOnly, Secure, and SameSite=Strict flags on all session cookies.",
  },
];

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getRandomFindings(target: string, count: number) {
  const shuffled = [...SIMULATED_FINDINGS].sort(() => Math.random() - 0.5);
  const paths = ["", "/api", "/login", "/admin", "/search", "/file", "/user", "/dashboard"];
  return shuffled.slice(0, count).map((f) => ({
    ...f,
    url: `${target}${paths[Math.floor(Math.random() * paths.length)]}`,
  }));
}

export async function runScan(scanId: number): Promise<void> {
  try {
    await db.update(scansTable).set({
      status: "running",
      startedAt: new Date(),
      currentPhase: SCAN_PHASES[0],
    }).where(eq(scansTable.id, scanId));

    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId));
    if (!scan) return;

    const target = scan.target;
    const totalPhases = SCAN_PHASES.length - 1;
    const findingCount = Math.floor(Math.random() * 6) + 4;
    const findings = getRandomFindings(target, findingCount);
    const findingsPerPhase = Math.ceil(findings.length / (totalPhases - 2));

    for (let i = 0; i < totalPhases; i++) {
      const phase = SCAN_PHASES[i];
      const progress = Math.round(((i + 1) / totalPhases) * 100);

      await db.update(scansTable).set({ progress, currentPhase: phase })
        .where(eq(scansTable.id, scanId));

      if (i >= 3 && i < totalPhases - 1) {
        const phaseFindings = findings.splice(0, findingsPerPhase);
        for (const finding of phaseFindings) {
          await db.insert(findingsTable).values({ scanId, ...finding });
        }
        const allFindings = await db.select().from(findingsTable)
          .where(eq(findingsTable.scanId, scanId));
        const counts = allFindings.reduce(
          (acc, f) => {
            if (f.severity === "critical") acc.critical++;
            else if (f.severity === "high") acc.high++;
            else if (f.severity === "medium") acc.medium++;
            else if (f.severity === "low") acc.low++;
            return acc;
          },
          { critical: 0, high: 0, medium: 0, low: 0 }
        );
        await db.update(scansTable).set({
          findingsCount: allFindings.length,
          criticalCount: counts.critical,
          highCount: counts.high,
          mediumCount: counts.medium,
          lowCount: counts.low,
        }).where(eq(scansTable.id, scanId));
      }
      await sleep(1500 + Math.random() * 1000);
    }

    // Insert remaining findings
    for (const finding of findings) {
      await db.insert(findingsTable).values({ scanId, ...finding });
    }

    const finalFindings = await db.select().from(findingsTable)
      .where(eq(findingsTable.scanId, scanId));
    const finalCounts = finalFindings.reduce(
      (acc, f) => {
        if (f.severity === "critical") acc.critical++;
        else if (f.severity === "high") acc.high++;
        else if (f.severity === "medium") acc.medium++;
        else if (f.severity === "low") acc.low++;
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    );

    await db.update(scansTable).set({
      status: "completed", progress: 100, currentPhase: "Completed",
      completedAt: new Date(),
      findingsCount: finalFindings.length,
      criticalCount: finalCounts.critical,
      highCount: finalCounts.high,
      mediumCount: finalCounts.medium,
      lowCount: finalCounts.low,
    }).where(eq(scansTable.id, scanId));

    console.log(`✅ Scan ${scanId} completed with ${finalFindings.length} findings`);
  } catch (err) {
    console.error(`❌ Scan ${scanId} failed:`, err);
    await db.update(scansTable).set({ status: "failed", currentPhase: "Failed" })
      .where(eq(scansTable.id, scanId));
  }
}
