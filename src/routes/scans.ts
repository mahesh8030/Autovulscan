import { Router } from "express";
import { db, scansTable, findingsTable } from "../db";
import { eq, desc, and } from "drizzle-orm";
import { z } from "zod";
import { runScan } from "../lib/scanner";

const router = Router();

function requireAuth(req: any, res: any): number | null {
  if (!req.session?.userId) { res.status(401).json({ error: "Not authenticated" }); return null; }
  return req.session.userId;
}

const CreateScanBody = z.object({
  target: z.string().url("Must be a valid URL"),
  scanType: z.enum(["quick", "full", "deep"]).default("full"),
  alertWebhook: z.string().optional(),
  alertType: z.enum(["discord", "telegram"]).optional(),
});

router.get("/scans", async (req: any, res: any) => {
  const userId = requireAuth(req, res);
  if (!userId) return;
  const limit  = Number(req.query.limit  ?? 50);
  const offset = Number(req.query.offset ?? 0);
  const scans  = await db.select().from(scansTable)
    .where(eq(scansTable.userId, userId))
    .orderBy(desc(scansTable.createdAt))
    .limit(limit).offset(offset);
  res.json(scans);
});

router.post("/scans", async (req: any, res: any) => {
  const userId = requireAuth(req, res);
  if (!userId) return;
  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  const { target, scanType, alertWebhook, alertType } = parsed.data;
  // Block private IPs
  const privatePatterns = ["localhost", "127.", "192.168.", "10.", "172.16.", "0.0.0.0"];
  if (privatePatterns.some(p => target.includes(p))) {
    return res.status(400).json({ error: "Private/internal addresses are not allowed." });
  }
  const [scan] = await db.insert(scansTable).values({
    target, scanType, alertWebhook: alertWebhook ?? null,
    alertType: alertType ?? null, userId, status: "pending", progress: 0,
  }).returning();
  runScan(scan.id).catch(() => {});
  res.status(201).json(scan);
});

router.get("/scans/:id", async (req: any, res: any) => {
  const userId = requireAuth(req, res);
  if (!userId) return;
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: "Invalid scan ID" });
  const [scan] = await db.select().from(scansTable)
    .where(and(eq(scansTable.id, id), eq(scansTable.userId, userId)));
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, id));
  res.json({ ...scan, findings });
});

router.get("/scans/:id/progress", async (req: any, res: any) => {
  const userId = requireAuth(req, res);
  if (!userId) return;
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: "Invalid scan ID" });
  const [scan] = await db.select().from(scansTable)
    .where(and(eq(scansTable.id, id), eq(scansTable.userId, userId)));
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  res.json({ id: scan.id, status: scan.status, progress: scan.progress, currentPhase: scan.currentPhase, findingsCount: scan.findingsCount });
});

router.delete("/scans/:id", async (req: any, res: any) => {
  const userId = requireAuth(req, res);
  if (!userId) return;
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: "Invalid scan ID" });
  const [deleted] = await db.delete(scansTable)
    .where(and(eq(scansTable.id, id), eq(scansTable.userId, userId))).returning();
  if (!deleted) return res.status(404).json({ error: "Scan not found" });
  res.sendStatus(204);
});

router.get("/scans/:id/report", async (req: any, res: any) => {
  const userId = requireAuth(req, res);
  if (!userId) return;
  const id = parseInt(req.params.id, 10);
  const [scan] = await db.select().from(scansTable)
    .where(and(eq(scansTable.id, id), eq(scansTable.userId, userId)));
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, id));
  const sevColor = (s: string) => ({ critical:"#ef4444", high:"#f97316", medium:"#eab308", low:"#3b82f6" }[s] ?? "#6b7280");
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>AutoVulnScan Report - ${scan.target}</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem}
h1{color:#00ff41;border-bottom:1px solid #30363d;padding-bottom:1rem}
.meta{color:#8b949e;margin-bottom:2rem}.stats{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
.stat{background:#161b22;border:1px solid #30363d;padding:1rem;border-radius:6px}
.stat .val{font-size:2rem;font-weight:bold}.critical{color:#ef4444}.high{color:#f97316}
.medium{color:#eab308}.low{color:#3b82f6}
.finding{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:1.5rem;margin-bottom:1rem}
.fh{display:flex;align-items:center;gap:1rem;margin-bottom:1rem;flex-wrap:wrap}
.fh h3{margin:0;color:#e6edf3}.fh small{color:#8b949e}
.badge{padding:2px 8px;border-radius:4px;color:white;font-size:.75rem;font-weight:bold}
code{background:#0d1117;padding:2px 6px;border-radius:4px;font-size:.85em;color:#a5d6ff}
p{margin:.5rem 0}</style></head><body>
<h1>🔐 AutoVulnScan Security Report</h1>
<div class="meta"><p>Target: <strong>${scan.target}</strong></p>
<p>Scan Type: ${scan.scanType} | Status: ${scan.status}</p>
<p>Started: ${scan.startedAt?.toISOString() ?? "N/A"} | Completed: ${scan.completedAt?.toISOString() ?? "N/A"}</p></div>
<div class="stats">
<div class="stat"><div class="val">${scan.findingsCount}</div><div>Total</div></div>
<div class="stat critical"><div class="val">${scan.criticalCount}</div><div>Critical</div></div>
<div class="stat high"><div class="val">${scan.highCount}</div><div>High</div></div>
<div class="stat medium"><div class="val">${scan.mediumCount}</div><div>Medium</div></div>
<div class="stat low"><div class="val">${scan.lowCount}</div><div>Low</div></div></div>
<h2>Findings</h2>
${findings.map(f => `<div class="finding"><div class="fh">
<span class="badge" style="background:${sevColor(f.severity)}">${f.severity.toUpperCase()}</span>
<h3>${f.title}</h3><small>${f.owaspCategory}</small></div>
<p><strong>URL:</strong> <code>${f.url}</code></p>
<p><strong>Description:</strong> ${f.description}</p>
${f.evidence ? `<p><strong>Evidence:</strong> <code>${f.evidence}</code></p>` : ""}
${f.remediation ? `<p><strong>Remediation:</strong> ${f.remediation}</p>` : ""}
</div>`).join("")}
<p style="color:#555;text-align:center;margin-top:2rem">AutoVulnScan — For Educational Use Only</p>
</body></html>`;
  res.setHeader("Content-Type", "text/html");
  res.setHeader("Content-Disposition", `attachment; filename="report-${id}.html"`);
  res.send(html);
});

router.get("/dashboard", async (req: any, res: any) => {
  const userId = requireAuth(req, res);
  if (!userId) return;
  const scans = await db.select().from(scansTable)
    .where(eq(scansTable.userId, userId)).orderBy(desc(scansTable.createdAt)).limit(100);
  const total    = scans.length;
  const critical = scans.reduce((s, sc) => s + sc.criticalCount, 0);
  const high     = scans.reduce((s, sc) => s + sc.highCount, 0);
  const medium   = scans.reduce((s, sc) => s + sc.mediumCount, 0);
  const low      = scans.reduce((s, sc) => s + sc.lowCount, 0);
  const recentScans = scans.slice(0, 5);
  res.json({ totalScans: total, totalFindings: critical+high+medium+low, criticalCount: critical, highCount: high, mediumCount: medium, lowCount: low, recentScans });
});

export default router;
