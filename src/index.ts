import express from "express";
import cors from "cors";
import session from "express-session";
import path from "path";
import { pool, initDb } from "./db";
import authRoutes from "./routes/auth";
import scanRoutes from "./routes/scans";

const app = express();
const PORT = parseInt(process.env.PORT ?? "3000", 10);

// Trust Render proxy
app.set("trust proxy", 1);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  name: "avs.sid",
  secret: process.env.SESSION_SECRET ?? "autovulnscan-secret-2025",
  resave: true,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: "none",
    secure: true,
  },
}));

// API routes
app.use("/api", authRoutes);
app.use("/api", scanRoutes);

// Health check
app.get("/api/health", (_req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, "../public")));

// SPA fallback
app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

async function start() {
  await initDb();
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`✅ AutoVulnScan running on http://0.0.0.0:${PORT}`);
    console.log(`🔐 API ready at http://0.0.0.0:${PORT}/api`);
  });
}

start().catch(console.error);
