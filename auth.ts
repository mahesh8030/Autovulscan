import express from "express";
import cors from "cors";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import path from "path";
import { pool, initDb } from "./db";
import authRoutes from "./routes/auth";
import scanRoutes from "./routes/scans";

const PgSession = connectPgSimple(session);
const app = express();
const PORT = parseInt(process.env.PORT ?? "3000", 10);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new PgSession({ pool, tableName: "session", createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET ?? "autovulnscan-secret-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: "lax",
            secure: process.env.NODE_ENV === "production" },
}));

// API routes
app.use("/api", authRoutes);
app.use("/api", scanRoutes);

// Health check
app.get("/api/health", (_req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, "../public")));

// SPA fallback — all non-API routes serve index.html
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
