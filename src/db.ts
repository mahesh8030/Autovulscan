import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import { pgTable, text, serial, timestamp, integer } from "drizzle-orm/pg-core";

const dbUrl = process.env.DATABASE_URL;

if (!dbUrl) {
  console.error("❌ DATABASE_URL is not set!");
  process.exit(1);
}

export const pool = new Pool({
  connectionString: dbUrl,
  ssl: { rejectUnauthorized: false },
  max: 3,
  min: 1,
  connectionTimeoutMillis: 30000,
  idleTimeoutMillis: 60000,
  allowExitOnIdle: false,
});

// Auto reconnect on connection drop
pool.on("error", (err) => {
  console.error("Database pool error:", err.message);
});

export const db = drizzle(pool);

export const usersTable = pgTable("users", {
  id:           serial("id").primaryKey(),
  username:     text("username").notNull().unique(),
  email:        text("email").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  createdAt:    timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const scansTable = pgTable("scans", {
  id:            serial("id").primaryKey(),
  target:        text("target").notNull(),
  scanType:      text("scan_type").notNull().default("full"),
  status:        text("status").notNull().default("pending"),
  progress:      integer("progress").notNull().default(0),
  currentPhase:  text("current_phase").notNull().default("Initializing"),
  findingsCount: integer("findings_count").notNull().default(0),
  criticalCount: integer("critical_count").notNull().default(0),
  highCount:     integer("high_count").notNull().default(0),
  mediumCount:   integer("medium_count").notNull().default(0),
  lowCount:      integer("low_count").notNull().default(0),
  alertWebhook:  text("alert_webhook"),
  alertType:     text("alert_type"),
  userId:        integer("user_id").notNull().references(() => usersTable.id),
  startedAt:     timestamp("started_at",   { withTimezone: true }),
  completedAt:   timestamp("completed_at", { withTimezone: true }),
  createdAt:     timestamp("created_at",   { withTimezone: true }).notNull().defaultNow(),
});

export const findingsTable = pgTable("findings", {
  id:            serial("id").primaryKey(),
  scanId:        integer("scan_id").notNull().references(() => scansTable.id, { onDelete: "cascade" }),
  title:         text("title").notNull(),
  description:   text("description").notNull(),
  severity:      text("severity").notNull(),
  owaspCategory: text("owasp_category").notNull(),
  url:           text("url").notNull(),
  evidence:      text("evidence"),
  remediation:   text("remediation"),
  createdAt:     timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export async function initDb(): Promise<void> {
  let retries = 5;
  while (retries > 0) {
    try {
      const client = await pool.connect();
      try {
        await client.query(`
          CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
          );
          CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL DEFAULT 'full',
            status TEXT NOT NULL DEFAULT 'pending',
            progress INTEGER NOT NULL DEFAULT 0,
            current_phase TEXT NOT NULL DEFAULT 'Initializing',
            findings_count INTEGER NOT NULL DEFAULT 0,
            critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0,
            medium_count INTEGER NOT NULL DEFAULT 0,
            low_count INTEGER NOT NULL DEFAULT 0,
            alert_webhook TEXT,
            alert_type TEXT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
          );
          CREATE TABLE IF NOT EXISTS findings (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            owasp_category TEXT NOT NULL,
            url TEXT NOT NULL,
            evidence TEXT,
            remediation TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
          );
        `);
        console.log("✅ Database tables ready");
        return;
      } finally {
        client.release();
      }
    } catch (err: any) {
      retries--;
      console.error(`❌ DB connection failed. Retries left: ${retries}. Error: ${err.message}`);
      if (retries === 0) throw err;
      await new Promise(r => setTimeout(r, 3000));
    }
  }
}
