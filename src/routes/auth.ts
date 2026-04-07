import { Router } from "express";
import bcrypt from "bcryptjs";
import { db, usersTable } from "../db";
import { eq } from "drizzle-orm";
import { z } from "zod";

const router = Router();

const LoginBody   = z.object({ username: z.string().min(1), password: z.string().min(1) });
const RegisterBody = z.object({ username: z.string().min(3), email: z.string().email(), password: z.string().min(6) });

router.get("/auth/me", async (req: any, res: any) => {
  if (!req.session?.userId) return res.status(401).json({ error: "Not authenticated" });
  const [user] = await db.select({ id: usersTable.id, username: usersTable.username, email: usersTable.email, createdAt: usersTable.createdAt })
    .from(usersTable).where(eq(usersTable.id, req.session.userId));
  if (!user) return res.status(401).json({ error: "User not found" });
  res.json(user);
});

router.post("/auth/login", async (req: any, res: any) => {
  const parsed = LoginBody.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input" });
  const { username, password } = parsed.data;
  const [user] = await db.select().from(usersTable).where(eq(usersTable.username, username));
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });
  req.session.userId = user.id;
  res.json({ id: user.id, username: user.username, email: user.email });
});

router.post("/auth/register", async (req: any, res: any) => {
  const parsed = RegisterBody.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  const { username, email, password } = parsed.data;
  const [existing] = await db.select().from(usersTable).where(eq(usersTable.username, username));
  if (existing) return res.status(400).json({ error: "Username already taken" });
  const passwordHash = await bcrypt.hash(password, 10);
  const [user] = await db.insert(usersTable).values({ username, email, passwordHash }).returning();
  req.session.userId = user.id;
  res.status(201).json({ id: user.id, username: user.username, email: user.email });
});

router.post("/auth/logout", (req: any, res: any) => {
  req.session.destroy(() => res.json({ ok: true }));
});

export default router;
