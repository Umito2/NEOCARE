import { createHash, pbkdf2, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { cert, getApps, initializeApp } from "firebase-admin/app";
import { getDatabase, type Database } from "firebase-admin/database";

const pbkdf2Async = promisify(pbkdf2);

export const DATABASE_URL = "https://neocare-system-default-rtdb.firebaseio.com/";
const PBKDF2_ROUNDS = 480_000;
export const SESSION_SECONDS = 12 * 60 * 60;
const AUTH_PATH = "neocare_system/auth";

export class ConfigError extends Error {}

function loadCredentials() {
  const json = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const base64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;
  if (json) return JSON.parse(json);
  if (base64) return JSON.parse(Buffer.from(base64, "base64").toString("utf8"));
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY;
  if (projectId && clientEmail && privateKey) {
    return { project_id: projectId, client_email: clientEmail, private_key: privateKey.replace(/\\n/g, "\n") };
  }
  throw new ConfigError(
    "Firebase credentials are missing. Set FIREBASE_SERVICE_ACCOUNT_JSON (or FIREBASE_PROJECT_ID, " +
      "FIREBASE_CLIENT_EMAIL and FIREBASE_PRIVATE_KEY) in the Netlify environment variables."
  );
}

export function db(): Database {
  const app =
    getApps()[0] ??
    initializeApp({
      credential: cert(loadCredentials()),
      databaseURL: process.env.FIREBASE_DATABASE_URL || DATABASE_URL,
    });
  return getDatabase(app);
}

export const ref = (path: string) => db().ref(path);
const authRef = (path: string) => ref(`${AUTH_PATH}/${path}`);
const sha256 = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
const now = () => Math.floor(Date.now() / 1000);

async function hashPassword(password: string, salt: Buffer = randomBytes(16)) {
  const digest = await pbkdf2Async(password, salt, PBKDF2_ROUNDS, 32, "sha256");
  return { salt, digest };
}

export class DuplicateEmailError extends Error {}

export async function createParent(parentId: string, name: string, email: string, phone: string, password: string) {
  const { salt, digest } = await hashPassword(password);
  const emailIndex = authRef(`parent_email_index/${sha256(email.toLowerCase())}`);
  const claim = await emailIndex.transaction((current) => (current == null ? parentId : undefined));
  if (!claim.committed || claim.snapshot.val() !== parentId) throw new DuplicateEmailError();
  try {
    await authRef(`parents/${parentId}`).set({
      parent_id: parentId,
      name,
      email,
      phone,
      password_salt: salt.toString("hex"),
      password_hash: digest.toString("hex"),
      created_at: now(),
    });
  } catch (error) {
    await emailIndex.transaction((current) => (current === parentId ? null : undefined));
    throw error;
  }
}

async function parentRecord(parentId: string | null) {
  if (!parentId) return null;
  const row = (await authRef(`parents/${parentId}`).get()).val();
  return row && typeof row === "object" ? row : null;
}

export async function authenticateParent(email: string, password: string) {
  const parentId = (await authRef(`parent_email_index/${sha256(email.toLowerCase())}`).get()).val();
  const row = await parentRecord(parentId);
  if (!row) {
    await hashPassword(password, Buffer.alloc(16));
    return null;
  }
  const { digest } = await hashPassword(password, Buffer.from(row.password_salt, "hex"));
  const stored = Buffer.from(row.password_hash, "hex");
  if (stored.length !== digest.length || !timingSafeEqual(digest, stored)) return null;
  return { role: "parent", user_id: row.parent_id, display_name: row.name, email: row.email };
}

export async function parentById(parentId: string) {
  const row = await parentRecord(parentId);
  if (!row) return null;
  return { parent_id: row.parent_id, name: row.name, email: row.email, phone: row.phone };
}

export interface Session {
  role: "doctor" | "parent";
  user_id: string;
  display_name: string;
  expires_at: number;
}

export async function createSession(role: string, userId: string, displayName: string) {
  const token = randomBytes(32).toString("base64url");
  await authRef(`sessions/${sha256(token)}`).set({
    role,
    user_id: userId,
    display_name: displayName,
    expires_at: now() + SESSION_SECONDS,
  });
  return token;
}

export async function getSession(token: string | undefined): Promise<Session | null> {
  if (!token) return null;
  const sessionRef = authRef(`sessions/${sha256(token)}`);
  const row = (await sessionRef.get()).val();
  if (!row || typeof row !== "object") return null;
  if ((row.expires_at ?? 0) <= now()) {
    await sessionRef.remove();
    return null;
  }
  return row;
}

export async function deleteSession(token: string | undefined) {
  if (token) await authRef(`sessions/${sha256(token)}`).remove();
}

export async function saveAlertSeverity(childId: string, severity: number) {
  await authRef(`alert_state/${childId}`).set({ severity, updated_at: now() });
}

export async function getAlertSeverity(childId: string): Promise<number> {
  const row = (await authRef(`alert_state/${childId}`).get()).val();
  return row && typeof row === "object" ? row.severity ?? 0 : 0;
}

export async function addAlert(alert: {
  child_id: string;
  parent_id: string;
  child_name: string;
  severity: string;
  subject: string;
  message: string;
  email_status: string;
}) {
  const alertRef = authRef("alerts").push();
  await alertRef.set({ ...alert, created_at: now() });
  return alertRef.key;
}

export async function listAlerts(role: string, userId: string, limit = 100) {
  const records = (await authRef("alerts").get()).val() || {};
  return Object.entries(records)
    .filter(([, alert]: [string, any]) => alert && typeof alert === "object" && (role !== "parent" || alert.parent_id === userId))
    .map(([alert_id, alert]: [string, any]) => ({ alert_id, ...alert }))
    .sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0))
    .slice(0, limit);
}

export async function getThresholds(): Promise<Record<string, number> | null> {
  const value = (await authRef("settings/alert_thresholds").get()).val();
  return value && typeof value === "object" ? value : null;
}

export async function saveThresholds(value: Record<string, number>) {
  await authRef("settings/alert_thresholds").set(value);
}
