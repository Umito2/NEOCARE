import { randomUUID, timingSafeEqual } from "node:crypto";
import type { Config, Context } from "@netlify/functions";
import nodemailer from "nodemailer";
import * as store from "../lib/store.mts";
import { additionalRecommendations, analyzePediatricVitals, generatePdfReport, type Evaluation } from "../lib/vitals.mts";

const CHILD_ID_PATTERN = /^child_[0-9]{2}$/;
const SESSION_COOKIE = "neocare_session";

class HttpError extends Error {
  constructor(public status: number, public detail: string) {
    super(detail);
  }
}

// ---------- validation ----------

type FieldSpec =
  | { type: "number"; min?: number; max?: number; minExclusive?: boolean; optional?: boolean }
  | { type: "string"; minLength?: number; maxLength?: number; pattern?: RegExp; choices?: string[]; optional?: boolean };

function validate(body: unknown, spec: Record<string, FieldSpec>): Record<string, any> {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new HttpError(422, "Request body must be a JSON object.");
  const input = body as Record<string, unknown>;
  const extra = Object.keys(input).filter((key) => !(key in spec));
  if (extra.length) throw new HttpError(422, `Unexpected field: ${extra[0]}.`);
  const result: Record<string, any> = {};
  for (const [key, rule] of Object.entries(spec)) {
    const value = input[key];
    if (value === undefined || value === null) {
      if (rule.optional) continue;
      throw new HttpError(422, `${key} is required.`);
    }
    if (rule.type === "number") {
      const number = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN;
      if (!Number.isFinite(number)) throw new HttpError(422, `${key} must be a number.`);
      if (rule.min !== undefined && (rule.minExclusive ? number <= rule.min : number < rule.min)) {
        throw new HttpError(422, `${key} must be ${rule.minExclusive ? "greater than" : "at least"} ${rule.min}.`);
      }
      if (rule.max !== undefined && number > rule.max) throw new HttpError(422, `${key} must be at most ${rule.max}.`);
      result[key] = number;
    } else {
      if (typeof value !== "string") throw new HttpError(422, `${key} must be text.`);
      if (rule.minLength !== undefined && value.length < rule.minLength) {
        throw new HttpError(422, `${key} must be at least ${rule.minLength} characters.`);
      }
      if (rule.maxLength !== undefined && value.length > rule.maxLength) {
        throw new HttpError(422, `${key} must be at most ${rule.maxLength} characters.`);
      }
      if (rule.pattern && !rule.pattern.test(value)) throw new HttpError(422, `${key} has an invalid format.`);
      if (rule.choices && !rule.choices.includes(value)) throw new HttpError(422, `${key} must be one of ${rule.choices.join(", ")}.`);
      result[key] = value;
    }
  }
  return result;
}

const positive = (max: number): FieldSpec => ({ type: "number", min: 0, minExclusive: true, max });

const CHILD_PROFILE: Record<string, FieldSpec> = {
  name: { type: "string", minLength: 1, maxLength: 80 },
  age_years: positive(18),
  height_cm: positive(250),
  weight_kg: positive(200),
};

const SIGNUP: Record<string, FieldSpec> = {
  parent_name: { type: "string", minLength: 1, maxLength: 80 },
  email: { type: "string", minLength: 5, maxLength: 254 },
  phone: { type: "string", minLength: 7, maxLength: 30 },
  password: { type: "string", minLength: 12, maxLength: 128 },
  child_name: { type: "string", minLength: 1, maxLength: 80 },
  age_years: positive(18),
  height_cm: positive(250),
  weight_kg: positive(200),
};

const LOGIN: Record<string, FieldSpec> = {
  role: { type: "string", choices: ["doctor", "parent"] },
  identifier: { type: "string", minLength: 1, maxLength: 254 },
  password: { type: "string", minLength: 1, maxLength: 128 },
};

const THRESHOLDS: Record<string, FieldSpec> = {
  spo2_min: { type: "number", min: 75, max: 100 },
  temperature_warning_c: { type: "number", min: 36, max: 45 },
  temperature_critical_c: { type: "number", min: 36, max: 45 },
  heart_rate_max_age_0_3: { type: "number", min: 30, max: 250 },
  heart_rate_max_age_over_3: { type: "number", min: 30, max: 250 },
  respiratory_rate_max_age_0_3: { type: "number", min: 10, max: 100 },
  respiratory_rate_max_age_over_3: { type: "number", min: 10, max: 100 },
};

const SENSOR_READING: Record<string, FieldSpec> = {
  child_id: { type: "string", pattern: CHILD_ID_PATTERN },
  heart_rate_bpm: positive(250),
  spo2_percent: { type: "number", min: 0, max: 100 },
  temperature_c: { type: "number", min: 25, max: 45 },
  resp_rate: { ...positive(100), optional: true },
  activity: { type: "string", choices: ["Sleeping", "Resting", "Active"], optional: true },
};

async function readJson(req: Request) {
  try {
    return await req.json();
  } catch {
    throw new HttpError(422, "Request body must be valid JSON.");
  }
}

function nonBlank(value: string, label: string) {
  const trimmed = value.trim();
  if (!trimmed) throw new HttpError(422, `${label} cannot be blank.`);
  return trimmed;
}

const safeEqual = (a: string, b: string) => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

// ---------- auth helpers ----------

async function currentUser(context: Context) {
  const session = await store.getSession(context.cookies.get(SESSION_COOKIE));
  if (!session) throw new HttpError(401, "Please sign in.");
  return session;
}

async function requireDoctor(context: Context) {
  const user = await currentUser(context);
  if (user.role !== "doctor") throw new HttpError(403, "Doctor access is required.");
  return user;
}

function setSessionCookie(req: Request, context: Context, token: string) {
  context.cookies.set({
    name: SESSION_COOKIE,
    value: token,
    httpOnly: true,
    secure: new URL(req.url).protocol === "https:",
    sameSite: "Lax",
    path: "/",
    expires: new Date(Date.now() + store.SESSION_SECONDS * 1000),
  });
}

// ---------- children ----------

const profilesRef = () => store.ref("neocare_system/children_profiles");
const liveRef = () => store.ref("neocare_system/live_monitoring");

async function getChildProfile(childId: string, user: store.Session) {
  if (!CHILD_ID_PATTERN.test(childId)) throw new HttpError(422, "child_id must use the format child_01.");
  const profile = (await profilesRef().child(childId).get()).val();
  if (!profile) throw new HttpError(404, "Child profile not found.");
  if (user.role === "parent" && profile.owner_parent_id !== user.user_id) throw new HttpError(404, "Child profile not found.");
  return profile;
}

// Claims the first free child ID with a transaction so concurrent signups never share an ID.
async function claimChildId(profile: Record<string, unknown>) {
  const readings = (await liveRef().get()).val() || {};
  for (let number = 1; number < 100; number++) {
    const childId = `child_${String(number).padStart(2, "0")}`;
    if (childId in readings) continue;
    const result = await profilesRef()
      .child(childId)
      .transaction((current) => (current == null ? profile : undefined));
    if (result.committed) return childId;
  }
  throw new HttpError(409, "No available child IDs remain.");
}

function latestChildStatus(profile: any, reading: any, thresholds: Record<string, number> | null): Evaluation {
  if (!reading) return { risk_status: "Waiting for readings", condition: "No sensor data received" };
  const resp = reading.respiratory_rate_br_min;
  const activity = reading.activity_state;
  const age = Number(profile.age_years ?? 0);
  const hr = Number(reading.heart_rate_bpm);
  const spo2 = Number(reading.spo2_percent);
  const temp = Number(reading.temperature_c);
  if (thresholds) {
    const young = age <= 3;
    const hrLimit = thresholds[young ? "heart_rate_max_age_0_3" : "heart_rate_max_age_over_3"];
    const rrLimit = thresholds[young ? "respiratory_rate_max_age_0_3" : "respiratory_rate_max_age_over_3"];
    if (spo2 < thresholds.spo2_min) return { risk_status: "Critical", condition: "SpO₂ below clinic alert threshold" };
    if (temp >= thresholds.temperature_critical_c) return { risk_status: "Critical", condition: "Temperature above clinic critical threshold" };
    if (temp >= thresholds.temperature_warning_c) return { risk_status: "Warning", condition: "Temperature above clinic warning threshold" };
    if ((activity === "Sleeping" || activity === "Resting") && hr > hrLimit) {
      return { risk_status: "Warning", condition: "Resting heart rate above clinic threshold" };
    }
    if (resp != null && Number(resp) > rrLimit) return { risk_status: "Warning", condition: "Respiratory rate above clinic threshold" };
    const missing = [resp == null && "respiratory rate", activity == null && "activity"].filter(Boolean);
    if (missing.length) return { risk_status: "Incomplete reading", condition: `Missing ${missing.join(", ")}` };
    return { risk_status: "Normal", condition: "No configured alert thresholds exceeded" };
  }
  if (resp == null || activity == null) return { risk_status: "Incomplete reading", condition: "Respiratory rate/activity missing" };
  return analyzePediatricVitals(age, hr, spo2, temp, Number(resp), activity);
}

function alertSeverity(profile: any, reading: any, thresholds: Record<string, number> | null): number | null {
  if (!thresholds || !reading) return 0;
  const resp = reading.respiratory_rate_br_min;
  const activity = reading.activity_state;
  const young = Number(profile.age_years) <= 3;
  if (Number(reading.spo2_percent) < thresholds.spo2_min) return 2;
  const temp = Number(reading.temperature_c);
  if (temp >= thresholds.temperature_critical_c) return 2;
  if (temp >= thresholds.temperature_warning_c) return 1;
  if (activity === "Sleeping" || activity === "Resting") {
    if (Number(reading.heart_rate_bpm) > thresholds[young ? "heart_rate_max_age_0_3" : "heart_rate_max_age_over_3"]) return 1;
  }
  if (resp != null && Number(resp) > thresholds[young ? "respiratory_rate_max_age_0_3" : "respiratory_rate_max_age_over_3"]) return 1;
  if (resp == null || activity == null) return null;
  return 0;
}

async function sendParentAlert(profile: any, reading: any, status: Evaluation) {
  const host = process.env.SMTP_HOST;
  const from = process.env.SMTP_FROM;
  if (!host || !from) return "not_configured";
  if (!profile.parent_email) return "no_parent_email";
  const username = process.env.SMTP_USERNAME;
  const password = process.env.SMTP_PASSWORD;
  const transport = nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT || 587),
    secure: (process.env.SMTP_USE_SSL || "").toLowerCase() === "true",
    requireTLS: (process.env.SMTP_USE_SSL || "").toLowerCase() !== "true",
    auth: username && password ? { user: username, pass: password } : undefined,
    connectionTimeout: 10_000,
  });
  await transport.sendMail({
    from,
    to: profile.parent_email,
    subject: `NEOCARE ${status.risk_status} reading alert for ${profile.name}`,
    text: `Automated NEOCARE reading alert for ${profile.name} (${profile.child_id}).

The latest device reading crossed a clinic-configured alert threshold:
Status: ${status.risk_status}
Reading time: ${reading.timestamp ?? "unknown"}
Heart rate: ${reading.heart_rate_bpm} bpm
SpO2: ${reading.spo2_percent}%
Temperature: ${reading.temperature_c} C
Respiratory rate: ${reading.respiratory_rate_br_min} breaths/min
Activity: ${reading.activity_state}

This automated notice is not a diagnosis or medical advice. Recheck the device reading and contact a qualified clinician if you are concerned. For an emergency, contact local emergency services.
`,
  });
  return "sent";
}

async function buildLatestReadingReport(childId: string, context: Context) {
  const user = await currentUser(context);
  const profile = await getChildProfile(childId, user);
  const reading = (await liveRef().child(childId).get()).val();
  if (!reading) throw new HttpError(409, "No sensor reading is available yet.");
  const resp = reading.respiratory_rate_br_min;
  const activity = reading.activity_state;
  if (resp == null || activity == null) {
    throw new HttpError(409, "The ESP32 must send resp_rate and activity to generate a recommendation report.");
  }
  const age = profile.age_years;
  const hr = reading.heart_rate_bpm;
  const spo2 = reading.spo2_percent;
  const temp = reading.temperature_c;
  const evaluation = analyzePediatricVitals(age, hr, spo2, temp, resp, activity);
  evaluation.causes = evaluation.causes.map((cause) =>
    cause.startsWith("3. Likely viral or bacterial infection")
      ? "These measurements alone cannot determine the cause; consult a clinician for interpretation."
      : cause
  );
  evaluation.recommendations = evaluation.recommendations.map((rec) =>
    rec.startsWith("Give weight-appropriate fever reducer")
      ? "For fever-care and medication guidance, contact a pediatric clinician; this report cannot advise medication or dosing."
      : rec
  );
  return {
    child_id: childId,
    child_name: profile.name,
    age_years: age,
    timestamp: reading.timestamp ?? "",
    activity_state: activity,
    heart_rate_bpm: hr,
    spo2_percent: spo2,
    temperature_c: temp,
    respiratory_rate_br_min: resp,
    ...evaluation,
    additional_recommendations: additionalRecommendations(age, hr, temp, activity, evaluation),
  };
}

// ---------- route handlers ----------

async function signup(req: Request, context: Context) {
  const data = validate(await readJson(req), SIGNUP);
  const email = data.email.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new HttpError(422, "Enter a valid email address.");
  const parentName = nonBlank(data.parent_name, "Parent name");
  const childName = nonBlank(data.child_name, "Child name");
  const phone = nonBlank(data.phone, "Phone");

  const parentId = randomUUID();
  const childId = await claimChildId({
    name: childName,
    age_years: data.age_years,
    height_cm: data.height_cm,
    weight_kg: data.weight_kg,
    parent_id: parentId,
    parent_email: email,
    parent_phone: phone,
    owner_parent_id: parentId,
  });
  try {
    await store.createParent(parentId, parentName, email, phone, data.password);
  } catch (error) {
    await profilesRef().child(childId).remove();
    if (error instanceof store.DuplicateEmailError) throw new HttpError(409, "An account with this email already exists.");
    throw error;
  }

  setSessionCookie(req, context, await store.createSession("parent", parentId, parentName));
  return Response.json({ role: "parent", display_name: parentName, child_id: childId });
}

async function login(req: Request, context: Context) {
  const data = validate(await readJson(req), LOGIN);
  let user: { role: string; user_id: string; display_name: string };
  if (data.role === "doctor") {
    const username = process.env.DOCTOR_USERNAME;
    const password = process.env.DOCTOR_PASSWORD;
    if (!username || !password) {
      throw new HttpError(503, "Doctor login is not configured. Set DOCTOR_USERNAME and DOCTOR_PASSWORD on the server.");
    }
    const usernameOk = safeEqual(data.identifier, username);
    const passwordOk = safeEqual(data.password, password);
    if (!usernameOk || !passwordOk) throw new HttpError(401, "Invalid doctor username or password.");
    user = { role: "doctor", user_id: username, display_name: "Clinic" };
  } else {
    const parent = await store.authenticateParent(data.identifier.trim().toLowerCase(), data.password);
    if (!parent) throw new HttpError(401, "Invalid email or password.");
    user = parent;
  }
  setSessionCookie(req, context, await store.createSession(user.role, user.user_id, user.display_name));
  return Response.json({ role: user.role, display_name: user.display_name });
}

async function logout(context: Context) {
  await store.deleteSession(context.cookies.get(SESSION_COOKIE));
  context.cookies.delete({ name: SESSION_COOKIE, path: "/" });
  return Response.json({ status: "signed_out" });
}

async function listChildren(context: Context) {
  const user = await currentUser(context);
  const [profiles, readings, thresholds] = await Promise.all([
    profilesRef().get().then((snap) => snap.val() || {}),
    liveRef().get().then((snap) => snap.val() || {}),
    store.getThresholds(),
  ]);
  const result = [];
  for (const childId of Object.keys(profiles).sort()) {
    const profile = profiles[childId];
    if (!profile || typeof profile !== "object") continue;
    if (user.role === "parent" && profile.owner_parent_id !== user.user_id) continue;
    const reading = readings[childId] ?? null;
    const child: Record<string, unknown> = {
      child_id: childId,
      ...profile,
      ...latestChildStatus(profile, reading, thresholds),
      latest_reading: reading,
    };
    if (user.role === "parent") {
      for (const key of ["owner_parent_id", "parent_id", "parent_email", "parent_phone"]) delete child[key];
    }
    result.push(child);
  }
  return Response.json(result);
}

async function saveChild(childId: string, req: Request, context: Context) {
  const user = await currentUser(context);
  const existing = await getChildProfile(childId, user);
  const data = validate(await readJson(req), CHILD_PROFILE);
  const profile = { ...existing, ...data, name: nonBlank(data.name, "Child name") };
  await profilesRef().child(childId).set(profile);
  return Response.json({ status: "saved", child_id: childId, ...profile });
}

async function createChild(req: Request, context: Context) {
  const user = await currentUser(context);
  if (user.role !== "parent") throw new HttpError(403, "Only a parent can create a child profile.");
  const parent = await store.parentById(user.user_id);
  if (!parent) throw new HttpError(401, "Parent account is no longer available.");
  const data = validate(await readJson(req), CHILD_PROFILE);
  const profile = {
    ...data,
    name: nonBlank(data.name, "Child name"),
    parent_id: user.user_id,
    parent_email: parent.email,
    parent_phone: parent.phone,
    owner_parent_id: user.user_id,
  };
  const childId = await claimChildId(profile);
  return Response.json({ status: "saved", child_id: childId, ...profile }, { status: 201 });
}

async function latestReading(childId: string, context: Context) {
  const user = await currentUser(context);
  await getChildProfile(childId, user);
  const reading = (await liveRef().child(childId).get()).val();
  if (!reading) return Response.json({ status: "waiting", child_id: childId });
  return Response.json({ status: "available", ...reading });
}

async function deleteChild(childId: string, context: Context) {
  const user = await currentUser(context);
  if (user.role !== "doctor") throw new HttpError(403, "Only clinic accounts can delete child profiles.");
  await getChildProfile(childId, user);
  await profilesRef().child(childId).remove();
  return Response.json({ status: "deleted", child_id: childId });
}

async function receiveReading(req: Request) {
  const configuredKey = process.env.ESP32_API_KEY;
  if (!configuredKey) throw new HttpError(503, "ESP32_API_KEY is not configured on the API server.");
  const apiKey = req.headers.get("x-api-key");
  if (!apiKey || !safeEqual(apiKey, configuredKey)) throw new HttpError(401, "Invalid or missing API key.");

  const reading = validate(await readJson(req), SENSOR_READING);
  const profile = (await profilesRef().child(reading.child_id).get()).val();
  if (!profile) throw new HttpError(404, "Unknown child_id.");

  const record: Record<string, unknown> = {
    child_id: reading.child_id,
    child_name: profile.name,
    age_years: profile.age_years,
    heart_rate_bpm: reading.heart_rate_bpm,
    spo2_percent: reading.spo2_percent,
    temperature_c: reading.temperature_c,
    timestamp: new Date().toISOString(),
    source_sensors: ["MAX30102", "MAX30205"],
  };
  if (reading.resp_rate !== undefined) record.respiratory_rate_br_min = reading.resp_rate;
  if (reading.activity !== undefined) record.activity_state = reading.activity;
  await liveRef().child(reading.child_id).set(record);

  const thresholds = await store.getThresholds();
  const status = latestChildStatus(profile, record, thresholds);
  const severity = alertSeverity(profile, record, thresholds);
  let notificationStatus = "thresholds_not_configured";
  if (thresholds) {
    const previous = await store.getAlertSeverity(reading.child_id);
    if (severity === null) {
      notificationStatus = "incomplete_reading_no_alert";
    } else if (severity === 0) {
      await store.saveAlertSeverity(reading.child_id, 0);
      notificationStatus = "recovered";
    } else if (severity > previous) {
      const severityName = status.risk_status;
      if (profile.owner_parent_id) {
        let emailStatus: string;
        try {
          emailStatus = await sendParentAlert({ ...profile, child_id: reading.child_id }, record, status);
        } catch (error) {
          console.error(`Could not send parent alert for ${reading.child_id}`, error);
          emailStatus = "failed";
        }
        await store.addAlert({
          child_id: reading.child_id,
          parent_id: profile.owner_parent_id,
          child_name: profile.name,
          severity: severityName,
          subject: `NEOCARE ${severityName} reading alert for ${profile.name}`,
          message: `Latest readings crossed a clinic-configured ${severityName.toLowerCase()} threshold. This automated notice is not a diagnosis.`,
          email_status: emailStatus,
        });
        notificationStatus = emailStatus;
      } else {
        notificationStatus = "parent_contact_not_configured";
      }
      await store.saveAlertSeverity(reading.child_id, severity);
    } else {
      notificationStatus = "same_episode_no_repeat";
    }
  }

  return Response.json({
    status: "stored",
    child_id: reading.child_id,
    timestamp: record.timestamp,
    measurements_received: ["heart_rate_bpm", "spo2_percent", "temperature_c"],
    notification_status: notificationStatus,
  });
}

async function route(req: Request, context: Context): Promise<Response> {
  const path = new URL(req.url).pathname.replace(/\/+$/, "") || "/";
  const method = req.method.toUpperCase();

  if (path === "/health") return Response.json({ status: "ok" });

  if (path === "/api/v1/auth/signup" && method === "POST") return signup(req, context);
  if (path === "/api/v1/auth/login" && method === "POST") return login(req, context);
  if (path === "/api/v1/auth/logout" && method === "POST") return logout(context);
  if (path === "/api/v1/auth/me" && method === "GET") {
    const user = await currentUser(context);
    return Response.json({ role: user.role, display_name: user.display_name });
  }

  if (path === "/api/v1/children") {
    if (method === "GET") return listChildren(context);
    if (method === "POST") return createChild(req, context);
  }

  const child = path.match(/^\/api\/v1\/children\/([^/]+)(\/.*)?$/);
  if (child) {
    const childId = decodeURIComponent(child[1]);
    const rest = child[2] ?? "";
    if (rest === "" && method === "PUT") return saveChild(childId, req, context);
    if (rest === "" && method === "DELETE") return deleteChild(childId, context);
    if (rest === "/readings/latest" && method === "GET") return latestReading(childId, context);
    if (rest === "/report/latest" && method === "GET") return Response.json(await buildLatestReadingReport(childId, context));
    if (rest === "/report/latest/pdf" && method === "GET") {
      const pdf = await generatePdfReport(await buildLatestReadingReport(childId, context));
      return new Response(Buffer.from(pdf), {
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": `attachment; filename="NEOCARE_${childId}_Report.pdf"`,
        },
      });
    }
  }

  if (path === "/api/v1/alerts" && method === "GET") {
    const user = await currentUser(context);
    return Response.json(await store.listAlerts(user.role, user.user_id));
  }

  if (path === "/api/v1/doctor/alert-thresholds") {
    if (method === "GET") {
      await requireDoctor(context);
      return Response.json({ thresholds: await store.getThresholds() });
    }
    if (method === "PUT") {
      await requireDoctor(context);
      const values = validate(await readJson(req), THRESHOLDS);
      if (values.temperature_warning_c >= values.temperature_critical_c) {
        throw new HttpError(422, "Warning temperature must be lower than critical temperature.");
      }
      await store.saveThresholds(values);
      return Response.json({ status: "saved", thresholds: values });
    }
  }

  if (path === "/api/v1/readings" && method === "POST") return receiveReading(req);

  throw new HttpError(404, "Not Found");
}

export default async (req: Request, context: Context) => {
  try {
    return await route(req, context);
  } catch (error) {
    if (error instanceof HttpError) return Response.json({ detail: error.detail }, { status: error.status });
    if (error instanceof store.ConfigError) return Response.json({ detail: error.message }, { status: 503 });
    console.error(error);
    return Response.json({ detail: "Internal server error." }, { status: 500 });
  }
};

export const config: Config = {
  path: ["/health", "/api/*"],
};
