import hmac
import logging
import os
import re
import smtplib
import sqlite3
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from fastapi.responses import FileResponse
from io import BytesIO

import auth_store
import main

BASE_DIR = Path(__file__).resolve().parent
logger = logging.getLogger(__name__)
PARENT_ID_PATTERN = re.compile(r"^child_[0-9]{2}$")
SIGNUP_LOCK = threading.Lock()


class SensorReading(BaseModel):
    model_config = ConfigDict(extra="forbid")

    child_id: str = Field(pattern=r"^child_[0-9]{2}$")
    heart_rate_bpm: float = Field(gt=0, le=250)
    spo2_percent: float = Field(ge=0, le=100)
    temperature_c: float = Field(ge=25, le=45)
    resp_rate: float | None = Field(default=None, gt=0, le=100)
    activity: Literal["Sleeping", "Resting", "Active"] | None = None


class ChildProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    age_years: float = Field(gt=0, le=18)
    height_cm: float = Field(gt=0, le=250)
    weight_kg: float = Field(gt=0, le=200)


class ParentSignup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parent_name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=5, max_length=254)
    phone: str = Field(min_length=7, max_length=30)
    password: str = Field(min_length=12, max_length=128)
    child_name: str = Field(min_length=1, max_length=80)
    age_years: float = Field(gt=0, le=18)
    height_cm: float = Field(gt=0, le=250)
    weight_kg: float = Field(gt=0, le=200)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("Enter a valid email address.")
        return value

    @field_validator("parent_name", "child_name", "phone")
    @classmethod
    def strip_nonempty(cls, value):
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank.")
        return value


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["doctor", "parent"]
    identifier: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class AlertThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spo2_min: float = Field(ge=75, le=100)
    temperature_warning_c: float = Field(ge=36, le=45)
    temperature_critical_c: float = Field(ge=36, le=45)
    heart_rate_max_age_0_3: float = Field(ge=30, le=250)
    heart_rate_max_age_over_3: float = Field(ge=30, le=250)
    respiratory_rate_max_age_0_3: float = Field(ge=10, le=100)
    respiratory_rate_max_age_over_3: float = Field(ge=10, le=100)

    @model_validator(mode="after")
    def warning_below_critical(self):
        if self.temperature_warning_c >= self.temperature_critical_c:
            raise ValueError("Warning temperature must be lower than critical temperature.")
        return self


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if os.getenv("VERCEL") == "1":
        os.environ.setdefault("NEOCARE_AUTH_STORAGE", "firebase")
    main.init_firebase()
    auth_database = main.db if os.getenv("NEOCARE_AUTH_STORAGE") == "firebase" else None
    auth_store.initialize(auth_database)
    yield


app = FastAPI(
    title="NEOCARE ESP32 Sensor API",
    description="Receives ESP32 sensor readings and stores the latest reading in Firebase.",
    lifespan=lifespan,
)


def verify_device_key(x_api_key: str | None) -> None:
    configured_key = os.getenv("ESP32_API_KEY")
    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail="ESP32_API_KEY is not configured on the API server.",
        )
    if not x_api_key or not hmac.compare_digest(x_api_key, configured_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


def current_user(request: Request):
    session = auth_store.get_session(request.cookies.get("neocare_session"))
    if session is None:
        raise HTTPException(status_code=401, detail="Please sign in.")
    return session


def require_doctor(request: Request):
    user = current_user(request)
    if user["role"] != "doctor":
        raise HTTPException(status_code=403, detail="Doctor access is required.")
    return user


def get_child_profile(child_id, user):
    if not PARENT_ID_PATTERN.fullmatch(child_id):
        raise HTTPException(status_code=422, detail="child_id must use the format child_01.")
    profile = main.db.reference("neocare_system/children_profiles").child(child_id).get()
    if not profile:
        raise HTTPException(status_code=404, detail="Child profile not found.")
    if user["role"] == "parent" and profile.get("owner_parent_id") != user["user_id"]:
        raise HTTPException(status_code=404, detail="Child profile not found.")
    return profile


def allocate_child_id(root_ref, profiles):
    readings = root_ref.child("live_monitoring").get() or {}
    used_ids = set(profiles) | set(readings)
    return next(
        (
            f"child_{number:02d}"
            for number in range(1, 100)
            if f"child_{number:02d}" not in used_ids
        ),
        None,
    )


def latest_child_status(profile, reading, thresholds=None):
    if not reading:
        return {"risk_status": "Waiting for readings", "condition": "No sensor data received"}
    resp_rate = reading.get("respiratory_rate_br_min")
    activity = reading.get("activity_state")
    age = float(profile.get("age_years", 0))
    hr = float(reading["heart_rate_bpm"])
    spo2 = float(reading["spo2_percent"])
    temp = float(reading["temperature_c"])
    if thresholds:
        young = age <= 3
        hr_limit = thresholds["heart_rate_max_age_0_3" if young else "heart_rate_max_age_over_3"]
        rr_limit = thresholds["respiratory_rate_max_age_0_3" if young else "respiratory_rate_max_age_over_3"]
        if spo2 < thresholds["spo2_min"]:
            return {"risk_status": "Critical", "condition": "SpO₂ below clinic alert threshold"}
        if temp >= thresholds["temperature_critical_c"]:
            return {"risk_status": "Critical", "condition": "Temperature above clinic critical threshold"}
        if temp >= thresholds["temperature_warning_c"]:
            return {"risk_status": "Warning", "condition": "Temperature above clinic warning threshold"}
        if activity in ("Sleeping", "Resting") and hr > hr_limit:
            return {"risk_status": "Warning", "condition": "Resting heart rate above clinic threshold"}
        if resp_rate is not None and rr_rate_exceeded(resp_rate, rr_limit):
            return {"risk_status": "Warning", "condition": "Respiratory rate above clinic threshold"}
        missing_fields = []
        if resp_rate is None:
            missing_fields.append("respiratory rate")
        if activity is None:
            missing_fields.append("activity")
        if missing_fields:
            return {
                "risk_status": "Incomplete reading",
                "condition": f"Missing {', '.join(missing_fields)}",
            }
        return {"risk_status": "Normal", "condition": "No configured alert thresholds exceeded"}
    if resp_rate is None or activity is None:
        return {"risk_status": "Incomplete reading", "condition": "Respiratory rate/activity missing"}
    return main.analyze_pediatric_vitals(age, hr, spo2, temp, resp_rate, activity)


def rr_rate_exceeded(resp_rate, limit):
    return float(resp_rate) > limit


def alert_severity(profile, reading, thresholds):
    if thresholds is None or not reading:
        return 0
    resp_rate = reading.get("respiratory_rate_br_min")
    activity = reading.get("activity_state")

    age = float(profile["age_years"])
    young = age <= 3
    if float(reading["spo2_percent"]) < thresholds["spo2_min"]:
        return 2
    temperature = float(reading["temperature_c"])
    if temperature >= thresholds["temperature_critical_c"]:
        return 2
    if temperature >= thresholds["temperature_warning_c"]:
        return 1
    if activity in ("Sleeping", "Resting"):
        hr_key = "heart_rate_max_age_0_3" if young else "heart_rate_max_age_over_3"
        if float(reading["heart_rate_bpm"]) > thresholds[hr_key]:
            return 1
    rr_key = (
        "respiratory_rate_max_age_0_3"
        if young
        else "respiratory_rate_max_age_over_3"
    )
    if resp_rate is not None and rr_rate_exceeded(resp_rate, thresholds[rr_key]):
        return 1
    if resp_rate is None or activity is None:
        return None
    return 0


def send_parent_alert(profile, reading, status):
    required = ("SMTP_HOST", "SMTP_FROM")
    if any(not os.getenv(key) for key in required):
        return "not_configured"
    recipient = profile.get("parent_email")
    if not recipient:
        return "no_parent_email"

    message = EmailMessage()
    message["Subject"] = f"NEOCARE {status['risk_status']} reading alert for {profile['name']}"
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = recipient
    message.set_content(
        f"""Automated NEOCARE reading alert for {profile['name']} ({profile['child_id']}).

The latest device reading crossed a clinic-configured alert threshold:
Status: {status['risk_status']}
Reading time: {reading.get('timestamp', 'unknown')}
Heart rate: {reading.get('heart_rate_bpm')} bpm
SpO2: {reading.get('spo2_percent')}%
Temperature: {reading.get('temperature_c')} C
Respiratory rate: {reading.get('respiratory_rate_br_min')} breaths/min
Activity: {reading.get('activity_state')}

This automated notice is not a diagnosis or medical advice. Recheck the device reading and contact a qualified clinician if you are concerned. For an emergency, contact local emergency services.
"""
    )
    host = os.environ["SMTP_HOST"]
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    timeout = 10
    if os.getenv("SMTP_USE_SSL", "").lower() == "true":
        with smtplib.SMTP_SSL(host, port, timeout=timeout) as smtp:
            if username and password:
                smtp.login(username, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(message)
    return "sent"


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/")
def dashboard():
    return FileResponse(BASE_DIR / "index.html")


@app.post("/api/v1/auth/signup")
def parent_signup(signup: ParentSignup, request: Request, response: Response):
    if len(signup.password) < 12:
        raise HTTPException(status_code=422, detail="Password must be at least 12 characters.")

    parent_id = str(uuid.uuid4())
    root_ref = main.db.reference("neocare_system")
    profiles_ref = root_ref.child("children_profiles")
    with SIGNUP_LOCK:
        profiles = profiles_ref.get() or {}
        child_id = allocate_child_id(root_ref, profiles)
        if child_id is None:
            raise HTTPException(status_code=409, detail="No available child IDs remain.")

        profile = {
            "name": signup.child_name,
            "age_years": signup.age_years,
            "height_cm": signup.height_cm,
            "weight_kg": signup.weight_kg,
            "parent_id": parent_id,
            "parent_email": signup.email,
            "parent_phone": signup.phone,
            "owner_parent_id": parent_id,
        }
        child_ref = profiles_ref.child(child_id)
        child_ref.set(profile)
        try:
            auth_store.create_parent(
                parent_id, signup.parent_name, signup.email, signup.phone, signup.password
            )
        except sqlite3.IntegrityError:
            child_ref.delete()
            raise HTTPException(
                status_code=409, detail="An account with this email already exists."
            ) from None
        except Exception:
            child_ref.delete()
            raise

    token = auth_store.create_session("parent", parent_id, signup.parent_name)
    response.set_cookie(
        "neocare_session",
        token,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        max_age=auth_store.SESSION_SECONDS,
        path="/",
    )
    return {
        "role": "parent",
        "display_name": signup.parent_name,
        "child_id": child_id,
    }


@app.post("/api/v1/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    if payload.role == "doctor":
        doctor_username = os.getenv("DOCTOR_USERNAME")
        doctor_password = os.getenv("DOCTOR_PASSWORD")
        if not doctor_username or not doctor_password:
            raise HTTPException(
                status_code=503,
                detail="Doctor login is not configured. Set DOCTOR_USERNAME and DOCTOR_PASSWORD on the server.",
            )
        valid = hmac.compare_digest(payload.identifier, doctor_username) and hmac.compare_digest(
            payload.password, doctor_password
        )
        if not valid:
            raise HTTPException(status_code=401, detail="Invalid doctor username or password.")
        user = {
            "role": "doctor",
            "user_id": doctor_username,
            "display_name": "Clinic",
        }
    else:
        user = auth_store.authenticate_parent(payload.identifier.strip().lower(), payload.password)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = auth_store.create_session(user["role"], user["user_id"], user["display_name"])
    response.set_cookie(
        "neocare_session",
        token,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        max_age=auth_store.SESSION_SECONDS,
        path="/",
    )
    return {"role": user["role"], "display_name": user["display_name"]}


@app.get("/api/v1/auth/me")
def who_am_i(request: Request):
    user = current_user(request)
    return {"role": user["role"], "display_name": user["display_name"]}


@app.post("/api/v1/auth/logout")
def logout(request: Request, response: Response):
    auth_store.delete_session(request.cookies.get("neocare_session"))
    response.delete_cookie("neocare_session", path="/", httponly=True, samesite="lax")
    return {"status": "signed_out"}


@app.get("/api/v1/children")
def list_children(request: Request):
    user = current_user(request)
    profiles = main.db.reference("neocare_system/children_profiles").get() or {}
    readings = main.db.reference("neocare_system/live_monitoring").get() or {}
    thresholds = auth_store.get_thresholds()
    result = []
    for child_id, profile in sorted(profiles.items()):
        if not isinstance(profile, dict):
            continue
        if user["role"] == "parent" and profile.get("owner_parent_id") != user["user_id"]:
            continue
        reading = readings.get(child_id)
        status = latest_child_status(profile, reading, thresholds)
        child_data = {
            "child_id": child_id,
            **profile,
            **status,
            "latest_reading": reading,
        }
        if user["role"] == "parent":
            child_data.pop("owner_parent_id", None)
            child_data.pop("parent_id", None)
            child_data.pop("parent_email", None)
            child_data.pop("parent_phone", None)
        result.append(child_data)
    return result


@app.put("/api/v1/children/{child_id}")
def save_child(child_id: str, profile: ChildProfile, request: Request):
    user = current_user(request)
    existing = get_child_profile(child_id, user)
    if user["role"] not in ("parent", "doctor"):
        raise HTTPException(status_code=403, detail="Profile editing is not allowed for this account.")
    profile_data = {
        **existing,
        **profile.model_dump(),
        "name": profile.name.strip(),
    }
    if not profile_data["name"]:
        raise HTTPException(status_code=422, detail="Child name cannot be blank.")
    main.db.reference("neocare_system/children_profiles").child(child_id).set(profile_data)
    return {"status": "saved", "child_id": child_id, **profile_data}


@app.post("/api/v1/children", status_code=201)
def create_child(profile: ChildProfile, request: Request):
    user = current_user(request)
    if user["role"] != "parent":
        raise HTTPException(status_code=403, detail="Only a parent can create a child profile.")
    parent = auth_store.parent_by_id(user["user_id"])
    if parent is None:
        raise HTTPException(status_code=401, detail="Parent account is no longer available.")

    profiles_ref = main.db.reference("neocare_system/children_profiles")
    root_ref = main.db.reference("neocare_system")
    with SIGNUP_LOCK:
        profiles = profiles_ref.get() or {}
        child_id = allocate_child_id(root_ref, profiles)
        if child_id is None:
            raise HTTPException(status_code=409, detail="No available child IDs remain.")
        data = {
            **profile.model_dump(),
            "name": profile.name.strip(),
            "parent_id": user["user_id"],
            "parent_email": parent["email"],
            "parent_phone": parent["phone"],
            "owner_parent_id": user["user_id"],
        }
        if not data["name"]:
            raise HTTPException(status_code=422, detail="Child name cannot be blank.")
        profiles_ref.child(child_id).set(data)
    return {"status": "saved", "child_id": child_id, **data}


@app.get("/api/v1/children/{child_id}/readings/latest")
def latest_reading(child_id: str, request: Request):
    user = current_user(request)
    get_child_profile(child_id, user)
    root_ref = main.db.reference("neocare_system")
    reading = root_ref.child("live_monitoring").child(child_id).get()
    if not reading:
        return {"status": "waiting", "child_id": child_id}
    return {"status": "available", **reading}


def build_latest_reading_report(child_id, request):
    user = current_user(request)
    root_ref = main.db.reference("neocare_system")
    profile = get_child_profile(child_id, user)
    reading = root_ref.child("live_monitoring").child(child_id).get()
    if not reading:
        raise HTTPException(status_code=409, detail="No sensor reading is available yet.")
    resp_rate = reading.get("respiratory_rate_br_min")
    activity = reading.get("activity_state")
    if resp_rate is None or activity is None:
        raise HTTPException(
            status_code=409,
            detail="The ESP32 must send resp_rate and activity to generate a recommendation report.",
        )

    age_years = profile["age_years"]
    heart_rate = reading["heart_rate_bpm"]
    spo2 = reading["spo2_percent"]
    temperature = reading["temperature_c"]
    evaluation = main.analyze_pediatric_vitals(
        age_years, heart_rate, spo2, temperature, resp_rate, activity
    )
    evaluation["causes"] = [
        (
            "These measurements alone cannot determine the cause; consult a clinician for interpretation."
            if cause.startswith("3. Likely viral or bacterial infection")
            else cause
        )
        for cause in evaluation["causes"]
    ]
    evaluation["recommendations"] = [
        (
            "For fever-care and medication guidance, contact a pediatric clinician; this report cannot advise medication or dosing."
            if recommendation.startswith("Give weight-appropriate fever reducer")
            else recommendation
        )
        for recommendation in evaluation["recommendations"]
    ]
    additional_recommendations = main.get_additional_recommendations(
        age_years, heart_rate, spo2, temperature, resp_rate, activity, evaluation
    )
    return {
        "child_id": child_id,
        "child_name": profile["name"],
        "age_years": age_years,
        "timestamp": reading.get("timestamp", ""),
        "activity_state": activity,
        "heart_rate_bpm": heart_rate,
        "spo2_percent": spo2,
        "temperature_c": temperature,
        "respiratory_rate_br_min": resp_rate,
        **evaluation,
        "additional_recommendations": additional_recommendations,
    }


@app.get("/api/v1/children/{child_id}/report/latest")
def latest_reading_report(child_id: str, request: Request):
    return build_latest_reading_report(child_id, request)


@app.get("/api/v1/children/{child_id}/report/latest/pdf")
def latest_reading_report_pdf(child_id: str, request: Request):
    report = build_latest_reading_report(child_id, request)
    pdf_bytes = main.generate_pdf_report(report, filename=None)
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="NEOCARE_{child_id}_Report.pdf"'
        },
    )


@app.delete("/api/v1/children/{child_id}")
def delete_child(child_id: str, request: Request):
    user = current_user(request)
    if user["role"] != "doctor":
        raise HTTPException(status_code=403, detail="Only clinic accounts can delete child profiles.")
    get_child_profile(child_id, user)
    main.db.reference("neocare_system/children_profiles").child(child_id).delete()
    return {"status": "deleted", "child_id": child_id}


@app.get("/api/v1/alerts")
def list_alerts(request: Request):
    user = current_user(request)
    return auth_store.list_alerts(user["role"], user["user_id"])


@app.get("/api/v1/doctor/alert-thresholds")
def get_doctor_thresholds(request: Request):
    require_doctor(request)
    return {"thresholds": auth_store.get_thresholds()}


@app.put("/api/v1/doctor/alert-thresholds")
def set_doctor_thresholds(thresholds: AlertThresholds, request: Request):
    require_doctor(request)
    values = thresholds.model_dump()
    auth_store.save_thresholds(values)
    return {"status": "saved", "thresholds": values}


@app.post("/api/v1/readings")
def receive_reading(
    reading: SensorReading,
    x_api_key: str | None = Header(default=None),
):
    verify_device_key(x_api_key)

    root_ref = main.db.reference("neocare_system")
    profile = root_ref.child("children_profiles").child(reading.child_id).get()
    if not profile:
        raise HTTPException(status_code=404, detail="Unknown child_id.")

    record = {
        "child_id": reading.child_id,
        "child_name": profile["name"],
        "age_years": profile["age_years"],
        "heart_rate_bpm": reading.heart_rate_bpm,
        "spo2_percent": reading.spo2_percent,
        "temperature_c": reading.temperature_c,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_sensors": ["MAX30102", "MAX30205"],
    }
    if reading.resp_rate is not None:
        record["respiratory_rate_br_min"] = reading.resp_rate
    if reading.activity is not None:
        record["activity_state"] = reading.activity
    root_ref.child("live_monitoring").child(reading.child_id).set(record)
    thresholds = auth_store.get_thresholds()
    status = latest_child_status(profile, record, thresholds)
    status_severity = alert_severity(profile, record, thresholds)
    notification_status = "thresholds_not_configured"
    if thresholds is not None:
        previous_severity = auth_store.get_alert_severity(reading.child_id)
        if status_severity is None:
            notification_status = "incomplete_reading_no_alert"
        elif status_severity == 0:
            auth_store.save_alert_severity(reading.child_id, 0)
            notification_status = "recovered"
        elif status_severity > previous_severity:
            severity_name = status["risk_status"]
            subject = f"NEOCARE {severity_name} reading alert for {profile['name']}"
            alert_message = (
                f"Latest readings crossed a clinic-configured {severity_name.lower()} "
                "threshold. This automated notice is not a diagnosis."
            )
            email_status = "not_configured"
            if profile.get("owner_parent_id"):
                try:
                    email_status = send_parent_alert(profile, record, status)
                except (OSError, smtplib.SMTPException, ValueError):
                    email_status = "failed"
                    logger.exception("Could not send parent alert for %s", reading.child_id)
                auth_store.add_alert(
                    reading.child_id,
                    profile["owner_parent_id"],
                    profile["name"],
                    severity_name,
                    subject,
                    alert_message,
                    email_status,
                )
                notification_status = email_status
            else:
                notification_status = "parent_contact_not_configured"
            auth_store.save_alert_severity(reading.child_id, status_severity)
        else:
            notification_status = "same_episode_no_repeat"

    return {
        "status": "stored",
        "child_id": reading.child_id,
        "timestamp": record["timestamp"],
        "measurements_received": ["heart_rate_bpm", "spo2_percent", "temperature_c"],
        "notification_status": notification_status,
    }
