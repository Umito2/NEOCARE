import glob
import json
import os
import base64
import firebase_admin
from firebase_admin import credentials, db
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# ==========================================
# 1. FIREBASE CONFIGURATION
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVICE_ACCOUNT_FILE = os.path.join(BASE_DIR, "serviceAccountKey.json")
LEGACY_SERVICE_ACCOUNT_FILE = os.path.join(BASE_DIR, "serviceAccountKey.json.json")
DATABASE_URL = "https://neocare-system-default-rtdb.firebaseio.com/"


def find_service_account_file():
    for candidate in (SERVICE_ACCOUNT_FILE, LEGACY_SERVICE_ACCOUNT_FILE):
        if os.path.isfile(candidate):
            return candidate

    for match in sorted(glob.glob(os.path.join(BASE_DIR, "*serviceAccountKey*.json*"))):
        if os.path.isfile(match):
            return match

    return None


def init_firebase():
    global SERVICE_ACCOUNT_FILE

    if not firebase_admin._apps:
        service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
        service_account_base64 = os.getenv("FIREBASE_SERVICE_ACCOUNT_BASE64")
        if service_account_json:
            service_account_info = json.loads(service_account_json)
            cred = credentials.Certificate(service_account_info)
        elif service_account_base64:
            service_account_info = json.loads(
                base64.b64decode(service_account_base64, validate=True)
            )
            cred = credentials.Certificate(service_account_info)
        else:
            resolved_file = find_service_account_file()
            if resolved_file is None:
                raise FileNotFoundError(
                    "Firebase credentials are missing. Set "
                    "FIREBASE_SERVICE_ACCOUNT_JSON on the server, or put "
                    "serviceAccountKey.json beside main.py for local development."
                )
            SERVICE_ACCOUNT_FILE = resolved_file
            cred = credentials.Certificate(SERVICE_ACCOUNT_FILE)
        firebase_admin.initialize_app(cred, {
            'databaseURL': os.getenv("FIREBASE_DATABASE_URL", DATABASE_URL)
        })
    print("[SUCCESS] Connected to NEOCARE Firebase Realtime Database!")


# ==========================================
# 2. PEDIATRIC AI ENGINE (Ages 1 - 6 Years)
# ==========================================
def analyze_pediatric_vitals(age_years, hr, spo2, temp, resp_rate, activity):
    """
    Analyzes child vitals and returns status, condition, causes (1, 2, 3), and recommendations.
    """
    max_normal_hr = 130 if age_years <= 3 else 115
    max_normal_rr = 34 if age_years <= 3 else 26

    if activity == "Active":
        max_normal_hr += 25
        max_normal_rr += 12

    if spo2 < 92:
        return {
            "risk_status": "Critical",
            "condition": "Severe Hypoxemia & Respiratory Distress",
            "causes": [
                f"1. Critical drop in blood oxygen saturation ({spo2}%), below safe threshold (95%).",
                f"2. High respiratory rate ({resp_rate} br/min) as lungs try to compensate for low oxygen.",
                f"3. Elevated heart rate ({hr} bpm) to pump remaining oxygen faster to vital organs."
            ],
            "recommendations": [
                "EMERGENCY: Contact the doctor or head to the nearest emergency room immediately.",
                "Place the child in an upright sitting position to help open airways.",
                "Administer prescribed nebulizer or asthma bronchodilator immediately if applicable."
            ]
        }

    elif temp >= 38.0:
        return {
            "risk_status": "Warning" if temp < 39.0 else "Critical",
            "condition": "Fever-Induced Tachycardia",
            "causes": [
                f"1. Body temperature is elevated ({temp} C) above normal pediatric range (36.5 - 37.4 C).",
                f"2. Fast heart rate ({hr} bpm) triggered directly by high temperature (~10-15 bpm increase per 1 C).",
                "3. Likely viral or bacterial infection accompanied by mild dehydration."
            ],
            "recommendations": [
                "Give weight-appropriate fever reducer (Paracetamol) and consult pediatrician.",
                "Apply lukewarm water compresses to neck and armpits (never use ice water).",
                "Increase oral fluids and water intake to prevent dehydration and calm heart rate."
            ]
        }

    elif hr > max_normal_hr and activity in ["Resting", "Sleeping"]:
        return {
            "risk_status": "Warning",
            "condition": "Unexplained Resting Tachycardia",
            "causes": [
                f"1. Heart rate ({hr} bpm) exceeds normal resting threshold ({max_normal_hr} bpm) for age {age_years}.",
                "2. Temperature and oxygen saturation are normal, ruling out fever or hypoxia.",
                "3. Potential causes include mild dehydration, sleep anxiety, or decongestant medication."
            ],
            "recommendations": [
                "Ensure the child is calm, resting comfortably, and well-hydrated.",
                "Check that the NEOCARE wristband is positioned properly on the wrist.",
                "Monitor for 15 minutes; if heart rate stays elevated, forward the PDF report to the doctor."
            ]
        }

    else:
        return {
            "risk_status": "Normal",
            "condition": "Optimal Health Status" if activity != "Active" else "Normal Physical Activity",
            "causes": [
                f"1. Heart rate ({hr} bpm) is within the healthy range for a {age_years}-year-old child.",
                f"2. Blood oxygen level ({spo2}%) and breathing rate ({resp_rate} br/min) show healthy lung function.",
                f"3. Body temperature ({temp} C) is normal and stable."
            ],
            "recommendations": [
                "All vital signs are optimal! Continue daily monitoring via the NEOCARE app."
            ]
        }


def get_additional_recommendations(age_years, hr, spo2, temp, resp_rate, activity, evaluation):
    if evaluation["risk_status"] == "Critical":
        return []

    if temp >= 38.0:
        return [
            "Record when the fever began and any other symptoms to share with the child's clinician.",
            "If the temperature reading seems unexpected, recheck it according to the thermometer instructions.",
        ]

    if hr > (130 if age_years <= 3 else 115) and activity in ["Resting", "Sleeping"]:
        return [
            "Check the wearable's fit and repeat the reading after the child has been calm and resting.",
            "Note the time, activity, and any symptoms to share with the child's clinician.",
        ]

    if activity == "Active":
        return [
            "Record that the reading was taken during activity and recheck after the child has rested.",
            "If the child seems unwell despite the reading, contact a pediatric clinician.",
        ]

    return [
        "Record the time and activity with each reading so changes are easier to discuss with a clinician.",
        "If the child seems unwell despite reassuring readings, contact a pediatric clinician.",
    ]


# ==========================================
# 3. AUTOMATIC PDF REPORT GENERATOR
# ==========================================
def generate_pdf_report(report_data, filename="NEOCARE_Health_Report.pdf"):
    """
    Creates a structured medical PDF report containing child info, vitals, causes (1,2,3), and recommendations.
    """
    pdf = FPDF()
    pdf.add_page()

    # Title Header
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(0, 128, 128)  # NEOCARE Teal Color
    pdf.cell(
        0, 12, "NEOCARE - Smart Pediatric Health Report",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C"
    )

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(
        0, 8, f"Generated on: {report_data['timestamp']}",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C"
    )
    pdf.ln(6)

    # Child Information Section
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(
        0, 10,
        f"Patient Name: {report_data['child_name']}   |   Age: {report_data['age_years']} Years   |   Activity: {report_data['activity_state']}",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    pdf.ln(3)

    # Vital Signs Table
    pdf.set_fill_color(230, 245, 245)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(47, 10, "Heart Rate", border=1, align="C", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(47, 10, "Oxygen (SpO2)", border=1, align="C", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(47, 10, "Temperature", border=1, align="C", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(47, 10, "Resp. Rate", border=1, align="C", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 11)
    pdf.cell(47, 10, f"{report_data['heart_rate_bpm']} bpm", border=1, align="C", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(47, 10, f"{report_data['spo2_percent']} %", border=1, align="C", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(47, 10, f"{report_data['temperature_c']} C", border=1, align="C", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(47, 10, f"{report_data['respiratory_rate_br_min']} br/min", border=1, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(8)

    # AI Diagnosis Status
    pdf.set_font("Helvetica", "B", 13)
    status = report_data["risk_status"]
    if status == "Critical":
        pdf.set_text_color(200, 0, 0)
    elif status == "Warning":
        pdf.set_text_color(210, 120, 0)
    else:
        pdf.set_text_color(0, 140, 60)

    pdf.cell(
        0, 10, f"AI Assessment: [{status}] - {report_data['condition']}",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    pdf.ln(3)

    # Causes (1, 2, 3)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Detected Medical Causes:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    for cause in report_data["causes"]:
        pdf.multi_cell(
            pdf.epw, 7, f"  {cause}",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
    pdf.ln(4)

    # Recommendations
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Care Recommendations:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    for rec in report_data["recommendations"]:
        pdf.multi_cell(
            pdf.epw, 7, f"  * {rec}",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )

    additional_recommendations = report_data.get("additional_recommendations", [])
    if additional_recommendations:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(
            0, 8, "Additional Local Suggestions (not medical advice):",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(
            pdf.epw, 7,
            "These suggestions are generated locally from simple rules. They do not replace advice from a pediatric clinician.",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        for rec in additional_recommendations:
            pdf.multi_cell(
                pdf.epw, 7, f"  * {rec}",
                new_x=XPos.LMARGIN, new_y=YPos.NEXT
            )

    pdf.set_text_color(90, 90, 90)
    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 9)
    pdf.multi_cell(
        pdf.epw,
        6,
        "This rule-based report is not a medical diagnosis or medical advice. "
        "Consult a qualified pediatric clinician for interpretation.",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )

    if filename is None:
        return bytes(pdf.output())

    output_path = filename if os.path.isabs(filename) else os.path.join(BASE_DIR, filename)
    pdf.output(output_path)
    print(f"[PDF GENERATED] Saved medical report to: {os.path.abspath(output_path)}")
    return None


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api:app", host="0.0.0.0", port=8000)