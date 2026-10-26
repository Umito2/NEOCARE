import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from "pdf-lib";

export interface Evaluation {
  risk_status: string;
  condition: string;
  causes?: string[];
  recommendations?: string[];
}

// Pediatric rule engine (ages 1 - 6 years), ported from main.py.
export function analyzePediatricVitals(
  age: number, hr: number, spo2: number, temp: number, resp: number, activity: string
): Required<Evaluation> {
  let maxHr = age <= 3 ? 130 : 115;
  let maxRr = age <= 3 ? 34 : 26;
  if (activity === "Active") {
    maxHr += 25;
    maxRr += 12;
  }

  if (spo2 < 92) {
    return {
      risk_status: "Critical",
      condition: "Severe Hypoxemia & Respiratory Distress",
      causes: [
        `1. Critical drop in blood oxygen saturation (${spo2}%), below safe threshold (95%).`,
        `2. High respiratory rate (${resp} br/min) as lungs try to compensate for low oxygen.`,
        `3. Elevated heart rate (${hr} bpm) to pump remaining oxygen faster to vital organs.`,
      ],
      recommendations: [
        "EMERGENCY: Contact the doctor or head to the nearest emergency room immediately.",
        "Place the child in an upright sitting position to help open airways.",
        "Administer prescribed nebulizer or asthma bronchodilator immediately if applicable.",
      ],
    };
  }
  if (temp >= 38.0) {
    return {
      risk_status: temp < 39.0 ? "Warning" : "Critical",
      condition: "Fever-Induced Tachycardia",
      causes: [
        `1. Body temperature is elevated (${temp} C) above normal pediatric range (36.5 - 37.4 C).`,
        `2. Fast heart rate (${hr} bpm) triggered directly by high temperature (~10-15 bpm increase per 1 C).`,
        "3. Likely viral or bacterial infection accompanied by mild dehydration.",
      ],
      recommendations: [
        "Give weight-appropriate fever reducer (Paracetamol) and consult pediatrician.",
        "Apply lukewarm water compresses to neck and armpits (never use ice water).",
        "Increase oral fluids and water intake to prevent dehydration and calm heart rate.",
      ],
    };
  }
  if (hr > maxHr && (activity === "Resting" || activity === "Sleeping")) {
    return {
      risk_status: "Warning",
      condition: "Unexplained Resting Tachycardia",
      causes: [
        `1. Heart rate (${hr} bpm) exceeds normal resting threshold (${maxHr} bpm) for age ${age}.`,
        "2. Temperature and oxygen saturation are normal, ruling out fever or hypoxia.",
        "3. Potential causes include mild dehydration, sleep anxiety, or decongestant medication.",
      ],
      recommendations: [
        "Ensure the child is calm, resting comfortably, and well-hydrated.",
        "Check that the NEOCARE wristband is positioned properly on the wrist.",
        "Monitor for 15 minutes; if heart rate stays elevated, forward the PDF report to the doctor.",
      ],
    };
  }
  return {
    risk_status: "Normal",
    condition: activity !== "Active" ? "Optimal Health Status" : "Normal Physical Activity",
    causes: [
      `1. Heart rate (${hr} bpm) is within the healthy range for a ${age}-year-old child.`,
      `2. Blood oxygen level (${spo2}%) and breathing rate (${resp} br/min) show healthy lung function.`,
      `3. Body temperature (${temp} C) is normal and stable.`,
    ],
    recommendations: ["All vital signs are optimal! Continue daily monitoring via the NEOCARE app."],
  };
}

export function additionalRecommendations(
  age: number, hr: number, temp: number, activity: string, evaluation: Evaluation
): string[] {
  if (evaluation.risk_status === "Critical") return [];
  if (temp >= 38.0) {
    return [
      "Record when the fever began and any other symptoms to share with the child's clinician.",
      "If the temperature reading seems unexpected, recheck it according to the thermometer instructions.",
    ];
  }
  if (hr > (age <= 3 ? 130 : 115) && (activity === "Resting" || activity === "Sleeping")) {
    return [
      "Check the wearable's fit and repeat the reading after the child has been calm and resting.",
      "Note the time, activity, and any symptoms to share with the child's clinician.",
    ];
  }
  if (activity === "Active") {
    return [
      "Record that the reading was taken during activity and recheck after the child has rested.",
      "If the child seems unwell despite the reading, contact a pediatric clinician.",
    ];
  }
  return [
    "Record the time and activity with each reading so changes are easier to discuss with a clinician.",
    "If the child seems unwell despite reassuring readings, contact a pediatric clinician.",
  ];
}

// The standard PDF fonts only support WinAnsi characters.
const ascii = (text: unknown) => String(text ?? "").replace(/₂/g, "2").replace(/[^\x20-\x7E\xA0-\xFF]/g, "?");

export async function generatePdfReport(report: Record<string, any>): Promise<Uint8Array> {
  const pdf = await PDFDocument.create();
  const regular = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const italic = await pdf.embedFont(StandardFonts.HelveticaOblique);

  const margin = 28;
  let page: PDFPage = pdf.addPage([595.28, 841.89]);
  const width = page.getWidth() - margin * 2;
  let y = page.getHeight() - margin;

  const ensureSpace = (height: number) => {
    if (y - height < margin) {
      page = pdf.addPage([595.28, 841.89]);
      y = page.getHeight() - margin;
    }
  };

  const line = (text: string, font: PDFFont, size: number, color = rgb(0, 0, 0), align: "left" | "center" = "left", lineHeight = size * 1.6) => {
    ensureSpace(lineHeight);
    const value = ascii(text);
    const x = align === "center" ? margin + (width - font.widthOfTextAtSize(value, size)) / 2 : margin;
    page.drawText(value, { x, y: y - size, size, font, color });
    y -= lineHeight;
  };

  const paragraph = (text: string, font: PDFFont, size: number, color = rgb(0, 0, 0)) => {
    const words = ascii(text).split(" ");
    let current = "";
    for (const word of words) {
      const candidate = current ? `${current} ${word}` : word;
      if (font.widthOfTextAtSize(candidate, size) > width && current) {
        line(current, font, size, color, "left", size * 1.8);
        current = `    ${word}`;
      } else {
        current = candidate;
      }
    }
    if (current) line(current, font, size, color, "left", size * 1.8);
  };

  line("NEOCARE - Smart Pediatric Health Report", bold, 20, rgb(0, 0.5, 0.5), "center", 34);
  line(`Generated on: ${report.timestamp}`, regular, 10, rgb(0.4, 0.4, 0.4), "center", 23);
  y -= 17;
  line(
    `Patient Name: ${report.child_name}   |   Age: ${report.age_years} Years   |   Activity: ${report.activity_state}`,
    bold, 12, rgb(0, 0, 0), "left", 28
  );
  y -= 8;

  // Vital signs table
  const cellWidth = width / 4;
  const cellHeight = 28;
  const rows = [
    { font: bold, fill: true, values: ["Heart Rate", "Oxygen (SpO2)", "Temperature", "Resp. Rate"] },
    {
      font: regular,
      fill: false,
      values: [
        `${report.heart_rate_bpm} bpm`,
        `${report.spo2_percent} %`,
        `${report.temperature_c} C`,
        `${report.respiratory_rate_br_min} br/min`,
      ],
    },
  ];
  for (const row of rows) {
    row.values.forEach((value, index) => {
      const x = margin + index * cellWidth;
      page.drawRectangle({
        x, y: y - cellHeight, width: cellWidth, height: cellHeight,
        borderColor: rgb(0, 0, 0), borderWidth: 0.7,
        color: row.fill ? rgb(0.9, 0.96, 0.96) : undefined,
      });
      const text = ascii(value);
      page.drawText(text, {
        x: x + (cellWidth - row.font.widthOfTextAtSize(text, 11)) / 2,
        y: y - cellHeight / 2 - 4, size: 11, font: row.font,
      });
    });
    y -= cellHeight;
  }
  y -= 22;

  const statusColor =
    report.risk_status === "Critical" ? rgb(0.78, 0, 0) : report.risk_status === "Warning" ? rgb(0.82, 0.47, 0) : rgb(0, 0.55, 0.24);
  paragraph(`AI Assessment: [${report.risk_status}] - ${report.condition}`, bold, 13, statusColor);
  y -= 8;

  line("Detected Medical Causes:", bold, 12, rgb(0, 0, 0), "left", 23);
  for (const cause of report.causes ?? []) paragraph(`  ${cause}`, regular, 11);
  y -= 11;

  line("Care Recommendations:", bold, 12, rgb(0, 0, 0), "left", 23);
  for (const rec of report.recommendations ?? []) paragraph(`  * ${rec}`, regular, 11);

  const extra: string[] = report.additional_recommendations ?? [];
  if (extra.length) {
    y -= 11;
    line("Additional Local Suggestions (not medical advice):", bold, 12, rgb(0, 0, 0), "left", 23);
    paragraph(
      "These suggestions are generated locally from simple rules. They do not replace advice from a pediatric clinician.",
      regular, 11
    );
    for (const rec of extra) paragraph(`  * ${rec}`, regular, 11);
  }

  y -= 22;
  paragraph(
    "This rule-based report is not a medical diagnosis or medical advice. Consult a qualified pediatric clinician for interpretation.",
    italic, 9, rgb(0.35, 0.35, 0.35)
  );

  return pdf.save();
}
