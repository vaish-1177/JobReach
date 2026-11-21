import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  detectLanguage,
  exportReportToMarkdown,
  extractStructuredJobData,
  inspectUrlStructurally,
  redactSensitiveInfo,
  runLocalVerification,
} from "../frontend/src/engine/localEngine.mjs";

test("1. Detects English advance registration fee scam as HIGH RISK with 7 categories", () => {
  const rep = runLocalVerification({
    text: "Company: Apex Global\nRole: Operations Executive\nSelected without interview. Pay ₹999 registration fee today.",
  });
  assert.equal(rep.risk_level, "HIGH RISK");
  assert.equal(rep.categories.length, 7);
  assert.ok(rep.suspicious_indicator_count >= 2);
});

test("2. Detects Hindi and Hinglish recruitment fraud signals", () => {
  const hi = runLocalVerification({ text: "बिना इंटरव्यू के नौकरी पाने के लिए ₹2,000 सिक्योरिटी डिपॉजिट दें।" });
  assert.equal(hi.detected_language, "hi");
  assert.equal(hi.risk_level, "HIGH RISK");

  const hinglish = runLocalVerification({ text: "Job ke liye pehle ₹1500 registration fees jama karo." });
  assert.equal(hinglish.detected_language, "hinglish");
  assert.equal(hinglish.risk_level, "HIGH RISK");
});

test("3. Negation handling: anti-fraud disclaimer does not trigger false positive", () => {
  const rep = runLocalVerification({
    text: "Company: Infosys Limited\nRole: Software Engineer\nApply at https://www.infosys.com/careers/ or careers@infosys.com. Never pay any registration fee during recruitment.",
  });
  assert.equal(rep.risk_level, "LOW RISK");
  assert.equal(rep.suspicious_indicator_count, 0);
});

test("4. Word 'urgent' alone does not trigger HIGH RISK", () => {
  const rep = runLocalVerification({
    text: "Company: Razorpay\nRole: Backend Software Engineer\nUrgent reminder: confirm interview via recruiting@razorpay.com.",
  });
  assert.equal(rep.risk_level, "LOW RISK");
});

test("5. Zero-visit URL inspector flags fake Infosys career portal", () => {
  const res = inspectUrlStructurally("https://infosys.careers-verification.xyz/apply");
  assert.equal(res.risk_level, "HIGH RISK");
  assert.equal(res.registrable_domain, "careers-verification.xyz");
  assert.equal(res.impersonated_brand, "INFOSYS");
});

test("6. Unknown company is marked Unverified, not fraudulent", () => {
  const rep = runLocalVerification({
    text: "Company: GreenLeaf Robotics\nRole: Firmware Engineer\nSalary: 8 LPA\nEmail: hr@greenleafrobotics.in",
  });
  assert.equal(rep.risk_level, "LOW RISK");
  assert.equal(rep.categories[0].overall_status, "Unverified");
});

test("7. PII redaction masks Aadhaar, PAN, IFSC, OTP/PIN, and bank account", () => {
  const { redacted, counts } = redactSensitiveInfo(
    "Aadhaar 2345 6789 0123 PAN ABCDE1234F IFSC HDFC0001234 OTP: 981234"
  );
  assert.ok(!redacted.includes("2345 6789 0123"));
  assert.ok(!redacted.includes("ABCDE1234F"));
  assert.ok(!redacted.includes("HDFC0001234"));
  assert.ok(!redacted.includes("981234"));
  assert.ok(Object.keys(counts).length >= 4);
});

test("8. Structured 10-field extraction leaves missing fields explicitly missing", () => {
  const ext = extractStructuredJobData("Company: Zoho\nRole: Frontend Developer");
  assert.equal(ext.employer.status, "extracted");
  assert.equal(ext.requisition_id.status, "missing");
  assert.equal(ext.requisition_id.value, null);
});

test("9. Markdown report export includes risk level and all 7 categories", () => {
  const rep = runLocalVerification({ text: "Company: Infosys\nRole: Systems Engineer" });
  const md = exportReportToMarkdown(rep);
  assert.ok(md.includes("# JobGuard AI — Evidence-Based Verification Report"));
  assert.ok(md.includes("7. Document and Message Consistency"));
});

test("10. Production bundle frontend/dist/index.html exists and contains JobGuard AI", () => {
  const distFile = path.resolve("frontend/dist/index.html");
  const html = fs.readFileSync(distFile, "utf-8");
  assert.ok(html.includes("JobGuard AI"));
  assert.ok(html.includes("Before You Trust the Offer, Verify the Evidence."));
  assert.ok(html.includes("Tesseract"));
  assert.ok(html.includes("1930"));
});

test("11. Calibrated v2 engine catches real-world WhatsApp/Telegram/UPI/task scams as HIGH RISK (>=60)", () => {
  const scams = [
    "Hello! Your resume has been shortlisted for part time online job. Work 1-2 hours daily on mobile and earn ₹2000-₹5000 per day. No experience needed. Reply YES on WhatsApp +91 9876543210.",
    "Earn ₹150 per YouTube video like and subscribe. Daily payout directly to bank. Join Telegram t.me/vip_tasks_india now!",
    "Congratulations! You are selected for Amazon WFH. Send ₹499 via GPay/PhonePe to 9876543210@ybl and share payment screenshot.",
    "Online form filling and captcha typing job from home. Earn ₹45,000 per month. 10th 12th pass can apply. Pay ₹800 agreement charge.",
    "Guaranteed MNC placement internship! Pay ₹3500 mandatory training fee for certificate and 100% job guarantee.",
    "Send your Aadhaar card, PAN card, and bank passbook photo on WhatsApp immediately to confirm joining.",
  ];
  for (const msg of scams) {
    const rep = runLocalVerification({ text: msg });
    assert.equal(rep.risk_level, "HIGH RISK", `Expected HIGH RISK for: ${msg} (got ${rep.risk_index})`);
    assert.ok(rep.risk_index >= 60, `Expected score >= 60 for: ${msg} (got ${rep.risk_index})`);
    assert.ok(rep.score_breakdown, "Expected transparent score_breakdown");
  }
});

test("12. Legitimate messages score LOW RISK (<=18) and avoid the old 26-score trap", () => {
  const legits = [
    "Hi, we are a Series A startup hiring a Full-Stack Developer (React + Node.js, 12-16 LPA) in Pune Hybrid. Email jobs@finpulse.in for a technical interview.",
    "Hi Yuvraj, saw your GitHub portfolio. We have an opening for a Junior Python Developer at Acme Labs, Noida (6-8 LPA). Open to a quick Google Meet call?",
    "भर्ती के दौरान कोई शुल्क नहीं लिया जाता है। कृपया केवल आधिकारिक वेबसाइट पर आवेदन करें।",
  ];
  for (const msg of legits) {
    const rep = runLocalVerification({ text: msg });
    assert.equal(rep.risk_level, "LOW RISK", `Expected LOW RISK for: ${msg} (got ${rep.risk_index})`);
    assert.ok(rep.risk_index <= 18, `Expected score <= 18 for: ${msg} (got ${rep.risk_index})`);
  }
});
