"""Comprehensive automated backend test suite for JobGuard AI."""
from __future__ import annotations

import io
import unittest
from docx import Document
from fastapi.testclient import TestClient

from backend.main import app
from backend.schemas import EvidenceStatus, RiskLevel
from backend.security import redact_sensitive_info
from backend.url_inspector import inspect_url_structurally


class TestJobGuardBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def test_01_health_and_frontend_served(self) -> None:
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["service"], "JobGuard AI")
        root = self.client.get("/")
        self.assertEqual(root.status_code, 200)
        self.assertIn("JobGuard AI", root.text)

    def test_02_advance_fee_english_scam_high_risk(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": "Company: Apex Global\nRole: Data Entry\nPay ₹999 registration fee to confirm your job today. Selected without interview."
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["risk_level"], RiskLevel.HIGH.value)
        self.assertEqual(len(data["categories"]), 7)
        self.assertGreaterEqual(data["suspicious_indicator_count"], 2)

    def test_03_hinglish_registration_fee_detected(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={"text": "Job ke liye pehle ₹1500 registration fees jama karo aur bina interview ke direct joining pao."},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["detected_language"], "hinglish")
        self.assertEqual(data["risk_level"], RiskLevel.HIGH.value)

    def test_04_hindi_security_deposit_detected(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={"text": "बिना इंटरव्यू के नौकरी पाने के लिए ₹2,000 सिक्योरिटी डिपॉजिट दें।"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["detected_language"], "hi")
        self.assertEqual(data["risk_level"], RiskLevel.HIGH.value)

    def test_05_anti_fraud_disclaimer_not_false_positive(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": (
                    "Company: Infosys Limited\nRole: Software Engineer\nLocation: Bengaluru\n"
                    "Apply at https://www.infosys.com/careers/ or email careers@infosys.com.\n"
                    "Important: Never pay any registration fee during recruitment. Infosys does not charge any fee."
                )
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["risk_level"], RiskLevel.LOW.value)
        self.assertEqual(data["suspicious_indicator_count"], 0)

    def test_06_urgent_word_alone_not_high_risk(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": (
                    "Company: Razorpay\nRole: Backend Engineer\nLocation: Bengaluru\n"
                    "Urgent reminder: please confirm your technical interview slot via recruiting@razorpay.com."
                )
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertNotEqual(data["risk_level"], RiskLevel.HIGH.value)
        self.assertEqual(data["risk_level"], RiskLevel.LOW.value)

    def test_07_unknown_company_marked_unverified_not_fraud(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": (
                    "Company: Sunrise Agritech Solutions\nRole: Field Analyst\nSalary: 6 LPA\n"
                    "Location: Lucknow\nApply via careers@sunriseagritech.in for technical interview."
                )
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["risk_level"], RiskLevel.LOW.value)
        emp_cat = data["categories"][0]
        self.assertEqual(emp_cat["category_name"], "Employer Identity")
        self.assertEqual(emp_cat["overall_status"], EvidenceStatus.UNVERIFIED.value)

    def test_08_fake_infosys_career_portal_impersonation(self) -> None:
        res = inspect_url_structurally("https://infosys.careers-verification.xyz/apply")
        self.assertEqual(res.risk_level, RiskLevel.HIGH)
        self.assertEqual(res.registrable_domain, "careers-verification.xyz")
        self.assertEqual(res.impersonated_brand, "INFOSYS")

    def test_09_url_shortener_raw_ip_punycode_and_dangerous_scheme(self) -> None:
        ip_res = inspect_url_structurally("http://192.168.1.50/hr-login")
        self.assertTrue(ip_res.is_ip_address)
        self.assertGreaterEqual(ip_res.risk_index, 55)

        puny = inspect_url_structurally("https://xn--infsys-cwa.com/careers")
        self.assertTrue(puny.has_punycode_or_idn)

        js_res = inspect_url_structurally("javascript:alert(1)")
        self.assertEqual(js_res.risk_level, RiskLevel.HIGH)

    def test_10_email_domain_mismatch_and_personal_email(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": "Company: Tata Consultancy Services (TCS)\nRole: Developer\nSend resume to tcs.hr.desk2026@gmail.com"
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        cat4 = data["categories"][3]
        self.assertEqual(cat4["category_name"], "Email and Domain Alignment")
        self.assertEqual(cat4["overall_status"], EvidenceStatus.SUSPICIOUS_SIGNAL.value)

    def test_11_cross_document_consistency_conflict(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": "Company: Infosys Limited\nRole: Systems Engineer\nSalary: 5 LPA\nLocation: Bengaluru",
                "secondary_text": "Company: GlobalTech Staffing\nRole: Data Entry Operator\nSalary: ₹15,000 per month\nLocation: Noida",
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        cat7 = data["categories"][6]
        self.assertEqual(cat7["overall_status"], EvidenceStatus.INCONSISTENT.value)
        self.assertGreaterEqual(data["inconsistent_check_count"], 1)

    def test_12_unavailable_providers_never_marked_confirmed(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={"text": "Company: Razorpay\nRole: Backend Engineer\nRequisition ID: RZP-100"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        cat2 = data["categories"][1]
        self.assertEqual(cat2["category_name"], "Vacancy and Requisition Verification")
        statuses = [rec["status"] for rec in cat2["records"]]
        self.assertIn(EvidenceStatus.CHECK_UNAVAILABLE.value, statuses)
        self.assertNotIn(EvidenceStatus.CONFIRMED_BY_SOURCE.value, statuses)

    def test_13_pre_analysis_10_field_extraction_and_edits(self) -> None:
        r = self.client.post(
            "/api/extract",
            json={"text": "Company: Zoho\nRole: Software Developer\nSalary: 8 LPA\nLocation: Chennai"},
        )
        self.assertEqual(r.status_code, 200)
        ext = r.json()
        self.assertEqual(ext["employer"]["status"], "extracted")
        self.assertEqual(ext["requisition_id"]["status"], "missing")
        self.assertIsNone(ext["requisition_id"]["value"])

        v = self.client.post(
            "/api/verify",
            json={
                "text": "Company: Zoho\nRole: Software Developer",
                "edited_fields": {"requisition_id": "ZOHO-2026-42"},
            },
        )
        self.assertEqual(v.status_code, 200)
        self.assertEqual(v.json()["extracted_data"]["requisition_id"]["value"], "ZOHO-2026-42")

    def test_14_document_extraction_txt_and_docx_and_invalid(self) -> None:
        # TXT
        r_txt = self.client.post(
            "/api/extract/document",
            files={"file": ("offer.txt", b"Company: Infosys\nRole: Analyst\nSalary: 6 LPA", "text/plain")},
        )
        self.assertEqual(r_txt.status_code, 200)
        self.assertEqual(r_txt.json()["file_type"], "txt")
        self.assertEqual(r_txt.json()["extracted_fields"]["employer"]["value"], "Infosys")

        # DOCX
        doc = Document()
        doc.add_paragraph("Company: Wipro Limited")
        doc.add_paragraph("Role: Project Engineer")
        buf = io.BytesIO()
        doc.save(buf)
        r_docx = self.client.post(
            "/api/extract/document",
            files={
                "file": (
                    "offer.docx",
                    buf.getvalue(),
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            },
        )
        self.assertEqual(r_docx.status_code, 200)
        self.assertEqual(r_docx.json()["file_type"], "docx")
        self.assertIn("Wipro", r_docx.json()["extracted_text"])

        # Unsupported extension
        r_bad = self.client.post(
            "/api/extract/document",
            files={"file": ("malware.exe", b"MZ...", "application/octet-stream")},
        )
        self.assertEqual(r_bad.status_code, 400)

    def test_15_privacy_redaction(self) -> None:
        sample = "Aadhaar 2345 6789 0123, PAN ABCDE1234F, IFSC SBIN0001234, OTP is 482910, Account No: 123456789012"
        redacted, counts = redact_sensitive_info(sample)
        self.assertNotIn("2345 6789 0123", redacted)
        self.assertNotIn("ABCDE1234F", redacted)
        self.assertNotIn("SBIN0001234", redacted)
        self.assertNotIn("482910", redacted)
        self.assertNotIn("123456789012", redacted)
        self.assertGreaterEqual(len(counts), 4)

    def test_16_api_error_handling_empty_payload(self) -> None:
        r = self.client.post("/api/verify", json={"text": "   "})
        self.assertEqual(r.status_code, 400)

    def test_17_ml_info_transparent_metrics(self) -> None:
        r = self.client.get("/api/ml/info")
        self.assertEqual(r.status_code, 200)
        info = r.json()
        self.assertIn("evaluation_metrics", info)
        self.assertIn("limitation", info)



    def test_18_real_world_scam_accuracy_no_26_trap(self) -> None:
        scams = [
            "Hello! Your resume has been shortlisted for part time online job. Work 1-2 hours daily on mobile and earn ₹2000-₹5000 per day. No experience needed. Reply YES on WhatsApp +91 9876543210.",
            "Earn ₹150 per YouTube video like and subscribe. Daily payout directly to bank. Join Telegram t.me/vip_tasks_india now!",
            "Congratulations! You are selected for Amazon WFH. Send ₹499 via GPay/PhonePe to 9876543210@ybl and share payment screenshot to get offer letter.",
            "Online form filling and captcha typing job from home. Earn ₹45,000 per month. 10th 12th pass can apply. Pay ₹800 agreement charge.",
            "Guaranteed MNC placement internship! Pay ₹3500 mandatory training fee for certificate and 100% job guarantee.",
            "Salary paid in USDT crypto for daily app optimization tasks on Telegram. Invest ₹1000 and withdraw ₹1400.",
            "Send your Aadhaar card, PAN card, and bank passbook photo on WhatsApp immediately to confirm joining.",
            "Your salary account verification is pending. Install AnyDesk and share the 9 digit code with HR immediately.",
        ]
        for msg in scams:
            r = self.client.post("/api/verify", json={"text": msg})
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertEqual(data["risk_level"], RiskLevel.HIGH.value, f"Failed on: {msg}")
            self.assertGreaterEqual(data["risk_index"], 60, f"Score too low on: {msg}")

    def test_19_legitimate_messages_score_low_not_26(self) -> None:
        legits = [
            "Hi, we are a Series A startup hiring a Full-Stack Developer (React + Node.js, 12-16 LPA) in Pune Hybrid. Email jobs@finpulse.in for a technical interview.",
            "Hi Yuvraj, saw your GitHub portfolio. We have an opening for a Junior Python Developer at Acme Labs, Noida (6-8 LPA). Open to a quick Google Meet call?",
            "भर्ती के दौरान कोई शुल्क नहीं लिया जाता है। कृपया केवल आधिकारिक वेबसाइट पर आवेदन करें।",
        ]
        for msg in legits:
            r = self.client.post("/api/verify", json={"text": msg})
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertEqual(data["risk_level"], RiskLevel.LOW.value, f"False positive on: {msg}")
            self.assertLessEqual(data["risk_index"], 18, f"Score too high on: {msg}")

if __name__ == "__main__":
    unittest.main()
