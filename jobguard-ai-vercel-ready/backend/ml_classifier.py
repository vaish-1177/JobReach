"""Secondary ML Layer: Reproducible Pure-Python TF-IDF (Unigram + Bigram) + L2 Logistic Regression.

Trains deterministically at startup on a 96-sample balanced synthetic corpus
(English, Hindi, and Hinglish real-world recruitment scams vs. legitimate messages).
All evaluation metrics are computed directly on a deterministic 25% held-out split,
and the synthetic dataset limitation is transparently disclosed in every report.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Tuple

from .schemas import MLAssessment

# Balanced 96-sample synthetic corpus (48 scam = 1, 48 legitimate = 0) across EN / HI / Hinglish
LABELED_SYNTHETIC_DATASET: List[Tuple[str, int]] = [
    # --- FRAUDULENT EXAMPLES (48) ---
    ("Pay Rs 999 refundable registration fee today to confirm your WFH job selection without interview.", 1),
    ("Job ke liye pehle 1500 registration fees jama karo aur direct joining letter pao.", 1),
    ("Earn Rs 5000 to 8000 daily by liking YouTube videos and rating Google Maps hotels on Telegram.", 1),
    ("Complete 3 VIP prepaid merchant tasks and recharge wallet to unlock your frozen salary payout.", 1),
    ("Congratulations you are selected without interview. Pay Rs 2500 security deposit for laptop kit.", 1),
    ("बिना इंटरव्यू के नौकरी पाने के लिए सिक्योरिटी डिपॉजिट दें और आज ही जॉइन करें।", 1),
    ("Install AnyDesk and share the 9 digit code with HR for salary account verification.", 1),
    ("Share your 6 digit OTP and UPI PIN to verify your bank account for stipend credit.", 1),
    ("Urgent hiring at Infosys apply on infosys.careers-verification.xyz and pay 500 processing fee.", 1),
    ("Mandatory paid training fee of Rs 4000 before joining for guaranteed internship certificate.", 1),
    ("Part time work from home earn 6000 per day no skills required message only on WhatsApp.", 1),
    ("Pay 750 document verification fee within 2 hours or your job offer will be cancelled.", 1),
    ("Ghar baithe roz 4000 kamayein bina interview ke direct selection telegram group join karo.", 1),
    ("Transfer Rs 1200 refundable security deposit to HR UPI ID to schedule your final interview.", 1),
    ("VIP Telegram task group guaranteed daily income recharge 3000 to withdraw 4500 bonus.", 1),
    ("रजिस्ट्रेशन फीस जमा करें और बिना इंटरव्यू के सीधी भर्ती पाएं।", 1),
    ("Hello! Your resume has been shortlisted for part time online job. Work 1-2 hours daily on mobile and earn 2000-5000 per day. Reply YES on WhatsApp.", 1),
    ("Earn 150 per YouTube video like and subscribe. Daily payout directly to your bank account. Message HR on Telegram t.me/hr_task_india.", 1),
    ("Amazon part time work from home job. No experience needed. Anyone 18+ can apply. Earn Rs 3000 daily using smartphone. WhatsApp +91 9876543210.", 1),
    ("Send Rs 499 via GPay or PhonePe to 9876543210@ybl and share payment screenshot to receive your offer letter immediately.", 1),
    ("Online form filling and captcha typing job from home. Earn 45000 per month. 10th 12th pass can apply. Small agreement charge of Rs 800.", 1),
    ("Congratulations! You are selected for Flipkart data entry WFH role. Pay Rs 1500 refundable laptop dispatch fee within 2 hours.", 1),
    ("Dear candidate, your CV is selected for TCS HR round. Contact HR on WhatsApp only and send Aadhaar PAN and bank passbook photo.", 1),
    ("Join our Telegram channel for Google Maps hotel rating task. Get Rs 200 instant bonus after completing 3 simple reviews.", 1),
    ("Part time mobile job for students and housewives. Work 2 hours a day, earn Rs 1500 to 3500 daily. No skills required. Contact on WhatsApp.", 1),
    ("Kindly scan the QR code and pay Rs 650 file processing charge for your joining kit and ID card.", 1),
    ("Your salary account verification is pending. Download TeamViewer QuickSupport and share the ID with our payroll executive.", 1),
    ("Hurry up! Only 5 seats left for direct joining without interview. Pay Rs 999 onboarding fee today before 6 PM.", 1),
    ("Invest Rs 1000 in merchant order grabbing task and withdraw Rs 1400 within 10 minutes. Guaranteed commission.", 1),
    ("Get 100% job guarantee after paying Rs 5500 mandatory certification fee. Direct placement in MNC.", 1),
    ("घर बैठे मोबाइल से रोज़ ₹2000-₹4000 कमाएं, कोई अनुभव नहीं चाहिए, अभी व्हाट्सएप पर मैसेज करें।", 1),
    ("वीडियो लाइक करके कमाएं ₹150 प्रति टास्क, तुरंत टेलीग्राम ग्रुप जॉइन करें।", 1),
    ("Aapka resume shortlist ho gaya hai. Direct joining ke liye Rs 1000 UPI karo aur screenshot bhejo.", 1),
    ("Ghar baithe copy paste aur form filling kaam karein, mahine ke 40000 kamaye, registration charge sirf 500.", 1),
    ("Hi, I am HR Manager from a leading e-commerce company. We have a remote part-time job paying Rs 2500/day. Reply INTERESTED.", 1),
    ("Your Infosys offer letter is ready! Send Rs 2000 refundable caution deposit via Paytm to hr.infosys.desk@gmail.com.", 1),
    ("Apply using bit.ly/fast-job-2026 for instant WFH data entry job paying Rs 50000 monthly, 12th pass welcome.", 1),
    ("Deposit Rs 3000 to unfreeze your VIP task account and release your Rs 12000 commission payout.", 1),
    ("Salary paid in USDT crypto for daily app optimization tasks on Telegram. Contact @hr_crypto_jobs.", 1),
    ("Offer will be cancelled within 30 minutes if you do not transfer Rs 1250 verification fee right now.", 1),
    ("Send your Aadhaar card, PAN card, and selfie with ID on WhatsApp immediately to confirm your job slot.", 1),
    ("Paid internship with guaranteed MNC placement certificate! Just pay Rs 3500 training fee to enroll today.", 1),
    ("Earn $200 per day doing simple Instagram reel likes and comments from your phone. Zero experience needed.", 1),
    ("Direct airport ground staff bharti bina interview. Processing fee 1800 jama karein turant.", 1),
    ("Work from home PDF to Word typing project. Earn Rs 35000 per week. Pay Rs 700 portal activation fee.", 1),
    ("Share your ATM PIN or OTP to link your salary account with our company payroll system.", 1),
    ("Congratulations! Selected at Wipro without interview. Fill forms.gle/wipro-fast and pay Rs 999 gate pass fee.", 1),
    ("नौकरी पक्की करने के लिए तुरंत ₹1500 यूपीआई से भेजें और स्क्रीनशॉट व्हाट्सएप करें।", 1),
    # --- LEGITIMATE EXAMPLES (48) ---
    ("Infosys is hiring Software Engineers in Bengaluru. Apply via infosys.com/careers. We never charge any registration fee.", 0),
    ("Thank you for applying for Backend Developer at Razorpay. Your technical interview is scheduled for Thursday at 3 PM.", 0),
    ("Urgent reminder: please submit your updated resume before Friday for the Data Analyst interview panel.", 0),
    ("TCS does not charge any fee at any stage of the recruitment process. Apply only on tcs.com/careers.", 0),
    ("We are looking for a Frontend Engineer with 2+ years React experience. Salary 12-16 LPA. Location Pune Hybrid.", 0),
    ("Summer Internship Program at Zoho Corporation. Stipend Rs 25000 per month. Technical assessment followed by 2 interviews.", 0),
    ("Hi Priya, following up on your application for Product Designer (Req ID: REQ-4421). Let us know your availability.", 0),
    ("Wipro Campus Hiring 2026. Eligibility B.Tech CSE/IT. Zero fees. Official communications only from @wipro.com.", 0),
    ("Notice: Never pay any registration fee or security deposit during recruitment. Report fake recruiters to HR.", 0),
    ("We reviewed your GitHub portfolio and would like to invite you to a 45-minute coding round via Google Meet.", 0),
    ("Open role: Junior Python Developer at Acme Labs, Noida. Full-time on-site. Send resume to careers@acmelabs.in.", 0),
    ("Your interview feedback is positive. HR will share the formal offer letter from @accenture.com next week.", 0),
    ("भर्ती के दौरान कोई शुल्क नहीं लिया जाता है। कृपया केवल आधिकारिक वेबसाइट पर आवेदन करें।", 0),
    ("Graduate Engineer Trainee opening in Hyderabad. 6.5 LPA CTC. Selection via online test and technical interview.", 0),
    ("Freelance UI/UX contract for 3 months. Hourly rate discussed during discovery call. Portfolio review required.", 0),
    ("Reminder: Campus placement pre-placement talk starts at 10 AM in Auditorium B. Carry your college ID card.", 0),
    ("Hi Rahul, I am a Technical Recruiter at Microsoft India. Are you open to discussing a Senior SWE role in Hyderabad?", 0),
    ("We received your application for Data Scientist (Job ID: AMZ-8821). Please complete the HackerRank online assessment by Monday.", 0),
    ("Invitation: Round 2 System Design Interview with the Platform Engineering team via Microsoft Teams at 4:00 PM IST.", 0),
    ("Google is hiring Software Engineering Interns for Summer 2027. Apply directly at google.com/about/careers. No fees charged.", 0),
    ("Hi, we are a Series A fintech startup in Bengaluru hiring a Full-Stack Developer (Node.js + React). CTC 14-18 LPA. Email jobs@finpulse.in.", 0),
    ("Thank you for interviewing with Deloitte USI. Our talent acquisition team will update you within 5 business days.", 0),
    ("Your background in embedded C++ caught my eye. Would you be interested in a Firmware Engineer role at GreenLeaf Robotics?", 0),
    ("Apply on boards.greenhouse.io/razorpay for the Staff Security Engineer opening in Bengaluru.", 0),
    ("Hi Ananya, sharing the Zoom link for tomorrow's 30-minute hiring manager discussion for the Product Analyst role.", 0),
    ("Flipkart GRID 6.0 Engineering Campus Challenge is open for B.Tech students. Register on the official portal. Zero application fee.", 0),
    ("We are hiring a Marketing Associate in Mumbai (Hybrid). 1-3 years experience required. Salary 6-8 LPA. Apply via linkedin.com/jobs.", 0),
    ("Please review the attached offer letter from @cognizant.com and let us know if you have any questions regarding the compensation breakup.", 0),
    ("Our engineering team liked your take-home assignment. Can we schedule a 1-hour code walkthrough this week?", 0),
    ("HCLTech Walk-in Drive for Java Microservices Developers (3-6 yrs exp) on Saturday at Noida Sector 126 campus.", 0),
    ("Hi, I saw your open-source contributions on GitHub. We have an opening for a DevOps Engineer (Kubernetes/AWS) in Pune.", 0),
    ("Congratulations on clearing Round 1! Your next technical round is scheduled on Friday via Google Meet with our Tech Lead.", 0),
    ("Capgemini is hiring Cloud Engineers. Apply on capgemini.com/careers. Beware of fraud: Capgemini never asks for money.", 0),
    ("Research Internship at IIT Kanpur CSE Department. Stipend Rs 15000/month. Selection based on academic transcript and interview.", 0),
    ("Hi, could you share your notice period, current CTC, and expected CTC for the QA Automation Engineer role at Freshworks?", 0),
    ("Thank you for your interest in Swiggy. Unfortunately we are not moving forward at this time, but we will keep your profile on file.", 0),
    ("We have an urgent opening for a React Native Developer (2+ yrs) at our Gurugram office. Apply at careers@urbanstack.io.", 0),
    ("Your background verification will be initiated only after you sign the official offer letter on our Workday portal.", 0),
    ("Reminder: Your coding assessment link expires in 48 hours. Please ensure a stable internet connection before starting.", 0),
    ("Hi, we are organizing a virtual hiring drive for Business Analysts (4-7 LPA) in Jaipur. Register on naukri.com.", 0),
    ("Zoho does not charge any fee for job applications or interviews. Official emails are sent only from @zohocorp.com.", 0),
    ("Following up on our LinkedIn conversation regarding the Machine Learning Engineer role (18-24 LPA, Bengaluru).", 0),
    ("Please bring two copies of your resume for the in-person technical interview at our Whitefield office on Tuesday.", 0),
    ("We are looking for a Content Writer intern for 6 months (Remote, stipend Rs 12000/month). Writing sample required.", 0),
    ("Job Alert: Backend Engineer (Go/PostgreSQL) at Postman, Bengaluru. Apply via jobs.lever.co/postman.", 0),
    ("Hi, thanks for applying to our Design Intern position. Could you share a link to your Behance or Dribbble portfolio?", 0),
    ("Oracle India is hiring Associate Software Developers. B.Tech/MCA 2026 batch. Selection via online test + 3 interview rounds.", 0),
    ("कृपया ध्यान दें: हमारी कंपनी भर्ती के लिए कभी भी कोई फीस या सिक्योरिटी डिपॉजिट नहीं लेती है।", 0),
]

TOKEN_RE = re.compile(r"[a-zA-Z0-9\u0900-\u097F₹$]{2,}")


def _tokenize(text: str) -> List[str]:
    unigrams = [t.lower() for t in TOKEN_RE.findall(text or "")]
    bigrams = [f"{unigrams[i]}_{unigrams[i + 1]}" for i in range(len(unigrams) - 1)]
    return unigrams + bigrams


class PurePythonTFIDFLogReg:
    """Deterministic Unigram+Bigram TF-IDF + L2-regularized Logistic Regression in pure Python."""

    def __init__(self) -> None:
        self.vocab: Dict[str, int] = {}
        self.idf: List[float] = []
        self.weights: List[float] = []
        self.bias: float = 0.0
        self.metrics: Dict[str, object] = {}
        self._train_and_evaluate()

    def _fit(self, docs: List[Tuple[str, int]], epochs: int = 260, lr: float = 1.4, l2: float = 0.001) -> None:
        tokenized = [_tokenize(text) for text, _ in docs]
        df: Counter = Counter()
        for toks in tokenized:
            for tok in set(toks):
                df[tok] += 1
        self.vocab = {tok: idx for idx, (tok, _) in enumerate(sorted(df.items()))}
        n_docs = len(docs)
        self.idf = [0.0] * len(self.vocab)
        for tok, idx in self.vocab.items():
            self.idf[idx] = math.log((1 + n_docs) / (1 + df[tok])) + 1.0

        vectors = [self._vectorize_tokens(toks) for toks in tokenized]
        self.weights = [0.0] * len(self.vocab)
        self.bias = 0.0

        for _ in range(epochs):
            grad_w = [0.0] * len(self.vocab)
            grad_b = 0.0
            for vec, (_, label) in zip(vectors, docs):
                z = self.bias + sum(self.weights[i] * v for i, v in vec.items())
                p = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, z))))
                err = p - label
                grad_b += err
                for i, v in vec.items():
                    grad_w[i] += err * v
            for i in range(len(self.weights)):
                self.weights[i] -= lr * (grad_w[i] / n_docs + l2 * self.weights[i])
            self.bias -= lr * (grad_b / n_docs)

    def _vectorize_tokens(self, toks: List[str]) -> Dict[int, float]:
        counts = Counter(t for t in toks if t in self.vocab)
        if not counts:
            return {}
        total = sum(counts.values())
        vec = {self.vocab[t]: (c / total) * self.idf[self.vocab[t]] for t, c in counts.items()}
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {i: v / norm for i, v in vec.items()}

    def _train_and_evaluate(self) -> None:
        train_docs: List[Tuple[str, int]] = []
        test_docs: List[Tuple[str, int]] = []
        for idx, item in enumerate(LABELED_SYNTHETIC_DATASET):
            if idx % 4 == 3:
                test_docs.append(item)
            else:
                train_docs.append(item)

        self._fit(train_docs)
        tp = fp = tn = fn = 0
        for text, y_true in test_docs:
            prob, _ = self.predict_proba(text)
            y_pred = 1 if prob >= 0.5 else 0
            if y_true == 1 and y_pred == 1:
                tp += 1
            elif y_true == 0 and y_pred == 1:
                fp += 1
            elif y_true == 0 and y_pred == 0:
                tn += 1
            else:
                fn += 1

        total = len(test_docs)
        acc = (tp + tn) / total if total else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0

        self.metrics = {
            "train_samples": len(train_docs),
            "test_samples": len(test_docs),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "heldout_accuracy": round(acc, 3),
            "heldout_precision": round(prec, 3),
            "heldout_recall": round(rec, 3),
            "heldout_f1": round(f1, 3),
            "note": f"Computed on a deterministic {len(LABELED_SYNTHETIC_DATASET)}-sample synthetic EN/HI/Hinglish benchmark; not a real-world production benchmark.",
        }
        # Refit on full synthetic corpus for inference
        self._fit(LABELED_SYNTHETIC_DATASET)

    def predict_proba(self, text: str) -> Tuple[float, List[str]]:
        toks = _tokenize(text)
        vec = self._vectorize_tokens(toks)
        if not vec:
            return 0.5, []
        z = self.bias + sum(self.weights[i] * v for i, v in vec.items())
        prob = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, z))))
        inv_vocab = {idx: tok for tok, idx in self.vocab.items()}
        contribs = sorted(
            ((self.weights[i] * v, inv_vocab[i]) for i, v in vec.items()),
            key=lambda x: abs(x[0]),
            reverse=True,
        )
        top_terms = [f"{tok.replace('_', ' ')} ({'+' if score >= 0 else ''}{score:.2f})" for score, tok in contribs[:6]]
        return round(prob, 3), top_terms


_CLASSIFIER = PurePythonTFIDFLogReg()


def run_ml_classification(text: str) -> MLAssessment:
    """Run secondary TF-IDF + Logistic Regression assessment with transparent disclosure."""
    prob, top_terms = _CLASSIFIER.predict_proba(text or "")
    label = (
        "Elevated Scam Text Pattern"
        if prob >= 0.65
        else "Ambiguous / Mixed Text Signal"
        if prob >= 0.35
        else "Low Scam Text Pattern"
    )
    return MLAssessment(
        available=True,
        model_type="Unigram+Bigram TF-IDF + L2 Logistic Regression (Pure Python)",
        predicted_label=label,
        scam_probability_estimate=prob,
        top_contributing_terms=top_terms,
        dataset_disclosure=(
            f"Secondary heuristic model trained on a {len(LABELED_SYNTHETIC_DATASET)}-sample synthetic EN/HI/Hinglish dataset. "
            "It serves strictly as a supporting signal alongside deterministic rules and structured evidence, "
            "not as a calibrated real-world fraud probability."
        ),
        evaluation_metrics=_CLASSIFIER.metrics,
    )


def get_ml_metadata() -> Dict[str, object]:
    return {
        "model_type": "Unigram+Bigram TF-IDF + L2 Logistic Regression (Pure Python)",
        "total_synthetic_samples": len(LABELED_SYNTHETIC_DATASET),
        "vocab_size": len(_CLASSIFIER.vocab),
        "evaluation_metrics": _CLASSIFIER.metrics,
        "limitation": "Trained on a synthetic dataset for reproducibility; primary decisions rely on deterministic evidence rules and URL/domain verification.",
    }
