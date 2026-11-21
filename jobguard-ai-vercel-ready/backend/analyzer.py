"""Layers A, B, G & H: Multilingual recruitment fraud rule engine, job ad analysis,
payment/sensitive-info detection, legitimacy trust signals, and cross-document consistency.

Handles English, Hindi, and Hinglish with explicit negation, context awareness,
compound-signal synergy, and positive credibility calibration.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .extractor import extract_structured_job_data
from .schemas import DetectionIndicator, ExtractedJobData, Severity


@dataclass(frozen=True)
class FraudRule:
    rule_id: str
    category: str
    severity: Severity
    weight: int
    pattern: re.Pattern
    explanation: str
    explanation_hi: str
    reason_it_matters: str
    suggested_action: str
    respect_negation: bool = True


NEGATION_PREFIX_RE = re.compile(
    r"(?i)(?:never|do\s+not|don't|does\s+not|doesn't|will\s+not|won't|not\s+ask(?:ing)?\s+(?:for|you\s+to)|"
    r"no\s+(?:upfront\s+|hidden\s+|kind\s+of\s+)?|zero|without\s+any|free\s+of|beware\s+of|warning\s*:|disclaimer\s*:|"
    r"note\s*:\s*we\s+(?:do\s+not|never)|we\s+(?:never|do\s+not)\s+(?:charge|ask|demand|collect)|"
    r"कभी\s+नहीं|न\s+दें|न\s+करें|नहीं\s+मांग|मत\s+दें|कोई\s+शुल्क\s+नहीं|mat\s+do|nahi\s+mangta|koi\s+fee\s+nahi)\s*"
    r"(?:pay|charge|ask|collect|demand|share|give|send|require|take)?\s*(?:any\s+|for\s+)?$"
)

SAFETY_DISCLAIMER_RE = re.compile(
    r"(?i)(?:never\s+(?:pay|send|share|transfer)\s+(?:any\s+)?(?:registration\s+fee|security\s+deposit|money|fee|amount|otp|upi\s+pin|password)|"
    r"does\s+not\s+(?:charge|ask\s+for|collect|require)\s+(?:any\s+)?(?:fee|fees|money|deposit|payment)\s*(?:at\s+any\s+stage|during\s+recruitment|for\s+interviews?|for\s+jobs?)?|"
    r"no\s+(?:registration\s+|application\s+|processing\s+)?fee(?:s)?\s+(?:is\s+|are\s+)?(?:charged|required)\s+(?:during|at\s+any\s+stage|for)|"
    r"zero\s+(?:registration\s+)?fee(?:s)?\b|"
    r"do\s+not\s+pay\s+any\s+(?:fee|fees|deposit|amount|money)|"
    r"भर्ती\s+के\s+दौरान\s+कोई\s+शुल्क\s+नहीं\s+लिया\s+जाता|"
    r"कोई\s+भी\s+रजिस्ट्रेशन\s+फीस\s+न\s+दें)"
)


RULES: List[FraudRule] = [
    # --- CRITICAL SEVERITY RULES ---
    FraudRule(
        rule_id="advance_registration_fee",
        category="Advance Fee / Registration Scam",
        severity=Severity.CRITICAL,
        weight=50,
        pattern=re.compile(
            r"(?i)\b(?:(?:pay|deposit|submit|transfer|send|clear|remit)\s+(?:a\s+|an\s+|the\s+|just\s+|only\s+)?(?:nominal\s+|small\s+|one[\s-]time\s+|refundable\s+)?(?:(?:₹|Rs\.?|INR|\$|USD)\s*\d[\d,]*(?:\s*(?:only|\/-))?\s*)?(?:refundable\s+)?(?:registration|application|processing|joining|onboarding|interview|document(?:ation)?|verification|file|offer\s+letter|portal|gate\s+pass|id\s+card|seat\s+booking|agreement|stamp)\s*(?:fee|fees|charge|charges|amount|cost)|"
            r"(?:pay|deposit|transfer|send)\s+(?:₹|Rs\.?|INR|\$|USD)\s*\d[\d,]*(?:\s*(?:only|\/-))?\s+(?:for|as|towards|to)\s+(?:registration|confirm(?:ing)?\s+(?:your\s+)?(?:job|seat|slot|offer|selection)|joining|onboarding|processing|interview|verification|documentation|offer\s+letter|id\s+card|portal\s+activation)|"
            r"(?:registration|processing|application|joining|onboarding|interview(?:\s+scheduling)?|document(?:ation)?\s+verification|file|agreement)\s*(?:fee|fees|charge|charges)\s*(?:of\s+(?:₹|Rs\.?|INR|\$|USD)?\s*\d[\d,]*|is\s+(?:₹|Rs\.?|INR|\$|USD)?\s*\d[\d,]*|is\s+(?:mandatory|required|applicable|compulsory|refundable)|to\s+(?:confirm|get\s+selected|schedule|proceed|activate)|jama\s+karo|jama\s+karein|bhejo|dena\s+hoga|lagta\s+hai|lagega)|"
            r"(?:pehle|pahle)\s+(?:₹|Rs\.?)?\s*\d[\d,]*\s*(?:rupees?|rs)?\s*(?:registration|joining|processing|form)?\s*(?:fee|fees|charge|paisa|paise)?\s*(?:jama\s+karo|jama\s+karein|bhejo|do|dena\s+hoga))\b|"
            r"रजिस्ट्रेशन\s+फीस\s*(?:जमा\s+करें|दें|देनी\s+होगी|₹?\s*\d[\d,]*)?|प्रोसेसिंग\s+फीस\s*(?:जमा\s+करें|दें|₹?\s*\d[\d,]*)?|जॉइनिंग\s+फीस|आवेदन\s+शुल्क\s+जमा\s+करें|फाइल\s+चार्ज",
        ),
        explanation="Demands an upfront registration, interview, processing, offer-letter, or verification fee to proceed with hiring.",
        explanation_hi="नौकरी या चयन के लिए पहले रजिस्ट्रेशन, प्रोसेसिंग, जॉइनिंग या सत्यापन शुल्क की मांग की गई है।",
        reason_it_matters="Legitimate employers never charge candidates to apply, interview, receive an offer letter, or confirm a job.",
        suggested_action="Stop all communication immediately and never pay any fee to confirm a job.",
    ),
    FraudRule(
        rule_id="security_or_equipment_deposit",
        category="Security / Equipment Deposit Scam",
        severity=Severity.CRITICAL,
        weight=50,
        pattern=re.compile(
            r"(?i)\b(?:refundable\s+(?:security\s+)?deposit|"
            r"(?:security|caution|refundable|warranty)\s+deposit\s*(?:of\s+(?:₹|Rs\.?|INR|\$|USD)?\s*\d[\d,]*|is\s+(?:required|mandatory|refundable)|to\s+confirm|before\s+joining|jama\s+karo|dena\s+hoga)?|"
            r"(?:laptop|equipment|macbook|id\s+card|kit|asset|uniform|courier|delivery)\s+(?:security\s+|shipping\s+|dispatch\s+)?(?:deposit|fee|fees|charge|charges)|"
            r"(?:deposit|pay)\s+(?:money|(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*)\s+to\s+(?:unlock|release|receive|withdraw|unfreeze)\s+(?:your\s+)?(?:salary|payout|commission|earnings|account))\b|"
            r"सिक्योरिटी\s+डिपॉजिट\s*(?:दें|जमा\s+करें|देना\s+होगा)?|लैपटॉप\s+डिपॉजिट|रिफंडेबल\s+डिपॉजिट",
        ),
        explanation="Requests a 'refundable' security deposit, laptop/kit dispatch fee, or payment to unlock salary.",
        explanation_hi="नौकरी, इंटर्नशिप या लैपटॉप के नाम पर 'रिफंडेबल' सिक्योरिटी डिपॉजिट की मांग की गई है।",
        reason_it_matters="Fraudsters label upfront payments as '100% refundable' to lower skepticism and disappear after collecting money.",
        suggested_action="Refuse any security or equipment deposit and verify the company independently.",
    ),
    FraudRule(
        rule_id="upi_or_direct_payment_demand",
        category="Direct UPI / QR / Payment Transfer Request",
        severity=Severity.CRITICAL,
        weight=48,
        pattern=re.compile(
            r"(?i)\b(?:(?:pay|send|transfer|deposit|scan)\s+(?:₹|Rs\.?|INR)?\s*\d[\d,]*(?:\s*(?:only|\/-))?\s*(?:via|through|on|to|by|using)\s+(?:upi|gpay|google\s*pay|phonepe|paytm|qr\s*code|neft|imps|bank\s+account)|"
            r"(?:gpay|google\s*pay|phonepe|paytm|upi)\s+(?:karo|karein|kardo|kijiye|number|id)\s*(?::|is|on|at)?\s*(?:₹?\s*\d|[\w.-]+@[a-z]+)?|"
            r"(?:send|share)\s+(?:the\s+|your\s+)?(?:payment|transaction|upi|gpay|phonepe|paytm)\s+(?:screenshot|receipt|utr|proof)|"
            r"scan\s+(?:the\s+|this\s+)?qr\s*code\s+(?:to\s+)?(?:pay|complete|confirm|verify|receive\s+salary)|"
            r"[a-zA-Z0-9._-]{3,}@(?:okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|paytm|upi|apl|fbl))\b|"
            r"(?:यूपीआई|गूगल\s*पे|फोनपे|पेटीएम|क्यूआर\s*कोड)\s*(?:पर|से)\s*(?:पैसे|फीस|भुगतान)\s*(?:भेजें|करें)",
        ),
        explanation="Asks for a direct UPI, GPay, PhonePe, Paytm, QR code payment, or payment screenshot during recruitment.",
        explanation_hi="भर्ती के नाम पर UPI, GPay, PhonePe, Paytm या QR कोड से सीधे पैसे भेजने या पेमेंट स्क्रीनशॉट की मांग की गई है।",
        reason_it_matters="Legitimate employers never collect hiring fees on personal UPI IDs or ask candidates to scan QR codes to receive salary.",
        suggested_action="Do not scan any QR code or transfer money to any UPI ID. Report the UPI ID if fraud occurred.",
    ),
    FraudRule(
        rule_id="prepaid_task_recharge_scam",
        category="Prepaid Task & Recharge Scam",
        severity=Severity.CRITICAL,
        weight=52,
        pattern=re.compile(
            r"(?i)(?<!\w)(?:prepaid\s+(?:merchant\s+|welfare\s+|vip\s+)?task|"
            r"task\s+(?:recharge|upgrade|commission|wallet)|"
            r"recharge\s+(?:your\s+)?(?:wallet|account|balance)\s+to\s+(?:complete|unlock|withdraw|continue)|"
            r"vip\s+(?:telegram\s+)?task\s*(?:group|payout|commission|order)|"
            r"(?:like|liking|subscribe|subscribing|follow|following)\s+(?:youtube|instagram|ig|tiktok|fb|facebook)\s*(?:videos?|reels?|channels?|posts?|pages?)\s*(?:and|&|to)?\s*(?:earn|get\s+paid|make\s+money|₹|rs)?|"
            r"(?:rate|rating|review|reviewing)\s+(?:google\s+maps?|hotels?|restaurants?|places?|amazon\s+products?|flipkart\s+products?|apps?)\s*(?:and|&|to)?\s*(?:earn|get\s+paid|₹|rs)?|"
            r"(?:₹|Rs\.?|INR)\s*(?:50|100|150|200|250|300|500)\s*(?:per|\/|for\s+each)\s*(?:[a-z]+\s+){0,2}(?:like|review|rating|task|subscribe|comment|video)s?|"
            r"order\s+grabbing|merchant\s+order\s+tasks?|app\s+optimization\s+tasks?)\b|"
            r"प्रीपेड\s+टास्क|वीडियो\s+लाइक\s+करके\s+कमाएं|टास्क\s+रिचार्ज|रिव्यू\s+लिखकर\s+कमाएं",
        ),
        explanation="Describes a prepaid task, wallet recharge, order-grabbing, or paid video-liking / review-rating scheme.",
        explanation_hi="वीडियो लाइक करने, गूगल रिव्यू देने या प्रीपेड टास्क रिचार्ज से कमाई का लालच दिया गया है।",
        reason_it_matters="Task scams pay small initial bait amounts (₹150–₹300) before trapping victims into depositing thousands in frozen 'VIP' tasks.",
        suggested_action="Leave the Telegram/WhatsApp group immediately and do not recharge any task wallet.",
    ),
    FraudRule(
        rule_id="sensitive_credentials_request",
        category="OTP / UPI PIN / Credential Theft",
        severity=Severity.CRITICAL,
        weight=54,
        pattern=re.compile(
            r"(?i)\b(?:(?:share|send|provide|enter|give|tell|forward|bhejo|batao)\s+(?:your\s+|the\s+|apna\s+)?(?:4[\s-]digit\s+|6[\s-]digit\s+)?(?:otp|upi\s+pin|atm\s+pin|debit\s+card\s+pin|cvv|cvc|netbanking\s+password|bank\s+password|mpin|login\s+password|card\s+number)|"
            r"(?:otp|upi\s+pin|atm\s+pin|mpin|cvv)\s+(?:share\s+karo|bhejo|dalein|dalo|required\s+for\s+(?:salary|verification|onboarding|kyc)))\b|"
            r"(?:ओटीपी|यूपीआई\s+पिन|एटीएम\s+पिन|पासवर्ड|सीवीवी)\s*(?:शेयर|साझा|भेजें|बताएं|डालें)",
        ),
        explanation="Requests an OTP, UPI PIN, ATM PIN, CVV, or banking password during recruitment.",
        explanation_hi="भर्ती या सैलरी वेरिफिकेशन के नाम पर ओटीपी, यूपीआई पिन, एटीएम पिन या पासवर्ड मांगा गया है।",
        reason_it_matters="No legitimate HR team ever needs your OTP, UPI PIN, CVV, or banking password to verify identity or set up payroll.",
        suggested_action="Never share OTPs, PINs, or passwords. If already shared, contact your bank and call 1930 immediately.",
    ),
    FraudRule(
        rule_id="remote_access_software",
        category="Remote-Access Software Scam",
        severity=Severity.CRITICAL,
        weight=54,
        pattern=re.compile(
            r"(?i)\b(?:install|download|open|use|connect\s+(?:via|on))\s+(?:the\s+)?(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer|ammyy\s*admin)|"
            r"\b(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer)\b.{0,45}\b(?:code|id|verify|interview|hr|onboarding|screen|salary|bank)\b",
        ),
        explanation="Asks you to install remote-access software (AnyDesk, TeamViewer, QuickSupport) for onboarding or HR verification.",
        explanation_hi="ऑनबोर्डिंग या सत्यापन के लिए AnyDesk या TeamViewer जैसे रिमोट-एक्सेस ऐप इंस्टॉल करने को कहा गया है।",
        reason_it_matters="Remote-access apps allow scammers to control your device, read OTPs, and drain bank accounts live.",
        suggested_action="Do not install AnyDesk/TeamViewer for recruiters. Uninstall immediately if already installed.",
    ),
    # --- HIGH SEVERITY RULES ---
    FraudRule(
        rule_id="crypto_or_investment_job_lure",
        category="Crypto / Investment / Deposit-Return Job Scam",
        severity=Severity.HIGH,
        weight=36,
        pattern=re.compile(
            r"(?i)\b(?:invest\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*\s*(?:and|&|to)\s*(?:earn|get|withdraw)\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*|"
            r"deposit\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*\s*(?:and|&)\s*(?:get|receive|withdraw)\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*|"
            r"salary\s+(?:paid\s+)?in\s+(?:usdt|crypto|bitcoin|btc|eth)|"
            r"crypto\s+(?:trading|task|wallet)\s+(?:job|commission|bonus)|"
            r"double\s+your\s+(?:money|income|deposit))\b",
        ),
        explanation="Mixes job recruitment with investment returns, deposit-and-withdraw bonuses, or crypto/USDT task commissions.",
        explanation_hi="नौकरी के नाम पर पैसे निवेश करने, डिपॉजिट पर तुरंत रिटर्न या क्रिप्टो/USDT टास्क का लालच दिया गया है।",
        reason_it_matters="Legitimate jobs pay you for your work—they never require you to deposit money to earn commission or returns.",
        suggested_action="Avoid any 'job' that asks you to invest or deposit funds to receive higher payouts.",
    ),
    FraudRule(
        rule_id="mandatory_paid_training",
        category="Paid Training / Fake Internship Scam",
        severity=Severity.HIGH,
        weight=34,
        pattern=re.compile(
            r"(?i)\b(?:pay\s+(?:for\s+)?(?:(?:₹|Rs\.?|INR|\$)\s*\d[\d,]*\s+)?(?:mandatory|compulsory|paid)?\s*(?:training|course|certification|internship)\s*(?:fee|fees|charge|before\s+joining|to\s+get\s+(?:hired|selected|placed|offer))?|"
            r"(?:mandatory|compulsory)\s+paid\s+(?:training|certification|internship|course)|"
            r"guaranteed\s+(?:job|placement|internship\s+certificate)\s+(?:after|in\s+exchange\s+for|with)\s+(?:paying|payment|fee|course)|"
            r"buy\s+(?:our\s+)?(?:internship|training)\s+certificate|"
            r"(?:training|internship|placement)\s+(?:fee|charges?)\s*(?:of\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*|is\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*|mandatory))\b|"
            r"ट्रेनिंग\s+फीस\s*(?:जमा\s+करें|देनी\s+होगी)?|इंटर्नशिप\s+फीस",
        ),
        explanation="Requires paying for mandatory training, an internship, or a certificate in exchange for guaranteed employment.",
        explanation_hi="नौकरी की गारंटी के बदले अनिवार्य पेड ट्रेनिंग, इंटर्नशिप या सर्टिफिकेट शुल्क मांगा गया है।",
        reason_it_matters="Pay-to-work training traps target students and freshers by selling worthless certificates under a fake job promise.",
        suggested_action="Verify whether the opportunity is genuine employment or a disguised paid course.",
    ),
    FraudRule(
        rule_id="unrealistic_wfh_earnings",
        category="Unrealistic Salary / WFH Compensation",
        severity=Severity.HIGH,
        weight=32,
        pattern=re.compile(
            r"(?i)(?<!\w)(?:earn\s+(?:up\s+to\s+|upto\s+)?(?:₹|Rs\.?|INR)\s*(?:[1-9],?\d{3}|[1-9]\d,?\d{3}|\d{4,5})(?:\s*(?:-|to|–)\s*(?:₹|Rs\.?|INR)?\s*\d[\d,]*)?\s*(?:per\s+day|daily|\/day|a\s+day|every\s+day)|"
            r"earn\s+(?:up\s+to\s+|upto\s+)?(?:\$|USD)\s*(?:[1-9]\d{2,})(?:\s*(?:-|to|–)\s*\$?\d[\d,]*)?\s*(?:per\s+day|daily|\/day|per\s+hour|\/hr)|"
            r"(?:daily|everyday)\s+(?:income|payout|earning|earnings|salary|profit)\s*(?:of\s+|is\s+|:|-)?\s*(?:₹|Rs\.?|INR)?\s*(?:[1-9],?\d{3}|[1-9]\d,?\d{3}|\d{4,5})|"
            r"(?:₹|Rs\.?|INR)\s*(?:[1-9],?\d{3}|[1-9]\d,?\d{3})(?:\s*(?:-|to|–)\s*(?:₹|Rs\.?|INR)?\s*\d[\d,]*)?\s*(?:per\s+day|daily|\/day)\s*(?:from\s+home|wfh|part[\s-]time|online|guaranteed)?|"
            r"(?:roz|roj|daily)\s+(?:₹|Rs\.?)?\s*\d{3,5}\s*(?:se\s+\d{3,5}\s*)?kama(?:yein|ye|o|aye)|"
            r"ghar\s+baithe\s+(?:roz|roj|daily|mahine|online)?\s*(?:₹|Rs\.?)?\s*\d{3,6}\s*(?:kama(?:yein|ye|o)|income|salary)?|"
            r"mobile\s+se\s+(?:roz|daily|ghar\s+baithe)?\s*(?:paise|paisa|₹?\s*\d[\d,]*)\s*kama(?:yein|ye|o))\b|"
            r"घर\s+बैठे\s+(?:रोज़|रोज|प्रतिदिन)?\s*₹?\s*\d[\d,]*\s*(?:कमाएं|कमाए|रुपये)",
        ),
        explanation="Promises unusually high daily earnings (e.g., ₹1,000–₹10,000/day) for simple work-from-home or mobile tasks.",
        explanation_hi="सरल घर बैठे या मोबाइल काम के लिए रोज़ाना हजारों रुपये की अवास्तविक कमाई का वादा किया गया है।",
        reason_it_matters="Disproportionately high daily payouts for minimal skills are a primary lure for WFH and task fraud.",
        suggested_action="Benchmark the claimed pay against standard market salaries for that role.",
    ),
    FraudRule(
        rule_id="guaranteed_selection_no_interview",
        category="Fake Selection / Guaranteed Job Promise",
        severity=Severity.HIGH,
        weight=30,
        pattern=re.compile(
            r"(?i)\b(?:guaranteed\s+(?:selection|job|placement|joining|offer|income)\s*(?:without\s+(?:any\s+)?interview|100%|today)?|"
            r"100%\s+(?:job|placement|selection)\s+guarantee|"
            r"(?:direct|instant|immediate)\s+(?:joining|selection|hiring)\s+(?:without|with\s+no|no)\s+(?:any\s+)?(?:interview|exam|test)|"
            r"(?:selected|shortlisted|hired)\s+without\s+(?:any\s+)?(?:interview|test|exam)|"
            r"no\s+interview\s+(?:required|needed)\s*(?:for\s+(?:direct\s+)?joining)?|"
            r"bina\s+(?:kisi\s+)?interview\s+(?:ke\s+)?(?:direct\s+)?(?:selection|naukri|job|joining|bharti))\b|"
            r"बिना\s+(?:किसी\s+)?इंटरव्यू\s+(?:के\s+)?(?:सीधी\s+भर्ती|नौकरी|चयन|जॉइनिंग)",
        ),
        explanation="Promises guaranteed job selection, 100% placement, or direct joining without any interview or evaluation.",
        explanation_hi="बिना किसी इंटरव्यू या जांच के पक्की नौकरी या सीधे चयन का वादा किया गया है।",
        reason_it_matters="Reputable employers evaluate candidates through interviews or assessments before issuing an offer.",
        suggested_action="Verify the hiring process directly on the employer's official career portal.",
    ),
    FraudRule(
        rule_id="sensitive_kyc_upfront",
        category="Upfront KYC / Identity & Bank Document Harvest",
        severity=Severity.HIGH,
        weight=38,
        pattern=re.compile(
            r"(?i)\b(?:(?:send|share|submit|whatsapp|upload)\s+(?:your\s+)?(?:aadhaar|aadhar|pan\s+card|bank\s+passbook|cancelled\s+cheque|debit\s+card|credit\s+card|selfie\s+with\s+(?:aadhaar|pan|id))\b.{0,45}\b(?:whatsapp|telegram|immediately|urgent|today|now|confirm|verification|salary|joining)|"
            r"(?:aadhaar|aadhar)\s*(?:and|&|\/|\+)\s*pan\s*(?:card)?\s*(?:and|&|,)?\s*(?:bank\s+(?:details|account|passbook)|selfie)\s*(?:on\s+whatsapp|immediately|to\s+confirm|for\s+joining))\b|"
            r"(?:आधार|पैन\s+कार्ड|बैंक\s+पासबुक)\s*(?:व्हाट्सएप|टेलीग्राम)\s*पर\s*भेजें",
        ),
        explanation="Requests sensitive KYC documents (Aadhaar, PAN, bank passbook, or ID selfie) over chat before verified hiring.",
        explanation_hi="सत्यापित ऑफर से पहले ही व्हाट्सएप/चैट पर आधार, पैन या बैंक पासबुक जैसे संवेदनशील दस्तावेज मांगे गए हैं।",
        reason_it_matters="Scammers harvest Aadhaar/PAN/bank details for identity theft, mule accounts, and fraudulent loans.",
        suggested_action="Never share Aadhaar, PAN, or bank passbook photos over WhatsApp/Telegram before verifying the employer.",
    ),
    FraudRule(
        rule_id="data_entry_typing_wfh_bait",
        category="High-Risk Data Entry / Typing / Copy-Paste WFH Bait",
        severity=Severity.MEDIUM,
        weight=20,
        pattern=re.compile(
            r"(?i)\b(?:(?:online|home[\s-]based|part[\s-]time|wfh|work\s+from\s+home)\s+(?:data\s+entry|form\s+filling|captcha\s+(?:typing|entry|work)|copy[\s-]paste|page\s+typing|handwriting|sms\s+sending|ad\s+(?:posting|clicking))\s*(?:job|work|project)?|"
            r"(?:captcha\s+(?:typing|entry|solving)|form\s+filling|copy[\s-]paste|page\s+typing|pdf\s+to\s+word\s+typing)\s+(?:job|work)\s*(?:from\s+home|online|daily\s+payout|earn)?)\b|"
            r"(?:डेटा\s+एंट्री|फॉर्म\s+फिलिंग|कॉपी\s+पेस्ट|कैप्चा\s+टाइपिंग)\s*(?:जॉब|काम)",
        ),
        explanation="Advertises a classic high-fraud WFH job category (captcha typing, form filling, copy-paste, or online page typing).",
        explanation_hi="ऑनलाइन डेटा एंट्री, फॉर्म फिलिंग, कॉपी-पेस्ट या कैप्चा टाइपिंग जैसे उच्च-जोखिम वाले काम का प्रस्ताव है।",
        reason_it_matters="Form-filling, captcha, and copy-paste WFH ads are overwhelmingly used to trap applicants into agreement fees or legal-threat extortion.",
        suggested_action="Verify the employer's legal registration and never sign penalty agreements or pay starter fees.",
    ),
    # --- MEDIUM SEVERITY RULES ---
    FraudRule(
        rule_id="messaging_only_funnel",
        category="WhatsApp / Telegram-Only Recruitment Funnel",
        severity=Severity.MEDIUM,
        weight=18,
        pattern=re.compile(
            r"(?i)\b(?:(?:contact|message|msg|dm|ping|reach|chat\s+with|apply\s+on|reply\s+on|text)\s+(?:hr\s+|us\s+|me\s+)?(?:only\s+)?(?:on|via|at)\s+(?:whatsapp|telegram)|"
            r"whatsapp\s+(?:us|me|hr|now|your\s+(?:cv|resume|name|details)|at\s+\+?\d|on\s+\+?\d)|"
            r"join\s+(?:our\s+)?(?:official\s+)?(?:telegram|whatsapp)\s+(?:job|hr|task|vip|work|earning|hiring)?\s*(?:channel|group)|"
            r"(?:reply|send|type)\s+['\"]?(?:yes|interested|ok|hi|start)['\"]?\s+(?:on\s+whatsapp|to\s+start|for\s+(?:details|joining|info))|"
            r"t\.me\/[a-z0-9_]+|wa\.me\/\d+|chat\.whatsapp\.com\/[a-z0-9]+)\b|"
            r"(?:व्हाट्सएप|टेलीग्राम)\s*(?:पर\s+)?(?:मैसेज|संपर्क|जॉइन)\s*करें",
        ),
        explanation="Routes recruitment through WhatsApp or Telegram messaging or asks you to reply 'YES/INTERESTED' to start.",
        explanation_hi="भर्ती प्रक्रिया को व्हाट्सएप या टेलीग्राम के माध्यम से चलाने या 'YES' रिप्लाई करने को कहा गया है।",
        reason_it_matters="Corporate hiring funnels conducted exclusively on Telegram/WhatsApp lack auditability and are heavily abused by scammers.",
        suggested_action="Ask for an official corporate email confirmation and a listing on the company's career website.",
    ),
    FraudRule(
        rule_id="unsolicited_shortlist_bait",
        category="Unsolicited Generic Shortlist / Mass-Outreach Bait",
        severity=Severity.MEDIUM,
        weight=16,
        pattern=re.compile(
            r"(?i)\b(?:(?:congratulations|congrats|greetings)[!.,\s]+(?:your\s+)?(?:resume|cv|profile|number|mobile\s+number)\s+(?:has\s+been\s+|is\s+|was\s+)?(?:shortlisted|selected|approved)\s*(?:for\s+(?:a\s+|an\s+|our\s+)?(?:part[\s-]time|work\s+from\s+home|online|remote|urgent)?\s*(?:job|vacancy|role|position|interview))?|"
            r"we\s+(?:found|got|received)\s+your\s+(?:resume|cv|number|contact)\s+(?:from|on)\s+(?:a\s+job\s+portal|job\s+portals|database|naukri|shine|indeed)\s*[,.\-]\s*(?:we\s+are\s+hiring|part[\s-]time|earn|work\s+from\s+home)|"
            r"hello,?\s+i\s+am\s+(?:hr|recruiter|manager)\s+(?:from|at)\s+(?:a\s+)?(?:leading|top|reputed|mnc)\s+(?:company|agency|e[\s-]commerce))\b",
        ),
        explanation="Uses a generic mass-outreach opener ('Congratulations, your resume is shortlisted') without verifiable job specifics.",
        explanation_hi="बिना स्पष्ट विवरण के सामान्य थोक संदेश ('बधाई हो, आपका रिज्यूमे शॉर्टलिस्ट हो गया है') का उपयोग किया गया है।",
        reason_it_matters="Scammers blast identical 'resume shortlisted' messages to thousands of phone numbers to lure targets into WhatsApp/Telegram funnels.",
        suggested_action="Check if you actually applied to this company and ask for the official job requisition ID and corporate email.",
    ),
    FraudRule(
        rule_id="vague_zero_skill_lure",
        category="Zero-Skill / Smartphone-Only Earning Pitch",
        severity=Severity.MEDIUM,
        weight=14,
        pattern=re.compile(
            r"(?i)\b(?:(?:only|just)\s+(?:a\s+)?(?:smartphone|mobile\s+phone|phone)\s+(?:is\s+)?(?:needed|required)|"
            r"(?:work|working)\s+(?:just\s+|only\s+)?(?:1|2|1[\s-]2|1\s+to\s+2|2[\s-]3)\s+hours?\s*(?:per\s+day|daily|a\s+day)\s*(?:from\s+(?:home|mobile|phone)|and\s+earn)?|"
            r"(?:no\s+skills?|no\s+qualification|no\s+experience)\s+(?:required|needed)\s*(?:[,!&+]\s*(?:anyone|students|housewives|freshers|earn|daily|weekly))|"
            r"(?:students|housewives|homemakers|retired|job\s+seekers)\s*(?:,|\/|and|&)\s*(?:housewives|students|freshers|part[\s-]timers)\s+(?:can\s+)?(?:apply|earn|join)|"
            r"age\s*(?::|\s)\s*(?:18|20|21|22|23|25)\s*(?:-|to|\+)\s*(?:55|60|65)?\s*(?:years?|yrs?)?\s*(?:above|only|and\s+above))\b",
        ),
        explanation="Markets a '1–2 hours daily on smartphone, no skills needed' pitch targeting broad demographics.",
        explanation_hi="बिना किसी कौशल के केवल मोबाइल से रोज़ 1-2 घंटे काम करके कमाई का प्रचार किया गया है।",
        reason_it_matters="Scam recruiters intentionally target students, housewives, and freshers with zero-barrier smartphone work pitches.",
        suggested_action="Be skeptical of zero-skill smartphone jobs promising high daily or weekly payouts.",
    ),
    FraudRule(
        rule_id="unofficial_form_or_shortlink",
        category="Unofficial Form / Shortened Apply Link",
        severity=Severity.MEDIUM,
        weight=14,
        pattern=re.compile(
            r"(?i)\b(?:forms\.gle\/[a-z0-9_-]+|docs\.google\.com\/forms\/[^\s]+|bit\.ly\/[a-z0-9_-]+|tinyurl\.com\/[a-z0-9_-]+|shorturl\.at\/[a-z0-9_-]+|rb\.gy\/[a-z0-9_-]+)\b",
        ),
        explanation="Directs applicants to a shortened URL or unofficial Google Form instead of a verified company career portal.",
        explanation_hi="आधिकारिक करियर पोर्टल के बजाय शॉर्ट लिंक या अनौपचारिक गूगल फॉर्म पर आवेदन करने को कहा गया है।",
        reason_it_matters="Shortened links hide the true destination domain, and fake Google Forms are frequently used to harvest personal data and UPI payments.",
        suggested_action="Verify the job on the employer's official website before entering personal details into any form.",
        respect_negation=False,
    ),
    # --- LOW / PRESSURE SEVERITY RULES ---
    FraudRule(
        rule_id="high_pressure_countdown",
        category="Artificial Urgency / Countdown Pressure",
        severity=Severity.LOW,
        weight=12,
        pattern=re.compile(
            r"(?i)\b(?:offer\s+(?:will\s+be\s+)?(?:cancelled|revoked|expired|withdrawn)\s+(?:within|in)\s+\d+\s*(?:minutes?|mins?|hours?|hrs?)|"
            r"(?:pay|deposit|register|confirm)\s+(?:within|in)\s+\d+\s*(?:minutes?|mins?|hours?|hrs?)|"
            r"(?:last|only)\s+\d+\s+(?:seats?|slots?|vacancies)\s+left.{0,30}(?:apply|pay|register|message|whatsapp|join)\s+(?:now|immediately|fast|today)|"
            r"(?:limited\s+(?:seats?|slots?)|hurry\s+up).{0,25}(?:register\s+now|pay\s+now|whatsapp|telegram)|"
            r"turant\s+(?:pay|fees|jama|paise))\b|"
            r"तुरंत\s+फीस\s+जमा\s+करें|आज\s+ही\s+पैसे\s+भेजें",
        ),
        explanation="Uses a short countdown deadline or artificial scarcity paired with pressure to act or pay immediately.",
        explanation_hi="बिना जांचे तुरंत भुगतान या सीट पक्की करने के लिए कम समय की चेतावनी दी गई है।",
        reason_it_matters="High-pressure countdowns prevent candidates from researching the company or consulting peers.",
        suggested_action="Pause and verify the company before responding; legitimate employers give reasonable time to review offers.",
        respect_negation=False,
    ),
]


# Positive legitimacy / trust signals (used for calibration when no CRITICAL/HIGH fraud rules fire)
LEGITIMACY_SIGNALS: List[Tuple[str, re.Pattern, int, str]] = [
    (
        "structured_interview_process",
        re.compile(
            r"(?i)\b(?:technical\s+(?:interview|round|assessment|screening)|coding\s+(?:round|test|challenge|assessment)|"
            r"online\s+(?:test|assessment)\s+and\s+(?:technical\s+)?interview|interview\s+(?:panel|slot|rounds?|schedule|feedback)|"
            r"portfolio\s+review|discovery\s+call|pre[\s-]placement\s+talk|google\s+meet|microsoft\s+teams|zoom\s+interview|"
            r"hiring\s+manager\s+(?:round|interview)|system\s+design\s+round)\b"
        ),
        8,
        "Mentions a structured, multi-step interview or technical assessment process.",
    ),
    (
        "professional_role_requirements",
        re.compile(
            r"(?i)\b(?:\d+\+?\s*(?:to|-)\s*\d*\s*years?\s+(?:of\s+)?experience|b\.?tech|m\.?tech|b\.?e\.?|mca|mba|"
            r"react|python|java|node\.?js|typescript|sql|kubernetes|aws|docker|figma|github\s+portfolio|"
            r"full[\s-]time\s+(?:on[\s-]site|hybrid)|hybrid\s+in\s+[a-z]+|ctc\b|\b\d+(?:\.\d+)?(?:\s*-\s*\d+(?:\.\d+)?)?\s*lpa\b)\b"
        ),
        6,
        "Includes realistic technical/academic qualifications, stack details, or standard compensation format.",
    ),
    (
        "trusted_ats_or_job_portal",
        re.compile(
            r"(?i)(?:boards\.greenhouse\.io|jobs\.lever\.co|myworkdayjobs\.com|jobs\.ashbyhq\.com|"
            r"jobs\.smartrecruiters\.com|linkedin\.com\/jobs|naukri\.com\/job-listings|careers\.[a-z0-9-]+\.(?:com|in|io|org)|"
            r"[a-z0-9-]+\.(?:com|in|io|org)\/careers\b)"
        ),
        8,
        "References a recognized corporate career portal or standard Applicant Tracking System (ATS).",
    ),
]


def detect_legitimacy_signals(text: str) -> List[Dict[str, object]]:
    """Detect positive credibility indicators (never override confirmed fraud)."""
    if not text:
        return []
    found: List[Dict[str, object]] = []
    for sig_id, pat, bonus, desc in LEGITIMACY_SIGNALS:
        m = pat.search(text)
        if m:
            found.append({
                "id": sig_id,
                "bonus": bonus,
                "matched_text": m.group(0),
                "description": desc,
            })
    return found


def run_rule_analysis(text: str, extracted: ExtractedJobData) -> Tuple[List[DetectionIndicator], bool]:
    """Run Layer A/B/G deterministic rules with negation and context awareness.

    Returns (indicators, has_anti_fraud_disclaimer).
    """
    if not text:
        return [], False

    has_disclaimer = bool(SAFETY_DISCLAIMER_RE.search(text))
    indicators: List[DetectionIndicator] = []
    seen_rules = set()

    for rule in RULES:
        for m in rule.pattern.finditer(text):
            if rule.respect_negation:
                prefix = text[max(0, m.start() - 65):m.start()]
                if NEGATION_PREFIX_RE.search(prefix):
                    continue
            matched = m.group(0).strip()
            if not matched:
                continue
            # Keep at most 1 indicator per rule_id to avoid double-counting the same rule twice
            if rule.rule_id in seen_rules:
                continue
            seen_rules.add(rule.rule_id)
            indicators.append(
                DetectionIndicator(
                    id=f"{rule.rule_id}_{len(indicators) + 1}",
                    category=rule.category,
                    matched_text=matched,
                    severity=rule.severity,
                    explanation=rule.explanation,
                    explanation_hi=rule.explanation_hi,
                    detection_method="deterministic_rule_engine",
                    reason_it_matters=rule.reason_it_matters,
                    suggested_action=rule.suggested_action,
                )
            )
            break

    # Layer B: Job advertisement structural anomaly checks (unusually high pay for minimal qualifications)
    if extracted.salary.status == "extracted" and extracted.salary.value:
        sal_val = extracted.salary.value.lower()
        low_qual = bool(
            re.search(
                r"(?i)\b(10th\s+pass|12th\s+pass|no\s+experience\s+(?:required|needed)|no\s+skills?\s+required|anyone\s+can\s+apply|only\s+smartphone\s+needed|fresher\s+10th|12th\s+fresher)\b",
                text,
            )
        )
        high_pay = bool(
            re.search(
                r"(?:₹|rs\.?|inr)\s*(?:[4-9]\d,?\d{3}|[1-9]\d{2},?\d{3})\s*(?:per\s+month|\/month|pm|monthly)?|(?:[1-9]\d)\s*lpa|(?:[4-9]\d|1\d\d)k\s*(?:\/month|per\s+month|pm)?",
                sal_val,
            )
        )
        if low_qual and high_pay:
            indicators.append(
                DetectionIndicator(
                    id=f"unrealistic_pay_for_qual_{len(indicators) + 1}",
                    category="Salary & Qualification Mismatch",
                    matched_text=extracted.salary.value,
                    severity=Severity.HIGH,
                    explanation="Advertises unusually high compensation alongside minimal or zero qualification requirements.",
                    explanation_hi="न्यूनतम योग्यता के साथ असामान्य रूप से बहुत अधिक वेतन का दावा किया गया है।",
                    detection_method="job_ad_structural_analysis",
                    reason_it_matters="Disproportionate compensation for no-skill roles is a common bait used to attract applicants into fee or data-harvesting scams.",
                    suggested_action="Compare the role's compensation with verified listings for similar entry-level roles.",
                )
            )

    return indicators, has_disclaimer


def compare_document_consistency(
    primary_text: str,
    primary_extracted: ExtractedJobData,
    secondary_text: Optional[str],
) -> List[dict]:
    """Layer H: Compare primary job description against a secondary document (e.g., offer letter or chat)."""
    if not secondary_text or not secondary_text.strip():
        return []

    secondary_extracted = extract_structured_job_data(secondary_text)
    conflicts: List[dict] = []

    fields_to_compare = [
        ("employer", "Employer Name"),
        ("role", "Job Title / Role"),
        ("salary", "Salary / Compensation"),
        ("location", "Job Location"),
        ("recruiter_email", "Recruiter Email"),
    ]

    for attr, label in fields_to_compare:
        f1 = getattr(primary_extracted, attr)
        f2 = getattr(secondary_extracted, attr)
        if f1.status == "extracted" and f2.status == "extracted" and f1.value and f2.value:
            v1_norm = re.sub(r"\s+", " ", f1.value.strip().lower())
            v2_norm = re.sub(r"\s+", " ", f2.value.strip().lower())
            if v1_norm != v2_norm and v1_norm not in v2_norm and v2_norm not in v1_norm:
                conflicts.append(
                    {
                        "field": label,
                        "primary_value": f1.value,
                        "secondary_value": f2.value,
                        "explanation": f"{label} differs between submitted materials ('{f1.value}' vs '{f2.value}').",
                    }
                )

    # Also check internal contradictions inside a single document
    if primary_extracted.additional_emails:
        dom1 = primary_extracted.recruiter_email.value.split("@")[-1].lower() if primary_extracted.recruiter_email.value else ""
        for extra in primary_extracted.additional_emails:
            dom2 = extra.split("@")[-1].lower()
            if dom1 and dom2 and dom1 != dom2:
                conflicts.append(
                    {
                        "field": "Email Domain Consistency",
                        "primary_value": primary_extracted.recruiter_email.value,
                        "secondary_value": extra,
                        "explanation": f"Multiple email addresses from different domains appear in the same recruitment material ('{dom1}' vs '{dom2}').",
                    }
                )

    return conflicts
