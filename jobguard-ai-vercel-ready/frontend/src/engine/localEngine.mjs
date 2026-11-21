/**
 * JobGuard AI — Calibrated Client-Side Verification Engine v2.0 (ES Module)
 * Mirrors the FastAPI backend's 17+ multilingual rules, 10-field extraction,
 * zero-visit URL inspection, PII redaction, compound multi-signal synergy,
 * positive legitimacy calibration, statistical n-gram text classifier,
 * 7-category evidence report, and Markdown exporter.
 */

export const MULTI_PART_TLDS = new Set([
  "co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "res.in", "edu.in",
  "co.uk", "org.uk", "com.au", "co.jp", "com.sg",
]);

export const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga",
  "buzz", "icu", "vip", "monster", "shop", "live", "online", "site", "club", "win",
]);

export const KNOWN_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy", "cutt.ly",
  "shorturl.at", "tiny.cc", "ow.ly", "rebrand.ly", "lnkd.in", "wa.me", "forms.gle",
]);

export const PROTECTED_EMPLOYERS = {
  infosys: { canonical: "Infosys Limited", domains: ["infosys.com"], portal: "https://www.infosys.com/careers/" },
  tcs: { canonical: "Tata Consultancy Services (TCS)", domains: ["tcs.com"], portal: "https://www.tcs.com/careers" },
  "tata consultancy": { canonical: "Tata Consultancy Services (TCS)", domains: ["tcs.com"], portal: "https://www.tcs.com/careers" },
  wipro: { canonical: "Wipro Limited", domains: ["wipro.com"], portal: "https://careers.wipro.com" },
  hcl: { canonical: "HCLTech", domains: ["hcltech.com", "hcl.com"], portal: "https://www.hcltech.com/careers" },
  hcltech: { canonical: "HCLTech", domains: ["hcltech.com", "hcl.com"], portal: "https://www.hcltech.com/careers" },
  accenture: { canonical: "Accenture", domains: ["accenture.com"], portal: "https://www.accenture.com/in-en/careers" },
  cognizant: { canonical: "Cognizant Technology Solutions", domains: ["cognizant.com"], portal: "https://careers.cognizant.com" },
  capgemini: { canonical: "Capgemini", domains: ["capgemini.com"], portal: "https://www.capgemini.com/careers/" },
  "tech mahindra": { canonical: "Tech Mahindra", domains: ["techmahindra.com"], portal: "https://careers.techmahindra.com" },
  ltimindtree: { canonical: "LTIMindtree", domains: ["ltimindtree.com"], portal: "https://www.ltimindtree.com/careers/" },
  deloitte: { canonical: "Deloitte", domains: ["deloitte.com"], portal: "https://jobsindia.deloitte.com" },
  pwc: { canonical: "PwC", domains: ["pwc.com"], portal: "https://www.pwc.in/careers.html" },
  kpmg: { canonical: "KPMG", domains: ["kpmg.com"], portal: "https://kpmg.com/in/en/home/careers.html" },
  ibm: { canonical: "IBM", domains: ["ibm.com"], portal: "https://www.ibm.com/careers" },
  oracle: { canonical: "Oracle", domains: ["oracle.com"], portal: "https://careers.oracle.com" },
  google: { canonical: "Google LLC", domains: ["google.com"], portal: "https://www.google.com/about/careers/" },
  microsoft: { canonical: "Microsoft Corporation", domains: ["microsoft.com"], portal: "https://careers.microsoft.com" },
  amazon: { canonical: "Amazon", domains: ["amazon.com", "amazon.jobs", "amazon.in"], portal: "https://www.amazon.jobs" },
  meta: { canonical: "Meta", domains: ["meta.com", "fb.com"], portal: "https://www.metacareers.com" },
  apple: { canonical: "Apple", domains: ["apple.com"], portal: "https://jobs.apple.com" },
  netflix: { canonical: "Netflix", domains: ["netflix.com"], portal: "https://jobs.netflix.com" },
  flipkart: { canonical: "Flipkart", domains: ["flipkart.com", "flipkartcareers.com"], portal: "https://www.flipkartcareers.com" },
  zoho: { canonical: "Zoho Corporation", domains: ["zohocorp.com", "zoho.com"], portal: "https://www.zoho.com/careers/" },
  razorpay: { canonical: "Razorpay", domains: ["razorpay.com"], portal: "https://razorpay.com/jobs/" },
  swiggy: { canonical: "Swiggy", domains: ["swiggy.in", "swiggy.com"], portal: "https://careers.swiggy.com" },
  zomato: { canonical: "Zomato", domains: ["zomato.com"], portal: "https://www.zomato.com/careers" },
  paytm: { canonical: "Paytm", domains: ["paytm.com"], portal: "https://paytm.com/careers/" },
  phonepe: { canonical: "PhonePe", domains: ["phonepe.com"], portal: "https://www.phonepe.com/careers/" },
  meesho: { canonical: "Meesho", domains: ["meesho.com"], portal: "https://www.meesho.io/jobs" },
  freshworks: { canonical: "Freshworks", domains: ["freshworks.com"], portal: "https://www.freshworks.com/company/careers/" },
  jio: { canonical: "Reliance Jio", domains: ["jio.com", "ril.com"], portal: "https://careers.jio.com" },
  hdfc: { canonical: "HDFC Bank", domains: ["hdfcbank.com"], portal: "https://www.hdfcbank.com/personal/about-us/careers" },
  icici: { canonical: "ICICI Bank", domains: ["icicibank.com"], portal: "https://www.icicicareers.com" },
  postman: { canonical: "Postman", domains: ["postman.com"], portal: "https://www.postman.com/company/careers/" },
};

export const PERSONAL_EMAIL_PROVIDERS = new Set([
  "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
  "live.com", "rediffmail.com", "protonmail.com", "proton.me", "icloud.com", "aol.com",
]);

const NEGATION_PREFIX_RE = /(?:never|do\s+not|don't|does\s+not|doesn't|will\s+not|won't|not\s+ask(?:ing)?\s+(?:for|you\s+to)|no\s+(?:upfront\s+|hidden\s+|kind\s+of\s+)?|zero|without\s+any|free\s+of|beware\s+of|warning\s*:|disclaimer\s*:|we\s+(?:never|do\s+not)\s+(?:charge|ask|demand|collect)|कभी\s+नहीं|न\s+दें|न\s+करें|नहीं\s+मांग|मत\s+दें|कोई\s+शुल्क\s+नहीं|mat\s+do|nahi\s+mangta|koi\s+fee\s+nahi)\s*(?:pay|charge|ask|collect|demand|share|give|send|require|take)?\s*(?:any\s+|for\s+)?$/i;

const SAFETY_DISCLAIMER_RE = /(?:never\s+(?:pay|send|share|transfer)\s+(?:any\s+)?(?:registration\s+fee|security\s+deposit|money|fee|amount|otp|upi\s+pin|password)|does\s+not\s+(?:charge|ask\s+for|collect|require)\s+(?:any\s+)?(?:fee|fees|money|deposit|payment)\s*(?:at\s+any\s+stage|during\s+recruitment|for\s+interviews?|for\s+jobs?)?|no\s+(?:registration\s+|application\s+|processing\s+)?fee(?:s)?\s+(?:is\s+|are\s+)?(?:charged|required)\s+(?:during|at\s+any\s+stage|for)|zero\s+(?:registration\s+)?fee(?:s)?\b|do\s+not\s+pay\s+any\s+(?:fee|fees|deposit|amount|money)|भर्ती\s+के\s+दौरान\s+कोई\s+शुल्क\s+नहीं\s+लिया\s+जाता|कोई\s+भी\s+रजिस्ट्रेशन\s+फीस\s+न\s+दें)/i;

export const FRAUD_RULES = [
  {
    id: "advance_registration_fee",
    category: "Advance Fee / Registration Scam",
    severity: "critical",
    weight: 50,
    respectNegation: true,
    rx: /(?<!\w)(?:(?:pay|deposit|submit|transfer|send|clear|remit)\s+(?:a\s+|an\s+|the\s+|just\s+|only\s+)?(?:nominal\s+|small\s+|one[\s-]time\s+|refundable\s+)?(?:(?:₹|Rs\.?|INR|\$|USD)\s*\d[\d,]*(?:\s*(?:only|\/-))?\s*)?(?:refundable\s+)?(?:registration|application|processing|joining|onboarding|interview|document(?:ation)?|verification|file|offer\s+letter|portal|gate\s+pass|id\s+card|seat\s+booking|agreement|stamp)\s*(?:fee|fees|charge|charges|amount|cost)|(?:pay|deposit|transfer|send)\s+(?:₹|Rs\.?|INR|\$|USD)\s*\d[\d,]*(?:\s*(?:only|\/-))?\s+(?:for|as|towards|to)\s+(?:registration|confirming|confirm\s+(?:your\s+)?(?:job|seat|slot|offer|selection)|joining|onboarding|processing|interview|verification|documentation|offer\s+letter|id\s+card|portal\s+activation)|(?:registration|processing|application|joining|onboarding|interview(?:\s+scheduling)?|document(?:ation)?\s+verification|file|agreement)\s*(?:fee|fees|charge|charges)\s*(?:of\s+(?:₹|Rs\.?|INR|\$|USD)?\s*\d[\d,]*|is\s+(?:₹|Rs\.?|INR|\$|USD)?\s*\d[\d,]*|is\s+(?:mandatory|required|applicable|compulsory|refundable)|to\s+(?:confirm|get\s+selected|schedule|proceed|activate)|jama\s+karo|jama\s+karein|bhejo|dena\s+hoga|lagta\s+hai|lagega)|(?:pehle|pahle)\s+(?:₹|Rs\.?)?\s*\d[\d,]*\s*(?:rupees?|rs)?\s*(?:registration|joining|processing|form)?\s*(?:fee|fees|charge|paisa|paise)?\s*(?:jama\s+karo|jama\s+karein|bhejo|do|dena\s+hoga))\b|रजिस्ट्रेशन\s+फीस\s*(?:जमा\s+करें|दें|देनी\s+होगी|₹?\s*\d[\d,]*)?|प्रोसेसिंग\s+फीस\s*(?:जमा\s+करें|दें|₹?\s*\d[\d,]*)?|जॉइनिंग\s+फीस|आवेदन\s+शुल्क\s+जमा\s+करें|फाइल\s+चार्ज/i,
    explanation: "Demands an upfront registration, interview, processing, offer-letter, or verification fee to proceed with hiring.",
    explanation_hi: "नौकरी या चयन के लिए पहले रजिस्ट्रेशन, प्रोसेसिंग, जॉइनिंग या सत्यापन शुल्क की मांग की गई है।",
    reason: "Legitimate employers never charge candidates to apply, interview, receive an offer letter, or confirm a job.",
    action: "Stop all communication immediately and never pay any fee to confirm a job.",
  },
  {
    id: "security_or_equipment_deposit",
    category: "Security / Equipment Deposit Scam",
    severity: "critical",
    weight: 50,
    respectNegation: true,
    rx: /(?<!\w)(?:refundable\s+(?:security\s+)?deposit|(?:security|caution|refundable|warranty)\s+deposit\s*(?:of\s+(?:₹|Rs\.?|INR|\$|USD)?\s*\d[\d,]*|is\s+(?:required|mandatory|refundable)|to\s+confirm|before\s+joining|jama\s+karo|dena\s+hoga)?|(?:laptop|equipment|macbook|id\s+card|kit|asset|uniform|courier|delivery)\s+(?:security\s+|shipping\s+|dispatch\s+)?(?:deposit|fee|fees|charge|charges)|(?:deposit|pay)\s+(?:money|(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*)\s+to\s+(?:unlock|release|receive|withdraw|unfreeze)\s+(?:your\s+)?(?:salary|payout|commission|earnings|account))\b|सिक्योरिटी\s+डिपॉजिट\s*(?:दें|जमा\s+करें|देना\s+होगा)?|लैपटॉप\s+डिपॉजिट|रिफंडेबल\s+डिपॉजिट/i,
    explanation: "Requests a 'refundable' security deposit, laptop/kit dispatch fee, or payment to unlock salary.",
    explanation_hi: "नौकरी, इंटर्नशिप या लैपटॉप के नाम पर 'रिफंडेबल' सिक्योरिटी डिपॉजिट की मांग की गई है।",
    reason: "Fraudsters label upfront payments as '100% refundable' to lower skepticism and disappear after collecting money.",
    action: "Refuse any security or equipment deposit and verify the company independently.",
  },
  {
    id: "upi_or_direct_payment_demand",
    category: "Direct UPI / QR / Payment Transfer Request",
    severity: "critical",
    weight: 48,
    respectNegation: true,
    rx: /(?<!\w)(?:(?:pay|send|transfer|deposit|scan)\s+(?:₹|Rs\.?|INR)?\s*\d[\d,]*(?:\s*(?:only|\/-))?\s*(?:via|through|on|to|by|using)\s+(?:upi|gpay|google\s*pay|phonepe|paytm|qr\s*code|neft|imps|bank\s+account)|(?:gpay|google\s*pay|phonepe|paytm|upi)\s+(?:karo|karein|kardo|kijiye|number|id)\s*(?::|is|on|at)?\s*(?:₹?\s*\d|[\w.-]+@[a-z]+)?|(?:send|share)\s+(?:the\s+|your\s+)?(?:payment|transaction|upi|gpay|phonepe|paytm)\s+(?:screenshot|receipt|utr|proof)|scan\s+(?:the\s+|this\s+)?qr\s*code\s+(?:to\s+)?(?:pay|complete|confirm|verify|receive\s+salary)|[a-zA-Z0-9._-]{3,}@(?:okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|paytm|upi|apl|fbl))\b|(?:यूपीआई|गूगल\s*पे|फोनपे|पेटीएम|क्यूआर\s*कोड)\s*(?:पर|से)\s*(?:पैसे|फीस|भुगतान)\s*(?:भेजें|करें)/i,
    explanation: "Asks for a direct UPI, GPay, PhonePe, Paytm, QR code payment, or payment screenshot during recruitment.",
    explanation_hi: "भर्ती के नाम पर UPI, GPay, PhonePe, Paytm या QR कोड से सीधे पैसे भेजने या पेमेंट स्क्रीनशॉट की मांग की गई है।",
    reason: "Legitimate employers never collect hiring fees on personal UPI IDs or ask candidates to scan QR codes to receive salary.",
    action: "Do not scan any QR code or transfer money to any UPI ID.",
  },
  {
    id: "prepaid_task_recharge_scam",
    category: "Prepaid Task & Recharge Scam",
    severity: "critical",
    weight: 52,
    respectNegation: true,
    rx: /(?<!\w)(?:prepaid\s+(?:merchant\s+|welfare\s+|vip\s+)?task|task\s+(?:recharge|upgrade|commission|wallet)|recharge\s+(?:your\s+)?(?:wallet|account|balance)\s+to\s+(?:complete|unlock|withdraw|continue)|vip\s+(?:telegram\s+)?task\s*(?:group|payout|commission|order)|(?:like|liking|subscribe|subscribing|follow|following)\s+(?:youtube|instagram|ig|tiktok|fb|facebook)\s*(?:videos?|reels?|channels?|posts?|pages?)\s*(?:and|&|to)?\s*(?:earn|get\s+paid|make\s+money|₹|rs)?|(?:rate|rating|review|reviewing)\s+(?:google\s+maps?|hotels?|restaurants?|places?|amazon\s+products?|flipkart\s+products?|apps?)\s*(?:and|&|to)?\s*(?:earn|get\s+paid|₹|rs)?|(?:₹|Rs\.?|INR)\s*(?:50|100|150|200|250|300|500)\s*(?:per|\/|for\s+each)\s*(?:[a-z]+\s+){0,2}(?:like|review|rating|task|subscribe|comment|video)s?|order\s+grabbing|merchant\s+order\s+tasks?|app\s+optimization\s+tasks?)\b|प्रीपेड\s+टास्क|वीडियो\s+लाइक\s+करके\s+कमाएं|टास्क\s+रिचार्ज|रिव्यू\s+लिखकर\s+कमाएं/i,
    explanation: "Describes a prepaid task, wallet recharge, order-grabbing, or paid video-liking / review-rating scheme.",
    explanation_hi: "वीडियो लाइक करने, गूगल रिव्यू देने या प्रीपेड टास्क रिचार्ज से कमाई का लालच दिया गया है।",
    reason: "Task scams pay small initial bait amounts (₹150–₹300) before trapping victims into depositing thousands in frozen 'VIP' tasks.",
    action: "Leave the Telegram/WhatsApp group immediately and do not recharge any task wallet.",
  },
  {
    id: "sensitive_credentials_request",
    category: "OTP / UPI PIN / Credential Theft",
    severity: "critical",
    weight: 54,
    respectNegation: true,
    rx: /(?<!\w)(?:(?:share|send|provide|enter|give|tell|forward|bhejo|batao)\s+(?:your\s+|the\s+|apna\s+)?(?:4[\s-]digit\s+|6[\s-]digit\s+)?(?:otp|upi\s+pin|atm\s+pin|debit\s+card\s+pin|cvv|cvc|netbanking\s+password|bank\s+password|mpin|login\s+password|card\s+number)|(?:otp|upi\s+pin|atm\s+pin|mpin|cvv)\s+(?:share\s+karo|bhejo|dalein|dalo|required\s+for\s+(?:salary|verification|onboarding|kyc)))\b|(?:ओटीपी|यूपीआई\s+पिन|एटीएम\s+पिन|पासवर्ड|सीवीवी)\s*(?:शेयर|साझा|भेजें|बताएं|डालें)/i,
    explanation: "Requests an OTP, UPI PIN, ATM PIN, CVV, or banking password during recruitment.",
    explanation_hi: "भर्ती या सैलरी वेरिफिकेशन के नाम पर ओटीपी, यूपीआई पिन, एटीएम पिन या पासवर्ड मांगा गया है।",
    reason: "No legitimate HR team ever needs your OTP, UPI PIN, CVV, or banking password.",
    action: "Never share OTPs, PINs, or passwords. If already shared, contact your bank and call 1930 immediately.",
  },
  {
    id: "remote_access_software",
    category: "Remote-Access Software Scam",
    severity: "critical",
    weight: 54,
    respectNegation: true,
    rx: /(?<!\w)(?:install|download|open|use|connect\s+(?:via|on))\s+(?:the\s+)?(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer|ammyy\s*admin)|(?<!\w)(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer)\b.{0,45}\b(?:code|id|verify|interview|hr|onboarding|screen|salary|bank)\b/i,
    explanation: "Asks you to install remote-access software (AnyDesk, TeamViewer, QuickSupport) for onboarding or HR verification.",
    explanation_hi: "ऑनबोर्डिंग या सत्यापन के लिए AnyDesk या TeamViewer जैसे रिमोट-एक्सेस ऐप इंस्टॉल करने को कहा गया है।",
    reason: "Remote-access apps allow scammers to control your device, read OTPs, and drain bank accounts live.",
    action: "Do not install AnyDesk/TeamViewer for recruiters. Uninstall immediately if already installed.",
  },
  {
    id: "crypto_or_investment_job_lure",
    category: "Crypto / Investment / Deposit-Return Job Scam",
    severity: "high",
    weight: 36,
    respectNegation: true,
    rx: /(?<!\w)(?:invest\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*\s*(?:and|&|to)\s*(?:earn|get|withdraw)\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*|deposit\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*\s*(?:and|&)\s*(?:get|receive|withdraw)\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*|salary\s+(?:paid\s+)?in\s+(?:usdt|crypto|bitcoin|btc|eth)|crypto\s+(?:trading|task|wallet)\s+(?:job|commission|bonus)|double\s+your\s+(?:money|income|deposit))\b/i,
    explanation: "Mixes job recruitment with investment returns, deposit-and-withdraw bonuses, or crypto/USDT task commissions.",
    explanation_hi: "नौकरी के नाम पर पैसे निवेश करने, डिपॉजिट पर तुरंत रिटर्न या क्रिप्टो/USDT टास्क का लालच दिया गया है।",
    reason: "Legitimate jobs pay you for your work—they never require you to deposit money to earn returns.",
    action: "Avoid any 'job' that asks you to invest or deposit funds to receive higher payouts.",
  },
  {
    id: "mandatory_paid_training",
    category: "Paid Training / Fake Internship Scam",
    severity: "high",
    weight: 34,
    respectNegation: true,
    rx: /(?<!\w)(?:pay\s+(?:for\s+)?(?:(?:₹|Rs\.?|INR|\$)\s*\d[\d,]*\s+)?(?:mandatory|compulsory|paid)?\s*(?:training|course|certification|internship)\s*(?:fee|fees|charge|before\s+joining|to\s+get\s+(?:hired|selected|placed|offer))?|(?:mandatory|compulsory)\s+paid\s+(?:training|certification|internship|course)|guaranteed\s+(?:job|placement|internship\s+certificate)\s+(?:after|in\s+exchange\s+for|with)\s+(?:paying|payment|fee|course)|buy\s+(?:our\s+)?(?:internship|training)\s+certificate|(?:training|internship|placement)\s+(?:fee|charges?)\s*(?:of\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*|is\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*|mandatory))\b|ट्रेनिंग\s+फीस\s*(?:जमा\s+करें|देनी\s+होगी)?|इंटर्नशिप\s+फीस/i,
    explanation: "Requires paying for mandatory training, an internship, or a certificate in exchange for guaranteed employment.",
    explanation_hi: "नौकरी की गारंटी के बदले अनिवार्य पेड ट्रेनिंग, इंटर्नशिप या सर्टिफिकेट शुल्क मांगा गया है।",
    reason: "Pay-to-work training traps target students and freshers by selling worthless certificates under a fake job promise.",
    action: "Verify whether the opportunity is genuine employment or a disguised paid course.",
  },
  {
    id: "unrealistic_wfh_earnings",
    category: "Unrealistic Salary / WFH Compensation",
    severity: "high",
    weight: 32,
    respectNegation: true,
    rx: /(?<!\w)(?:earn\s+(?:up\s+to\s+|upto\s+)?(?:₹|Rs\.?|INR)\s*(?:[1-9],?\d{3}|[1-9]\d,?\d{3}|\d{4,5})(?:\s*(?:-|to|–)\s*(?:₹|Rs\.?|INR)?\s*\d[\d,]*)?\s*(?:per\s+day|daily|\/day|a\s+day|every\s+day)|earn\s+(?:up\s+to\s+|upto\s+)?(?:\$|USD)\s*(?:[1-9]\d{2,})(?:\s*(?:-|to|–)\s*\$?\d[\d,]*)?\s*(?:per\s+day|daily|\/day|per\s+hour|\/hr)|(?:daily|everyday)\s+(?:income|payout|earning|earnings|salary|profit)\s*(?:of\s+|is\s+|:|-)?\s*(?:₹|Rs\.?|INR)?\s*(?:[1-9],?\d{3}|[1-9]\d,?\d{3}|\d{4,5})|(?:₹|Rs\.?|INR)\s*(?:[1-9],?\d{3}|[1-9]\d,?\d{3})(?:\s*(?:-|to|–)\s*(?:₹|Rs\.?|INR)?\s*\d[\d,]*)?\s*(?:per\s+day|daily|\/day)\s*(?:from\s+home|wfh|part[\s-]time|online|guaranteed)?|(?:roz|roj|daily)\s+(?:₹|Rs\.?)?\s*\d{3,5}\s*(?:se\s+\d{3,5}\s*)?kama(?:yein|ye|o|aye)|ghar\s+baithe\s+(?:roz|roj|daily|mahine|online)?\s*(?:₹|Rs\.?)?\s*\d{3,6}\s*(?:kama(?:yein|ye|o)|income|salary)?|mobile\s+se\s+(?:roz|daily|ghar\s+baithe)?\s*(?:paise|paisa|₹?\s*\d[\d,]*)\s*kama(?:yein|ye|o))\b|घर\s+बैठे\s+(?:रोज़|रोज|प्रतिदिन)?\s*₹?\s*\d[\d,]*\s*(?:कमाएं|कमाए|रुपये)/i,
    explanation: "Promises unusually high daily earnings (e.g., ₹1,000–₹10,000/day) for simple work-from-home or mobile tasks.",
    explanation_hi: "सरल घर बैठे या मोबाइल काम के लिए रोज़ाना हजारों रुपये की अवास्तविक कमाई का वादा किया गया है।",
    reason: "Disproportionately high daily payouts for minimal skills are a primary lure for WFH and task fraud.",
    action: "Benchmark the claimed pay against standard market salaries for that role.",
  },
  {
    id: "guaranteed_selection_no_interview",
    category: "Fake Selection / Guaranteed Job Promise",
    severity: "high",
    weight: 30,
    respectNegation: true,
    rx: /(?<!\w)(?:guaranteed\s+(?:selection|job|placement|joining|offer|income)\s*(?:without\s+(?:any\s+)?interview|100%|today)?|100%\s+(?:job|placement|selection)\s+guarantee|(?:direct|instant|immediate)\s+(?:joining|selection|hiring)\s+(?:without|with\s+no|no)\s+(?:any\s+)?(?:interview|exam|test)|(?:selected|shortlisted|hired)\s+without\s+(?:any\s+)?(?:interview|test|exam)|no\s+interview\s+(?:required|needed)\s*(?:for\s+(?:direct\s+)?joining)?|bina\s+(?:kisi\s+)?interview\s+(?:ke\s+)?(?:direct\s+)?(?:selection|naukri|job|joining|bharti))\b|बिना\s+(?:किसी\s+)?इंटरव्यू\s+(?:के\s+)?(?:सीधी\s+भर्ती|नौकरी|चयन|जॉइनिंग)/i,
    explanation: "Promises guaranteed job selection, 100% placement, or direct joining without any interview or evaluation.",
    explanation_hi: "बिना किसी इंटरव्यू या जांच के पक्की नौकरी या सीधे चयन का वादा किया गया है।",
    reason: "Reputable employers evaluate candidates through interviews or assessments before issuing an offer.",
    action: "Verify the hiring process directly on the employer's official career portal.",
  },
  {
    id: "sensitive_kyc_upfront",
    category: "Upfront KYC / Identity & Bank Document Harvest",
    severity: "high",
    weight: 38,
    respectNegation: true,
    rx: /(?<!\w)(?:(?:send|share|submit|whatsapp|upload)\s+(?:your\s+)?(?:aadhaar|aadhar|pan\s+card|bank\s+passbook|cancelled\s+cheque|debit\s+card|credit\s+card|selfie\s+with\s+(?:aadhaar|pan|id))\b.{0,45}\b(?:whatsapp|telegram|immediately|urgent|today|now|confirm|verification|salary|joining)|(?:aadhaar|aadhar)\s*(?:and|&|\/|\+)\s*pan\s*(?:card)?\s*(?:and|&|,)?\s*(?:bank\s+(?:details|account|passbook)|selfie)\s*(?:on\s+whatsapp|immediately|to\s+confirm|for\s+joining))\b|(?:आधार|पैन\s+कार्ड|बैंक\s+पासबुक)\s*(?:व्हाट्सएप|टेलीग्राम)\s*पर\s*भेजें/i,
    explanation: "Requests sensitive KYC documents (Aadhaar, PAN, bank passbook, or ID selfie) over chat before verified hiring.",
    explanation_hi: "सत्यापित ऑफर से पहले ही व्हाट्सएप/चैट पर आधार, पैन या बैंक पासबुक जैसे संवेदनशील दस्तावेज मांगे गए हैं।",
    reason: "Scammers harvest Aadhaar/PAN/bank details for identity theft, mule accounts, and fraudulent loans.",
    action: "Never share Aadhaar, PAN, or bank passbook photos over WhatsApp/Telegram before verifying the employer.",
  },
  {
    id: "data_entry_typing_wfh_bait",
    category: "High-Risk Data Entry / Typing / Copy-Paste WFH Bait",
    severity: "medium",
    weight: 20,
    respectNegation: true,
    rx: /(?<!\w)(?:(?:online|home[\s-]based|part[\s-]time|wfh|work\s+from\s+home)\s+(?:data\s+entry|form\s+filling|captcha\s+(?:typing|entry|work)|copy[\s-]paste|page\s+typing|handwriting|sms\s+sending|ad\s+(?:posting|clicking))\s*(?:job|work|project)?|(?:captcha\s+(?:typing|entry|solving)|form\s+filling|copy[\s-]paste|page\s+typing|pdf\s+to\s+word\s+typing)\s+(?:job|work)\s*(?:from\s+home|online|daily\s+payout|earn)?)\b|(?:डेटा\s+एंट्री|फॉर्म\s+फिलिंग|कॉपी\s+पेस्ट|कैप्चा\s+टाइपिंग)\s*(?:जॉब|काम)/i,
    explanation: "Advertises a classic high-fraud WFH job category (captcha typing, form filling, copy-paste, or online page typing).",
    explanation_hi: "ऑनलाइन डेटा एंट्री, फॉर्म फिलिंग, कॉपी-पेस्ट या कैप्चा टाइपिंग जैसे उच्च-जोखिम वाले काम का प्रस्ताव है।",
    reason: "Form-filling, captcha, and copy-paste WFH ads are overwhelmingly used to trap applicants into agreement fees or legal-threat extortion.",
    action: "Verify the employer's legal registration and never sign penalty agreements or pay starter fees.",
  },
  {
    id: "messaging_only_funnel",
    category: "WhatsApp / Telegram-Only Recruitment Funnel",
    severity: "medium",
    weight: 18,
    respectNegation: true,
    rx: /(?<!\w)(?:(?:contact|message|msg|dm|ping|reach|chat\s+with|apply\s+on|reply\s+on|text)\s+(?:hr\s+|us\s+|me\s+)?(?:only\s+)?(?:on|via|at)\s+(?:whatsapp|telegram)|whatsapp\s+(?:us|me|hr|now|your\s+(?:cv|resume|name|details)|at\s+\+?\d|on\s+\+?\d)|join\s+(?:our\s+)?(?:official\s+)?(?:telegram|whatsapp)\s+(?:job|hr|task|vip|work|earning|hiring)?\s*(?:channel|group)|(?:reply|send|type)\s+['"]?(?:yes|interested|ok|hi|start)['"]?\s+(?:on\s+whatsapp|to\s+start|for\s+(?:details|joining|info))|t\.me\/[a-z0-9_]+|wa\.me\/\d+|chat\.whatsapp\.com\/[a-z0-9]+)\b|(?:व्हाट्सएप|टेलीग्राम)\s*(?:पर\s+)?(?:मैसेज|संपर्क|जॉइन)\s*करें/i,
    explanation: "Routes recruitment through WhatsApp or Telegram messaging or asks you to reply 'YES/INTERESTED' to start.",
    explanation_hi: "भर्ती प्रक्रिया को व्हाट्सएप या टेलीग्राम के माध्यम से चलाने या 'YES' रिप्लाई करने को कहा गया है।",
    reason: "Corporate hiring funnels conducted exclusively on Telegram/WhatsApp lack auditability and are heavily abused by scammers.",
    action: "Ask for an official corporate email confirmation and a listing on the company's career website.",
  },
  {
    id: "unsolicited_shortlist_bait",
    category: "Unsolicited Generic Shortlist / Mass-Outreach Bait",
    severity: "medium",
    weight: 16,
    respectNegation: true,
    rx: /(?<!\w)(?:(?:congratulations|congrats|greetings)[!.,\s]+(?:your\s+)?(?:resume|cv|profile|number|mobile\s+number)\s+(?:has\s+been\s+|is\s+|was\s+)?(?:shortlisted|selected|approved)\s*(?:for\s+(?:a\s+|an\s+|our\s+)?(?:part[\s-]time|work\s+from\s+home|online|remote|urgent)?\s*(?:job|vacancy|role|position|interview))?|we\s+(?:found|got|received)\s+your\s+(?:resume|cv|number|contact)\s+(?:from|on)\s+(?:a\s+job\s+portal|job\s+portals|database|naukri|shine|indeed)\s*[,.\-]\s*(?:we\s+are\s+hiring|part[\s-]time|earn|work\s+from\s+home)|hello,?\s+i\s+am\s+(?:hr|recruiter|manager)\s+(?:from|at)\s+(?:a\s+)?(?:leading|top|reputed|mnc)\s+(?:company|agency|e[\s-]commerce))\b/i,
    explanation: "Uses a generic mass-outreach opener ('Congratulations, your resume is shortlisted') without verifiable job specifics.",
    explanation_hi: "बिना स्पष्ट विवरण के सामान्य थोक संदेश ('बधाई हो, आपका रिज्यूमे शॉर्टलिस्ट हो गया है') का उपयोग किया गया है।",
    reason: "Scammers blast identical 'resume shortlisted' messages to thousands of phone numbers to lure targets into WhatsApp/Telegram funnels.",
    action: "Check if you actually applied to this company and ask for the official requisition ID and corporate email.",
  },
  {
    id: "vague_zero_skill_lure",
    category: "Zero-Skill / Smartphone-Only Earning Pitch",
    severity: "medium",
    weight: 14,
    respectNegation: true,
    rx: /(?<!\w)(?:(?:only|just)\s+(?:a\s+)?(?:smartphone|mobile\s+phone|phone)\s+(?:is\s+)?(?:needed|required)|(?:work|working)\s+(?:just\s+|only\s+)?(?:1|2|1[\s-]2|1\s+to\s+2|2[\s-]3)\s+hours?\s*(?:per\s+day|daily|a\s+day)\s*(?:from\s+(?:home|mobile|phone)|and\s+earn)?|(?:no\s+skills?|no\s+qualification|no\s+experience)\s+(?:required|needed)\s*(?:[,!&+]\s*(?:anyone|students|housewives|freshers|earn|daily|weekly))|(?:students|housewives|homemakers|retired|job\s+seekers)\s*(?:,|\/|and|&)\s*(?:housewives|students|freshers|part[\s-]timers)\s+(?:can\s+)?(?:apply|earn|join)|age\s*(?::|\s)\s*(?:18|20|21|22|23|25)\s*(?:-|to|\+)\s*(?:55|60|65)?\s*(?:years?|yrs?)?\s*(?:above|only|and\s+above))\b/i,
    explanation: "Markets a '1–2 hours daily on smartphone, no skills needed' pitch targeting broad demographics.",
    explanation_hi: "बिना किसी कौशल के केवल मोबाइल से रोज़ 1-2 घंटे काम करके कमाई का प्रचार किया गया है।",
    reason: "Scam recruiters intentionally target students, housewives, and freshers with zero-barrier smartphone work pitches.",
    action: "Be skeptical of zero-skill smartphone jobs promising high daily or weekly payouts.",
  },
  {
    id: "unofficial_form_or_shortlink",
    category: "Unofficial Form / Shortened Apply Link",
    severity: "medium",
    weight: 14,
    respectNegation: false,
    rx: /(?<!\w)(?:forms\.gle\/[a-z0-9_-]+|docs\.google\.com\/forms\/[^\s]+|bit\.ly\/[a-z0-9_-]+|tinyurl\.com\/[a-z0-9_-]+|shorturl\.at\/[a-z0-9_-]+|rb\.gy\/[a-z0-9_-]+)\b/i,
    explanation: "Directs applicants to a shortened URL or unofficial Google Form instead of a verified company career portal.",
    explanation_hi: "आधिकारिक करियर पोर्टल के बजाय शॉर्ट लिंक या अनौपचारिक गूगल फॉर्म पर आवेदन करने को कहा गया है।",
    reason: "Shortened links hide the true destination domain, and fake Google Forms are frequently used to harvest personal data and UPI payments.",
    action: "Verify the job on the employer's official website before entering personal details into any form.",
  },
  {
    id: "high_pressure_countdown",
    category: "Artificial Urgency / Countdown Pressure",
    severity: "low",
    weight: 12,
    respectNegation: false,
    rx: /(?<!\w)(?:offer\s+(?:will\s+be\s+)?(?:cancelled|revoked|expired|withdrawn)\s+(?:within|in)\s+\d+\s*(?:minutes?|mins?|hours?|hrs?)|(?:pay|deposit|register|confirm)\s+(?:within|in)\s+\d+\s*(?:minutes?|mins?|hours?|hrs?)|(?:last|only)\s+\d+\s+(?:seats?|slots?|vacancies)\s+left.{0,30}(?:apply|pay|register|message|whatsapp|join)\s+(?:now|immediately|fast|today)|(?:limited\s+(?:seats?|slots?)|hurry\s+up).{0,25}(?:register\s+now|pay\s+now|whatsapp|telegram)|turant\s+(?:pay|fees|jama|paise))\b|तुरंत\s+फीस\s+जमा\s+करें|आज\s+ही\s+पैसे\s+भेजें/i,
    explanation: "Uses a short countdown deadline or artificial scarcity paired with pressure to act or pay immediately.",
    explanation_hi: "बिना जांचे तुरंत भुगतान या सीट पक्की करने के लिए कम समय की चेतावनी दी गई है।",
    reason: "High-pressure countdowns prevent candidates from researching the company or consulting peers.",
    action: "Pause and verify the company before responding; legitimate employers give reasonable time to review offers.",
  },
];

const LEGITIMACY_SIGNALS = [
  {
    id: "structured_interview_process",
    bonus: 8,
    rx: /\b(?:technical\s+(?:interview|round|assessment|screening)|coding\s+(?:round|test|challenge|assessment)|online\s+(?:test|assessment)\s+and\s+(?:technical\s+)?interview|interview\s+(?:panel|slot|rounds?|schedule|feedback)|portfolio\s+review|discovery\s+call|pre[\s-]placement\s+talk|google\s+meet|microsoft\s+teams|zoom\s+interview|hiring\s+manager\s+(?:round|interview)|system\s+design\s+round)\b/i,
    desc: "Mentions a structured interview or technical assessment process.",
  },
  {
    id: "professional_role_requirements",
    bonus: 6,
    rx: /\b(?:\d+\+?\s*(?:to|-)\s*\d*\s*years?\s+(?:of\s+)?experience|b\.?tech|m\.?tech|b\.?e\.?|mca|mba|react|python|java|node\.?js|typescript|sql|kubernetes|aws|docker|figma|github\s+portfolio|full[\s-]time\s+(?:on[\s-]site|hybrid)|hybrid\s+in\s+[a-z]+|ctc\b|\b\d+(?:\.\d+)?(?:\s*-\s*\d+(?:\.\d+)?)?\s*lpa\b)\b/i,
    desc: "Includes realistic qualifications, tech stack, or standard compensation structure.",
  },
  {
    id: "trusted_ats_or_job_portal",
    bonus: 8,
    rx: /(?:boards\.greenhouse\.io|jobs\.lever\.co|myworkdayjobs\.com|jobs\.ashbyhq\.com|jobs\.smartrecruiters\.com|linkedin\.com\/jobs|naukri\.com\/job-listings|careers\.[a-z0-9-]+\.(?:com|in|io|org)|[a-z0-9-]+\.(?:com|in|io|org)\/careers\b)/i,
    desc: "References a recognized corporate career portal or standard ATS.",
  },
];

// Lightweight client-side weighted log-odds statistical text classifier (EN / HI / Hinglish)
const STAT_LEXICON = [
  ["registration fee", 1.85], ["security deposit", 1.85], ["refundable", 1.2], ["processing fee", 1.75],
  ["prepaid task", 2.0], ["recharge", 1.55], ["vip task", 1.9], ["anydesk", 2.1], ["teamviewer", 2.0],
  ["upi pin", 2.1], ["otp", 1.4], ["gpay", 1.5], ["phonepe", 1.5], ["paytm", 1.2], ["qr code", 1.5],
  ["without interview", 1.8], ["direct joining", 1.6], ["bina interview", 1.9], ["jama karo", 1.9],
  ["ghar baithe", 1.6], ["roz kama", 1.6], ["per day", 1.15], ["daily payout", 1.5], ["daily income", 1.55],
  ["youtube video", 1.4], ["google maps", 1.3], ["whatsapp", 0.95], ["telegram", 1.25], ["t.me/", 1.45],
  ["no experience", 0.9], ["no skills", 1.25], ["10th pass", 1.15], ["12th pass", 1.05], ["smartphone", 0.95],
  ["housewives", 1.1], ["reply yes", 1.3], ["captcha", 1.65], ["form filling", 1.55], ["copy paste", 1.45],
  ["usdt", 1.6], ["aadhaar", 0.95], ["passbook", 1.25], ["screenshot", 0.85], ["payment", 0.75],
  ["सिक्योरिटी डिपॉजिट", 2.0], ["रजिस्ट्रेशन फीस", 2.0], ["बिना इंटरव्यू", 1.9], ["घर बैठे", 1.5],
  // Legitimate negative weights
  ["technical interview", -1.45], ["coding round", -1.45], ["google meet", -1.15], ["microsoft teams", -1.15],
  ["github", -1.0], ["portfolio", -0.95], ["lpa", -0.9], ["ctc", -0.85], ["assessment", -1.05],
  ["never pay", -1.8], ["does not charge", -1.8], ["zero fees", -1.5], ["no fee", -1.4],
  ["careers", -0.75], ["requisition", -1.0], ["hiring manager", -1.2], ["greenhouse.io", -1.4],
  ["lever.co", -1.4], ["workday", -1.2], ["hybrid", -0.7], ["on-site", -0.7], ["notice period", -1.1],
  ["कोई शुल्क नहीं", -1.8],
];

export function runLocalTextClassifier(text) {
  const lower = (text || "").toLowerCase();
  if (!lower.trim()) {
    return {
      available: true,
      model_type: "Client-Side Weighted N-Gram Log-Odds Classifier",
      predicted_label: "Ambiguous / Mixed Text Signal",
      scam_probability_estimate: 0.5,
      top_contributing_terms: [],
      dataset_disclosure: "Local browser statistical text scorer using curated EN/HI/Hinglish n-gram weights; serves as a supporting signal alongside deterministic rules.",
    };
  }
  let z = -0.15;
  const hits = [];
  for (const [term, w] of STAT_LEXICON) {
    if (lower.includes(term)) {
      z += w;
      hits.push([w, term]);
    }
  }
  const prob = Number((1 / (1 + Math.exp(-Math.max(-12, Math.min(12, z))))).toFixed(3));
  hits.sort((a, b) => Math.abs(b[0]) - Math.abs(a[0]));
  const topTerms = hits.slice(0, 6).map(([w, t]) => `${t} (${w >= 0 ? "+" : ""}${w.toFixed(2)})`);
  const label = prob >= 0.65 ? "Elevated Scam Text Pattern" : prob >= 0.35 ? "Ambiguous / Mixed Text Signal" : "Low Scam Text Pattern";
  return {
    available: true,
    model_type: "Client-Side Weighted N-Gram Log-Odds Classifier",
    predicted_label: label,
    scam_probability_estimate: prob,
    top_contributing_terms: topTerms,
    dataset_disclosure: "Local browser statistical text scorer using curated EN/HI/Hinglish n-gram weights; serves as a supporting signal alongside deterministic rules.",
  };
}

export function redactSensitiveInfo(text) {
  if (!text) return { redacted: "", counts: {} };
  const patterns = [
    ["aadhaar", /(?<!\d)(?:[2-9]\d{3}[\s-]\d{4}[\s-]\d{4}|[2-9]\d{11})(?!\d)/g, "[REDACTED_AADHAAR]"],
    ["pan", /\b[A-Z]{5}\d{4}[A-Z]\b/g, "[REDACTED_PAN]"],
    ["ifsc", /\b[A-Z]{4}0[A-Z0-9]{6}\b/g, "[REDACTED_IFSC]"],
    ["card_number", /(?<!\d)(?:\d{4}[\s-]){3}\d{4}(?!\d)/g, "[REDACTED_CARD]"],
    ["bank_account", /((?:a\/c|acct|account)\s*(?:no\.?|number|#)?\s*[:=-]?\s*)\d{9,18}\b/gi, "$1[REDACTED_BANK_ACCOUNT]"],
    ["otp_pin_cvv", /((?:otp|upi\s*pin|atm\s*pin|mpin|cvv|cvc|pin\s*(?:code|is|:))\s*(?:is|code|:|=|-)?\s*)\d{3,8}\b/gi, "$1[REDACTED_SECRET_CODE]"],
    ["password", /((?:password|passcode|pwd)\s*(?:is|:|=)\s*)\S{3,40}/gi, "$1[REDACTED_PASSWORD]"],
  ];
  let redacted = text;
  const counts = {};
  for (const [label, regex, replacement] of patterns) {
    let n = 0;
    redacted = redacted.replace(regex, (...args) => {
      n += 1;
      return typeof replacement === "string" && replacement.includes("$1")
        ? replacement.replace("$1", args[1] || "")
        : replacement;
    });
    if (n > 0) counts[label] = n;
  }
  return { redacted, counts };
}

export function detectLanguage(text, hint = "auto") {
  if (["en", "hi", "hinglish"].includes(hint)) return hint;
  if (!text) return "en";
  const devanagari = (text.match(/[\u0900-\u097F]/g) || []).length;
  const latin = (text.match(/[a-zA-Z]/g) || []).length;
  if (devanagari >= 5 && devanagari >= latin * 0.2) return "hi";
  if (/\b(aapka|aapke|abhi|karo|karein|turant|bhejo|jama|paisa|paise|naukri|ghar\s+baithe|bina\s+interview|roz|kamayein|kamao|fees|pehle|bharti)\b/i.test(text)) {
    return "hinglish";
  }
  return "en";
}

export function extractRegistrableDomain(hostname) {
  const host = (hostname || "").toLowerCase().replace(/^\.+|\.+$/g, "");
  if (!host) return { regDomain: "", subdomains: [] };
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return { regDomain: host, subdomains: [] };
  const parts = host.split(".");
  if (parts.length < 2) return { regDomain: host, subdomains: [] };
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return { regDomain: parts.slice(-3).join("."), subdomains: parts.slice(0, -3) };
  }
  return { regDomain: lastTwo, subdomains: parts.slice(0, -2) };
}

export function extractUrlsFromText(text) {
  if (!text) return [];
  const regex = /(?:https?:\/\/|www\.)[^\s<>"'\)\]]+|\b(?:[a-zA-Z0-9-]+\.)+(?:in|com|org|net|io|co|xyz|top|click|icu|vip|online|site|live|shop|info|jobs|co\.in|gov\.in|ly|at|gy|cc|me|gle)(?:\/[^\s<>"'\)\]]*)?/gi;
  const out = [];
  const seen = new Set();
  let m;
  while ((m = regex.exec(text)) !== null) {
    if (m.index > 0 && text[m.index - 1] === "@") continue;
    const clean = m[0].replace(/[.,;:!?'\")\]}]+$/, "");
    if (clean && !seen.has(clean.toLowerCase())) {
      seen.add(clean.toLowerCase());
      out.push(clean);
    }
  }
  return out.slice(0, 8);
}

export function inspectUrlStructurally(rawUrl) {
  const submitted = (rawUrl || "").trim();
  const lower = submitted.toLowerCase();
  if (/^(javascript|data|vbscript|file):/.test(lower)) {
    return {
      submitted_url: submitted, normalized_url: submitted, hostname: "", registrable_domain: "",
      subdomains: [], scheme: lower.split(":")[0], is_https: false, is_ip_address: false,
      is_shortened: false, has_punycode_or_idn: false, subdomain_count: 0,
      impersonated_brand: null, official_domains: [], risk_level: "HIGH RISK", risk_index: 95,
      summary: "Executable or unsafe URI scheme detected. Never open this link.",
      signals: [{ signal: "dangerous_uri_scheme", severity: "critical", explanation: "Non-web executable URI scheme." }],
      reputation_status: "Check Unavailable", reputation_provider: "none (local zero-visit structural inspection)",
      recommended_actions: ["Do not click or paste this address into your browser."],
      limitations: ["Zero-visit structural inspection; URL was never opened."],
    };
  }
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(submitted) ? submitted : "http://" + submitted;
  let parsed;
  try { parsed = new URL(withScheme); } catch {
    return {
      submitted_url: submitted, normalized_url: withScheme, hostname: "", registrable_domain: "",
      subdomains: [], scheme: "invalid", is_https: false, is_ip_address: false,
      is_shortened: false, has_punycode_or_idn: false, subdomain_count: 0,
      impersonated_brand: null, official_domains: [], risk_level: "HIGH RISK", risk_index: 80,
      summary: "Malformed recruitment URL.",
      signals: [{ signal: "malformed_url", severity: "high", explanation: "Not a valid standard URL." }],
      reputation_status: "Check Unavailable", reputation_provider: "none (local zero-visit structural inspection)",
      recommended_actions: ["Do not open malformed links."], limitations: ["Zero-visit structural inspection."],
    };
  }
  const scheme = parsed.protocol.replace(":", "").toLowerCase();
  const isHttps = scheme === "https";
  const host = (parsed.hostname || "").toLowerCase().replace(/^\.+|\.+$/g, "");
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  const hasIdn = host.includes("xn--") || /[^\x00-\x7F]/.test(host);
  const { regDomain, subdomains } = extractRegistrableDomain(host);
  const isShortened = KNOWN_SHORTENERS.has(regDomain);
  const signals = [];
  let points = 0;

  if (parsed.username || parsed.password || submitted.includes("@")) { points += 42; signals.push({ signal: "embedded_credentials_in_url", severity: "high", explanation: "Contains '@' in URL authority." }); }
  if (isIp) { points += 45; signals.push({ signal: "raw_ip_address", severity: "high", explanation: "Uses raw numeric IP address." }); }
  if (hasIdn) { points += 38; signals.push({ signal: "punycode_or_idn_homograph", severity: "high", explanation: "Contains Punycode/IDN characters." }); }
  if (!isHttps) { points += 14; signals.push({ signal: "unencrypted_http", severity: "medium", explanation: "Uses unencrypted HTTP." }); }
  if (host.length > 40) { points += 20; signals.push({ signal: "excessively_long_hostname", severity: "medium", explanation: `Long hostname (${host.length} chars).` }); }
  if (subdomains.length >= 3) { points += 22; signals.push({ signal: "excessive_subdomains", severity: "medium", explanation: `Contains ${subdomains.length} subdomains.` }); }
  const tld = regDomain.split(".").pop() || "";
  if (SUSPICIOUS_TLDS.has(tld)) { points += 26; signals.push({ signal: "suspicious_tld", severity: "medium", explanation: `Uses high-abuse TLD '.${tld}'.` }); }
  if (isShortened) { points += 24; signals.push({ signal: "url_shortener", severity: "medium", explanation: `Uses URL shortener '${regDomain}'.` }); }

  let impersonatedBrand = null;
  let officialDomains = [];
  const fullLower = (host + parsed.pathname).toLowerCase();
  const tokens = new Set(fullLower.split(/[^a-z0-9]+/).filter(Boolean));
  for (const [key, info] of Object.entries(PROTECTED_EMPLOYERS)) {
    if (key.includes(" ")) continue;
    const hit = key.length <= 3 ? tokens.has(key) : fullLower.includes(key);
    if (hit && !info.domains.includes(regDomain)) {
      impersonatedBrand = key.toUpperCase();
      officialDomains = info.domains;
      points += 52;
      signals.push({
        signal: "employer_brand_impersonation",
        severity: "critical",
        explanation: `References '${key.toUpperCase()}' in the URL, but actual domain is '${regDomain}' instead of official (${info.domains.join(", ")}).`,
      });
      break;
    }
  }

  if (parsed.search && /(redirect|url=|next=|token=|otp=|session=)/i.test(parsed.search)) {
    points += 18;
    signals.push({ signal: "suspicious_redirect_parameters", severity: "medium", explanation: "Contains redirect/session query parameters." });
  }

  const riskIndex = Math.min(98, Math.max(5, points));
  const riskLevel = riskIndex >= 60 || impersonatedBrand ? "HIGH RISK" : riskIndex >= 25 ? "MEDIUM RISK" : "LOW RISK";
  return {
    submitted_url: submitted, normalized_url: parsed.href, hostname: host, registrable_domain: regDomain,
    subdomains, scheme, is_https: isHttps, is_ip_address: isIp, is_shortened: isShortened,
    has_punycode_or_idn: hasIdn, subdomain_count: subdomains.length, impersonated_brand: impersonatedBrand,
    official_domains: officialDomains, risk_level: riskLevel, risk_index: riskIndex,
    summary: riskLevel === "HIGH RISK" ? `High-risk structural signals on '${regDomain}'. Do not open this link.` : riskLevel === "MEDIUM RISK" ? `Structural warning signs on '${regDomain}'. Verify independently.` : `No strong structural phishing signals on '${regDomain}'.`,
    signals, reputation_status: "Check Unavailable", reputation_provider: "none (local zero-visit structural inspection)",
    recommended_actions: riskLevel === "HIGH RISK" ? [`Do not open '${regDomain}'.`, "Navigate manually to the employer's official website."] : ["Verify the domain matches the official employer website."],
    limitations: ["Zero-visit structural inspection; URL was never opened."],
  };
}

export function extractStructuredJobData(text, jobUrl = "") {
  const combined = (text || "").trim();
  const s = jobUrl && !combined.includes(jobUrl) ? `${combined}\nJob URL: ${jobUrl}`.trim() : combined;
  const miss = (f) => ({ field_name: f, value: null, status: "missing", confidence: 0, supporting_snippet: null });
  const ok = (f, v, c, sn) => ({ field_name: f, value: String(v).trim(), status: "extracted", confidence: c, supporting_snippet: sn });

  const emp =
    s.match(/(?:company|employer|organization|organisation|कंपनी)\s*[:\-]\s*([^\n,;.|]+)/i) ||
    s.match(/\b(Infosys|TCS|Tata Consultancy Services|Wipro|HCLTech|Accenture|Cognizant|Capgemini|Tech Mahindra|LTIMindtree|Deloitte|PwC|KPMG|IBM|Oracle|Google|Microsoft|Amazon|Meta|Apple|Netflix|Flipkart|Zoho|Razorpay|Swiggy|Zomato|Paytm|PhonePe|Meesho|Freshworks|Reliance Jio|HDFC Bank|ICICI Bank|Postman)\b/i);
  const role =
    s.match(/(?:job\s+title|role|position|designation|पद)\s*[:\-]\s*([^\n;.|]+)/i) ||
    s.match(/\b((?:Senior|Junior|Associate|Staff|Lead|Frontend|Backend|Full[\s-]Stack|Software|Python|Java|React|Data|Product|Cloud|DevOps|QA|Firmware|Web|Marketing|HR|Business\s+Development|Customer\s+Support|Online\s+Data\s+Entry|Part[\s-]Time\s+Online)\s+(?:Engineer|Developer|Intern|Analyst|Scientist|Designer|Manager|Executive|Associate|Specialist|Trainee|Operator|Job|Role))\b/i);
  const sal =
    s.match(/(?:salary|ctc|package|stipend|स्टाइपेंड|earn|payout)\s*[:\-]?\s*((?:₹|Rs\.?|INR|\$|USD)\s*\d[\d,]*(?:\.\d+)?(?:\s*(?:-|to|–)\s*(?:₹|Rs\.?|INR|\$|USD)?\s*\d[\d,]*(?:\.\d+)?)?\s*(?:LPA|lakhs?|k|per\s+month|\/month|pm|per\s+day|daily|\/day|per\s+week|\/week)?|\d+(?:\.\d+)?(?:\s*(?:-|to|–)\s*\d+(?:\.\d+)?)?\s*LPA)/i) ||
    s.match(/\b(\d{1,2}(?:\.\d+)?(?:\s*(?:-|to|–)\s*\d{1,2}(?:\.\d+)?)?\s*LPA)\b/i);
  const email = s.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/);
  const phone = s.match(/(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/);
  const loc =
    s.match(/(?:location|work\s+location|city)\s*[:\-]\s*([^\n;.|]+)/i) ||
    s.match(/\b(Bengaluru|Bangalore|Hyderabad|Pune|Mumbai|Noida|Gurugram|Gurgaon|New Delhi|Delhi NCR|Chennai|Kolkata|Lucknow|Jaipur|Ahmedabad|Remote|Work\s+From\s+Home)\b/i);
  const req = s.match(/(?:requisition\s*(?:id|no\.?|#)|req\s*(?:id|no\.?|#)|job\s*(?:id|code|ref))\s*[:\-#]?\s*([A-Z0-9][A-Z0-9\-_/]{2,24})/i);
  const urls = extractUrlsFromText(s);
  const primaryUrl = jobUrl && jobUrl.trim() ? jobUrl.trim() : urls[0] || null;
  const dead = s.match(/(?:deadline|apply\s+(?:by|before)|within|before)\s*[:\-]?\s*(\d+\s*(?:minutes?|mins?|hours?|hrs?|days?)|[0-9:]+\s*(?:am|pm)\s*today)/i);

  let pay = miss("payment_requests");
  const pm = s.match(/((?:pay|deposit|transfer|send|jama\s+karo|दें)[^.\n]{0,65}?(?:registration\s+fee|security\s+deposit|processing\s+fee|agreement\s+charge|training\s+fee|prepaid\s+task|recharge|upi|gpay|phonepe|₹\s*\d[\d,]*)|सिक्योरिटी\s+डिपॉजिट|रजिस्ट्रेशन\s+फीस)/i);
  if (pm) {
    const pref = s.slice(Math.max(0, pm.index - 55), pm.index);
    if (!NEGATION_PREFIX_RE.test(pref)) pay = ok("payment_requests", pm[0], 0.92, pm[0]);
  }

  return {
    employer: emp ? ok("employer", emp[1] || emp[0], 0.88, emp[0]) : miss("employer"),
    role: role ? ok("role", role[1] || role[0], 0.86, role[0]) : miss("role"),
    salary: sal ? ok("salary", sal[1] || sal[0], 0.85, sal[0]) : miss("salary"),
    recruiter_email: email ? ok("recruiter_email", email[0], 0.95, email[0]) : miss("recruiter_email"),
    phone: phone ? ok("phone", phone[0], 0.9, phone[0]) : miss("phone"),
    location: loc ? ok("location", loc[1] || loc[0], 0.82, loc[0]) : miss("location"),
    job_url: primaryUrl ? ok("job_url", primaryUrl, 0.96, primaryUrl) : miss("job_url"),
    requisition_id: req ? ok("requisition_id", req[1], 0.9, req[0]) : miss("requisition_id"),
    payment_requests: pay,
    deadlines: dead ? ok("deadlines", dead[1] || dead[0], 0.8, dead[0]) : miss("deadlines"),
    detected_language: detectLanguage(combined || jobUrl),
  };
}

export function runLocalVerification({
  text = "",
  secondary_text = "",
  job_url = "",
  edited_fields = {},
  is_demo = false,
  interface_language = "en",
  redact_sensitive = true,
} = {}) {
  const ts = new Date().toISOString();
  const ext = extractStructuredJobData(text, job_url);
  for (const [k, v] of Object.entries(edited_fields || {})) {
    if (ext[k]) {
      ext[k] = v && String(v).trim()
        ? { field_name: k, value: String(v).trim(), status: "extracted", confidence: 1, supporting_snippet: "User reviewed" }
        : { field_name: k, value: null, status: "missing", confidence: 0, supporting_snippet: null };
    }
  }

  const { redacted, counts } = redact_sensitive ? redactSensitiveInfo(text) : { redacted: text, counts: {} };
  const hasDisc = SAFETY_DISCLAIMER_RE.test(text);
  const inds = [];
  const seenRuleIds = new Set();

  for (const rule of FRAUD_RULES) {
    const m = text.match(rule.rx);
    if (!m) continue;
    if (rule.respectNegation) {
      const pref = text.slice(Math.max(0, m.index - 65), m.index);
      if (NEGATION_PREFIX_RE.test(pref)) continue;
    }
    if (seenRuleIds.has(rule.id)) continue;
    seenRuleIds.add(rule.id);
    inds.push({
      id: `${rule.id}_${inds.length + 1}`,
      category: rule.category,
      matched_text: m[0].trim(),
      severity: rule.severity,
      weight: rule.weight,
      explanation: rule.explanation,
      explanation_hi: rule.explanation_hi,
      detection_method: "deterministic_rule_engine",
      reason_it_matters: rule.reason,
      suggested_action: rule.action,
    });
  }

  // Layer B: Salary & Qualification mismatch
  if (ext.salary.status === "extracted" && ext.salary.value) {
    const lowQual = /\b(10th\s+pass|12th\s+pass|no\s+experience\s+(?:required|needed)|no\s+skills?\s+required|anyone\s+can\s+apply|only\s+smartphone\s+needed)\b/i.test(text);
    const highPay = /(?:₹|rs\.?|inr)\s*(?:[4-9]\d,?\d{3}|[1-9]\d{2},?\d{3})\s*(?:per\s+month|\/month|pm|monthly)?|(?:[1-9]\d)\s*lpa|(?:[4-9]\d|1\d\d)k\s*(?:\/month|per\s+month|pm)?/i.test(ext.salary.value);
    if (lowQual && highPay) {
      inds.push({
        id: `salary_qual_${inds.length + 1}`,
        category: "Salary & Qualification Mismatch",
        matched_text: ext.salary.value,
        severity: "high",
        weight: 28,
        explanation: "Advertises unusually high compensation alongside minimal or zero qualification requirements.",
        explanation_hi: "न्यूनतम योग्यता के साथ असामान्य रूप से बहुत अधिक वेतन का दावा किया गया है।",
        detection_method: "job_ad_structural_analysis",
        reason_it_matters: "Disproportionate compensation for no-skill roles is a common bait used to attract applicants into fee scams.",
        suggested_action: "Compare the role's compensation with verified listings for similar entry-level roles.",
      });
    }
  }

  // Layer F: Zero-visit URL inspection
  const urls = extractUrlsFromText(text);
  if (ext.job_url.value && !urls.includes(ext.job_url.value)) urls.unshift(ext.job_url.value);
  const uRes = urls.map(inspectUrlStructurally);
  uRes.forEach((u) => {
    if (u.risk_level !== "LOW RISK") {
      inds.push({
        id: `url_${inds.length + 1}`,
        category: u.impersonated_brand ? "Fake Career Portal / Suspicious URL" : "Suspicious Recruitment Link",
        matched_text: u.submitted_url,
        severity: u.impersonated_brand ? "critical" : (u.risk_level === "HIGH RISK" ? "high" : "medium"),
        weight: u.impersonated_brand ? 52 : (u.risk_level === "HIGH RISK" ? 32 : 18),
        explanation: u.signals.slice(0, 2).map((s) => s.explanation).join("; ") || u.summary,
        explanation_hi: `संदिग्ध लिंक '${u.registrable_domain}': बिना आधिकारिक पुष्टि के इस लिंक को न खोलें।`,
        detection_method: "zero_visit_url_inspector",
        reason_it_matters: "Lookalike career portals impersonate real employers to steal resumes or fees.",
        suggested_action: u.recommended_actions[0] || "Do not open this link.",
      });
    }
  });

  // Layer C & E: Employer Registry + Email Alignment
  const empVal = ext.employer.value;
  let regEntry = null;
  if (empVal) {
    const lowerEmp = empVal.toLowerCase();
    for (const [k, info] of Object.entries(PROTECTED_EMPLOYERS)) {
      if (lowerEmp.includes(k)) { regEntry = info; break; }
    }
  }
  const email = ext.recruiter_email.value;
  const eDom = email ? email.split("@").pop().toLowerCase() : null;
  let emailStatus = "Unverified";
  let emailExp = "No recruiter email supplied.";
  let isPersonalEmail = false;
  let domainMismatch = false;
  if (eDom) {
    isPersonalEmail = PERSONAL_EMAIL_PROVIDERS.has(eDom);
    if (regEntry && regEntry.domains.includes(eDom)) {
      emailStatus = "Confirmed by Source";
      emailExp = `Email '@${eDom}' matches ${regEntry.canonical}'s official domain.`;
    } else if (regEntry && isPersonalEmail) {
      emailStatus = "Suspicious Signal";
      domainMismatch = true;
      emailExp = `Personal email '@${eDom}' used for corporate employer '${regEntry.canonical}'.`;
      inds.push({
        id: `em_${inds.length + 1}`,
        category: "Personal Email Claiming Major Corporate Employer",
        matched_text: email,
        severity: "medium",
        weight: 18,
        explanation: emailExp,
        explanation_hi: "बड़ी कंपनी के नाम पर व्यक्तिगत जीमेल/याहू ईमेल का उपयोग किया गया है।",
        detection_method: "email_domain_alignment",
        reason_it_matters: "Major companies rarely send official offers from Gmail/Yahoo.",
        suggested_action: "Request official corporate email confirmation.",
      });
    } else if (regEntry) {
      emailStatus = "Inconsistent";
      domainMismatch = true;
      emailExp = `Email domain '@${eDom}' does not match ${regEntry.canonical} (${regEntry.domains.join(", ")}).`;
      inds.push({
        id: `em_lookalike_${inds.length + 1}`,
        category: "Lookalike Recruiter Email Domain",
        matched_text: email,
        severity: "high",
        weight: 30,
        explanation: emailExp,
        explanation_hi: "रिक्रूटर का ईमेल डोमेन कंपनी के आधिकारिक डोमेन से मेल नहीं खाता।",
        detection_method: "email_domain_alignment",
        reason_it_matters: "Scammers register lookalike domains to impersonate corporate HR.",
        suggested_action: "Verify the recruiter email against the official company domain.",
      });
    } else if (isPersonalEmail) {
      emailExp = `Recruiter uses a free personal email ('@${eDom}'); corporate affiliation cannot be verified.`;
    } else {
      emailExp = `Custom domain '@${eDom}' is not in the local reference registry.`;
    }
  }

  // Layer H: Cross-document consistency
  const conflicts = [];
  if (secondary_text && secondary_text.trim()) {
    const s2 = extractStructuredJobData(secondary_text, "");
    ["employer", "role", "salary", "location", "recruiter_email"].forEach((f) => {
      if (ext[f].value && s2[f].value && ext[f].value.toLowerCase() !== s2[f].value.toLowerCase()) {
        conflicts.push(`${f}: '${ext[f].value}' vs '${s2[f].value}'`);
      }
    });
    conflicts.forEach((c) => {
      inds.push({
        id: `conflict_${inds.length + 1}`,
        category: "Document & Communication Inconsistency",
        matched_text: c,
        severity: "high",
        weight: 28,
        explanation: `Conflict across submitted materials (${c}).`,
        explanation_hi: "दस्तावेजों या संदेशों में जानकारी में विरोधाभास पाया गया है।",
        detection_method: "cross_document_consistency",
        reason_it_matters: "Conflicting employer, role, or salary details indicate a fabricated template.",
        suggested_action: "Clarify discrepancies directly via official corporate HR.",
      });
    });
  }

  // 7-category evidence report
  const paymentCats = new Set([
    "Advance Fee / Registration Scam", "Security / Equipment Deposit Scam",
    "Direct UPI / QR / Payment Transfer Request", "Paid Training / Fake Internship Scam",
    "Prepaid Task & Recharge Scam", "Crypto / Investment / Deposit-Return Job Scam",
    "OTP / UPI PIN / Credential Theft", "Upfront KYC / Identity & Bank Document Harvest",
    "Remote-Access Software Scam",
  ]);
  const hasPaySignal = inds.some((i) => paymentCats.has(i.category));
  const hasMessagingSignal = inds.some((i) => i.category === "WhatsApp / Telegram-Only Recruitment Funnel");
  const hasOfficialUrl = uRes.some((u) => regEntry && regEntry.domains.includes(u.registrable_domain));

  const categories = [
    {
      category_number: 1, category_id: "employer_identity", category_name: "Employer Identity",
      overall_status: regEntry ? "Confirmed by Source" : "Unverified",
      summary: regEntry ? `Matched ${regEntry.canonical} (${regEntry.portal}).` : (empVal ? `Employer '${empVal}' is not in local registry (Unverified, not automatically fraudulent).` : "No employer identified."),
      records: [{ check_name: "Curated Employer Reference Registry", source_examined: "Local Registry (35+ Employers)", source_type: "curated_registry", observed_result: regEntry ? `Official domains: ${regEntry.domains.join(", ")}` : "Not in local registry", supporting_quotation: ext.employer.supporting_snippet, status: regEntry ? "Confirmed by Source" : "Unverified", timestamp: ts, explanation: "Unknown companies are never automatically marked fraudulent.", residual_uncertainty: "Confirm live corporate registration independently." }],
    },
    {
      category_number: 2, category_id: "vacancy_verification", category_name: "Vacancy and Requisition Verification",
      overall_status: "Check Unavailable",
      summary: "Live Greenhouse/Lever ATS check requires optional external provider.",
      records: [{ check_name: "Public ATS Check (Greenhouse / Lever)", source_examined: "Allowlisted ATS APIs", source_type: "external_verification", observed_result: "External ATS provider disabled in local mode.", supporting_quotation: ext.requisition_id.supporting_snippet, status: "Check Unavailable", timestamp: ts, explanation: "Unavailable providers are honestly reported as Check Unavailable.", residual_uncertainty: "Search this role directly on the company's official career portal." }],
    },
    {
      category_number: 3, category_id: "recruiter_contact", category_name: "Recruiter Contact Verification",
      overall_status: hasMessagingSignal ? "Suspicious Signal" : "Unverified",
      summary: hasMessagingSignal ? "Recruiter routes candidates through WhatsApp or Telegram." : (ext.phone.value ? `Contact number: ${ext.phone.value}` : "No phone or messaging funnel detected."),
      records: [{ check_name: "Recruiter Contact Channel", source_examined: "User text", source_type: "local_heuristic", observed_result: hasMessagingSignal ? "Uses WhatsApp/Telegram recruitment funnel." : "No messaging-only funnel detected.", supporting_quotation: ext.phone.supporting_snippet, status: hasMessagingSignal ? "Suspicious Signal" : "Unverified", timestamp: ts, explanation: "Verify recruiter identity via official corporate channels.", residual_uncertainty: "Phone numbers cannot be verified locally." }],
    },
    {
      category_number: 4, category_id: "email_domain_alignment", category_name: "Email and Domain Alignment",
      overall_status: emailStatus, summary: emailExp,
      records: [{ check_name: "Recruiter Email vs. Employer Domain", source_examined: email || "None", source_type: "local_heuristic", observed_result: emailExp, supporting_quotation: ext.recruiter_email.supporting_snippet, status: emailStatus, timestamp: ts, explanation: emailExp, residual_uncertainty: "Pasted text cannot verify SPF/DKIM email headers." }],
    },
    {
      category_number: 5, category_id: "link_domain_safety", category_name: "Link and Domain Safety",
      overall_status: uRes.some((u) => u.risk_level !== "LOW RISK") ? "Suspicious Signal" : (hasOfficialUrl ? "Confirmed by Source" : "Unverified"),
      summary: uRes[0] ? uRes[0].summary : "No URLs found.",
      records: [{ check_name: "Zero-Visit Structural URL Inspection", source_examined: uRes[0] ? uRes[0].submitted_url : "None", source_type: "local_heuristic", observed_result: uRes[0] ? uRes[0].summary : "No URLs present.", supporting_quotation: uRes[0] ? uRes[0].submitted_url : null, status: uRes.some((u) => u.risk_level !== "LOW RISK") ? "Suspicious Signal" : (hasOfficialUrl ? "Confirmed by Source" : "Unverified"), timestamp: ts, explanation: "URLs are never automatically opened.", residual_uncertainty: "External reputation blocklists require API configuration." }],
    },
    {
      category_number: 6, category_id: "payment_sensitive_info", category_name: "Payment and Sensitive Information Requests",
      overall_status: hasPaySignal ? "Suspicious Signal" : (hasDisc ? "Confirmed by Source" : "Unverified"),
      summary: hasPaySignal ? "Upfront payment, deposit, UPI, KYC, or sensitive credential demand detected." : (hasDisc ? "Protective anti-fraud disclaimer detected." : "No upfront payment or OTP/PIN request detected."),
      records: [{ check_name: "Payment, UPI, KYC & Sensitive Info Rules", source_examined: "User text", source_type: "local_heuristic", observed_result: hasPaySignal ? "Payment/credential red flag detected." : (hasDisc ? "Anti-fraud disclaimer recognized (not a scam trigger)." : "Checked for fees, deposits, UPI, KYC, OTP/PIN, and AnyDesk."), supporting_quotation: ext.payment_requests.supporting_snippet, status: hasPaySignal ? "Suspicious Signal" : (hasDisc ? "Confirmed by Source" : "Unverified"), timestamp: ts, explanation: "Legitimate hiring never demands upfront fees, UPI transfers, or OTP/UPI PINs.", residual_uncertainty: "Stay alert in follow-up messages." }],
    },
    {
      category_number: 7, category_id: "document_consistency", category_name: "Document and Message Consistency",
      overall_status: conflicts.length ? "Inconsistent" : (secondary_text ? "Confirmed by Source" : "Unverified"),
      summary: conflicts.length ? `Contradictions: ${conflicts.join("; ")}` : (secondary_text ? "No contradictions detected across submitted texts." : "Single document submitted."),
      records: [{ check_name: "Cross-Document Consistency", source_examined: secondary_text ? "Primary + Secondary" : "Primary Only", source_type: "local_heuristic", observed_result: conflicts.length ? conflicts.join("; ") : "No conflicts detected.", supporting_quotation: null, status: conflicts.length ? "Inconsistent" : (secondary_text ? "Confirmed by Source" : "Unverified"), timestamp: ts, explanation: "Compares employer, role, salary, and location across materials.", residual_uncertainty: "Review full offer terms carefully." }],
    },
  ];

  // =========================================================================
  // CALIBRATED MULTI-LAYER RISK SCORING v2.0 (Eliminates the hardcoded 26 trap)
  // =========================================================================
  const crit = inds.filter((i) => i.severity === "critical").length;
  const hi = inds.filter((i) => i.severity === "high").length;
  const med = inds.filter((i) => i.severity === "medium").length;
  const maxUrlRisk = uRes.reduce((mx, u) => Math.max(mx, u.risk_index || 0), 0);

  const indicatorPoints = inds.reduce((sum, i) => sum + (i.weight || (i.severity === "critical" ? 50 : i.severity === "high" ? 30 : i.severity === "medium" ? 16 : 10)), 0);
  const distinctCats = new Set(inds.map((i) => i.category)).size;
  const synergyBonus = distinctCats >= 4 ? 18 : distinctCats === 3 ? 12 : distinctCats === 2 ? 6 : 0;

  let combinedSignalPts = indicatorPoints + synergyBonus;
  if (combinedSignalPts > 70) {
    combinedSignalPts = 70 + Math.round((combinedSignalPts - 70) * 0.42);
  }

  let rawScore = 12 + combinedSignalPts;
  if (maxUrlRisk >= 60 && crit === 0) rawScore = Math.max(rawScore, maxUrlRisk);

  // Statistical text classifier contribution
  const mlRes = runLocalTextClassifier(text);
  let mlDelta = 0;
  if (mlRes.scam_probability_estimate >= 0.72) {
    mlDelta = Math.round((mlRes.scam_probability_estimate - 0.5) * 32);
  } else if (mlRes.scam_probability_estimate >= 0.58) {
    mlDelta = Math.round((mlRes.scam_probability_estimate - 0.5) * 20);
  } else if (mlRes.scam_probability_estimate <= 0.32 && crit === 0 && hi === 0 && maxUrlRisk < 40) {
    mlDelta = -Math.round((0.45 - mlRes.scam_probability_estimate) * 22);
  }
  rawScore += mlDelta;

  // Positive legitimacy trust signals (only when no critical/high fraud exists)
  let trustDeduction = 0;
  if (crit === 0 && hi === 0 && maxUrlRisk < 40 && conflicts.length === 0) {
    if (emailStatus === "Confirmed by Source") trustDeduction += 10;
    else if (eDom && !isPersonalEmail && !domainMismatch) trustDeduction += 5;
    if (hasOfficialUrl) trustDeduction += 8;
    if (hasDisc) trustDeduction += 10;
    let textTrust = 0;
    for (const sig of LEGITIMACY_SIGNALS) {
      if (sig.rx.test(text)) textTrust += sig.bonus;
    }
    trustDeduction += Math.min(16, textTrust);
    trustDeduction = Math.min(28, trustDeduction);
    rawScore -= trustDeduction;
    if (hasDisc && med === 0) rawScore = Math.min(rawScore, 12);
  }

  // Proportional missing-info uncertainty (replaces old hardcoded sc = 26)
  const missCore = ["employer", "role", "recruiter_email", "job_url"].filter((k) => ext[k].status === "missing").length;
  let uncertaintyBump = 0;
  if (crit === 0 && hi === 0 && med === 0 && trustDeduction < 8 && missCore >= 2) {
    uncertaintyBump = Math.min(9, (missCore - 1) * 3);
    rawScore += uncertaintyBump;
  }

  // Critical / multi-high floors
  if (crit >= 1) {
    rawScore = Math.max(rawScore, 70 + Math.min(20, (crit - 1) * 10 + hi * 6 + med * 4));
  } else if (hi >= 2) {
    rawScore = Math.max(rawScore, 62);
  }

  const riskIndex = Math.max(4, Math.min(98, Math.round(rawScore)));
  const riskLevel = riskIndex >= 60 || crit >= 1 || hi >= 2
    ? "HIGH RISK"
    : (riskIndex >= 28 || hi >= 1 || med >= 1 || conflicts.length ? "MEDIUM RISK" : "LOW RISK");

  const allRecs = categories.flatMap((c) => c.records);
  const confirmed = allRecs.filter((r) => r.status === "Confirmed by Source").length;
  const unverified = allRecs.filter((r) => r.status === "Unverified").length;
  const unavailable = allRecs.filter((r) => r.status === "Check Unavailable").length;
  const inconsistent = allRecs.filter((r) => r.status === "Inconsistent").length;
  const suspicious = allRecs.filter((r) => r.status === "Suspicious Signal").length;

  return {
    report_id: "jg-" + Date.now().toString(36),
    timestamp: ts,
    is_demo: Boolean(is_demo),
    detected_language: ext.detected_language,
    interface_language,
    risk_index: riskIndex,
    risk_level: riskLevel,
    risk_headline: riskLevel === "HIGH RISK"
      ? "Multiple serious fraud indicators or contradictory evidence found."
      : riskLevel === "MEDIUM RISK"
      ? "Concerning signals or important unverified details require caution."
      : "No strong fraud signals detected — still verify unconfirmed details.",
    risk_index_disclaimer: "Heuristic Risk Index (0–100) reflects explainable evidence signals—not a calibrated probability of fraud. Absence of indicators is not proof of legitimacy.",
    score_breakdown: {
      base: 12,
      red_flags: indicatorPoints,
      synergy: synergyBonus,
      text_classifier: mlDelta,
      legitimacy_offset: -trustDeduction,
      uncertainty: uncertaintyBump,
    },
    evidence_coverage_percent: Math.round(((confirmed + inconsistent + suspicious) / allRecs.length) * 100),
    verification_confidence: confirmed >= 2 ? "Moderate (Multiple Local Checks Confirmed)" : "Partial (Local Verification Engine)",
    suspicious_indicator_count: inds.length,
    confirmed_check_count: confirmed,
    unverified_check_count: unverified,
    unavailable_check_count: unavailable,
    inconsistent_check_count: inconsistent,
    extracted_data: ext,
    indicators: inds,
    url_inspections: uRes,
    categories,
    recommended_actions: riskLevel === "HIGH RISK"
      ? ["Do not pay any registration fee, security deposit, UPI transfer, or task recharge.", "Do not open unverified career links or install AnyDesk/TeamViewer.", "In India, call 1930 immediately if money was transferred and report on cybercrime.gov.in."]
      : ["Verify the opening on the employer's official career portal.", "Never share OTPs, UPI PINs, Aadhaar/PAN photos, or upfront fees at any stage."],
    recommended_actions_hi: ["किसी भी रजिस्ट्रेशन फीस, यूपीआई भुगतान या सिक्योरिटी डिपॉजिट का भुगतान न करें।", "वित्तीय धोखाधड़ी होने पर 1930 पर कॉल करें या cybercrime.gov.in पर रिपोर्ट करें।"],
    what_was_verified: categories.filter((c) => c.overall_status === "Confirmed by Source").map((c) => `${c.category_name}: ${c.summary}`),
    what_could_not_be_verified: categories.filter((c) => ["Unverified", "Check Unavailable"].includes(c.overall_status)).map((c) => `${c.category_name}: ${c.summary}`),
    ml_assessment: mlRes,
    ai_explanation: {
      provider: "local_evidence_explainer",
      used_external_llm: false,
      summary: `${riskLevel} (${riskIndex}/100): ${inds.length} indicator(s) detected across 7 categories.`,
      plain_language_advice: ["Verify employer & vacancy independently."],
      uncertainty_note: "External providers are disabled locally.",
    },
    redacted_input_preview: redacted.slice(0, 1500),
    redaction_counts: counts,
  };
}

export function exportReportToMarkdown(report) {
  const lines = [
    "# JobGuard AI — Evidence-Based Verification Report",
    "",
    `- **Report ID:** ${report.report_id}`,
    `- **Risk Level:** ${report.risk_level} (${report.risk_index}/100 heuristic index)`,
    `- **Evidence Coverage:** ${report.evidence_coverage_percent}%`,
    `- **Detected Language:** ${report.detected_language}`,
    "",
    "## Seven-Category Evidence Breakdown",
    "",
  ];
  for (const cat of report.categories || []) {
    lines.push(`### ${cat.category_number}. ${cat.category_name} — ${cat.overall_status}`);
    lines.push(cat.summary || "");
    lines.push("");
  }
  return lines.join("\n");
}
