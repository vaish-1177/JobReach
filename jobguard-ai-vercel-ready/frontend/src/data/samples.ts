export interface DemoScenario {
  id: string;
  label: string;
  categoryHint: string;
  lang: "en" | "hi" | "hinglish";
  isDemo: true;
  text: string;
  secondaryText?: string;
  jobUrl?: string;
}

export const DEMO_SCENARIOS: DemoScenario[] = [
  {
    id: "demo-reg-fee",
    label: "Demo 1: Fake Company Asking for Registration Fee (English)",
    categoryHint: "Advance Registration Fee Scam",
    lang: "en",
    isDemo: true,
    text: "Company: Apex Global Solutions Pvt Ltd\nRole: Junior Operations Executive\nSalary: ₹42,000 per month\nLocation: Noida\nCongratulations! You are selected without interview. Pay ₹999 registration fee to confirm your job before 6:00 PM today. Contact HR at hr.apexglobal99@gmail.com or WhatsApp +91 98112 34567.",
  },
  {
    id: "demo-wfh-unrealistic",
    label: "Demo 2: Unrealistic Work-From-Home Earnings (Hinglish)",
    categoryHint: "Work-From-Home Scam",
    lang: "hinglish",
    isDemo: true,
    text: "Part-time Work From Home Opportunity! Ghar baithe roz ₹5,000 kamayein — 10th pass, no experience required, only smartphone needed. Job ke liye pehle ₹1500 registration fees jama karo aur turant joining pao. Message us on WhatsApp +91 90123 45678.",
  },
  {
    id: "demo-telegram-task",
    label: "Demo 3: Telegram Prepaid Task Scam",
    categoryHint: "Telegram Prepaid Task Scam",
    lang: "en",
    isDemo: true,
    text: "VIP Telegram Task Group! Earn ₹5,000 to ₹10,000 daily by liking YouTube videos and rating Google Maps hotels. Complete 3 prepaid merchant tasks and recharge wallet to unlock your frozen salary payout. Join https://t.me/vip_daily_tasks_hr now.",
  },
  {
    id: "demo-fake-internship",
    label: "Demo 4: Fake Internship with Security Deposit (Hindi)",
    categoryHint: "Internship Security Deposit Scam",
    lang: "hi",
    isDemo: true,
    text: "कंपनी: BrightFuture Tech Solutions\nपद: Web Development Intern\nस्टाइपेंड: ₹25,000 per month\nबिना इंटरव्यू के नौकरी पाने के लिए ₹2,000 सिक्योरिटी डिपॉजिट दें और लैपटॉप किट प्राप्त करें। संपर्क: +91 88001 22334",
  },
  {
    id: "demo-gmail-suspicious-site",
    label: "Demo 5: Fake Recruiter Using Gmail & Suspicious Career Website",
    categoryHint: "Fake Recruiter & Phishing Portal",
    lang: "en",
    isDemo: true,
    text: "Company: Tata Consultancy Services (TCS)\nRole: Associate Software Engineer\nSalary: 7.5 LPA\nLocation: Hyderabad\nDear Candidate, please upload your Aadhaar, PAN, and complete verification at https://tcs-hr-onboarding-verify.top/apply within 2 hours. Reply to tcs.hiring.desk2026@gmail.com.",
    jobUrl: "https://tcs-hr-onboarding-verify.top/apply",
  },
  {
    id: "demo-contradictory-offer",
    label: "Demo 6: Offer Letter with Contradictory Company Information",
    categoryHint: "Document Consistency Conflict",
    lang: "en",
    isDemo: true,
    text: "Company: Infosys Limited\nRole: Systems Engineer\nSalary: 4.5 LPA\nLocation: Bengaluru\nRecruiter Email: hr@infosys-careers-desk.xyz\nRequisition ID: INF-2026-881",
    secondaryText: "Offer Letter from: GlobalTech Staffing Services\nPosition: Data Entry Operator\nSalary: ₹18,000 per month\nLocation: Gurugram\nContact: hiring@globaltechstaff.online",
  },
  {
    id: "demo-impersonation-link",
    label: "Demo 7: Suspicious Link Impersonating Known Company",
    categoryHint: "Employer Impersonation URL",
    lang: "en",
    isDemo: true,
    text: "Company: Infosys\nRole: Graduate Engineer Trainee\nApply immediately on our official portal: https://infosys.careers-verification.xyz/apply?redirect=http://verify-hr.top\nOffer will be cancelled within 3 hours if verification is incomplete.",
    jobUrl: "https://infosys.careers-verification.xyz/apply?redirect=http://verify-hr.top",
  },
  {
    id: "demo-genuine-no-fee",
    label: "Demo 8: Genuine Job Advertisement (No Upfront Fee)",
    categoryHint: "Legitimate Job Posting",
    lang: "en",
    isDemo: true,
    text: "Company: Razorpay\nRole: Backend Software Engineer\nSalary: 16-22 LPA\nLocation: Bengaluru\nEmployment Type: Full-time (Hybrid)\nRequisition ID: RZP-ENG-4092\nApply via https://razorpay.com/jobs/ or contact recruiting@razorpay.com. Selection involves an online technical round followed by two engineering interviews.",
    jobUrl: "https://razorpay.com/jobs/",
  },
  {
    id: "demo-genuine-disclaimer",
    label: "Demo 9: Genuine Recruitment Email with Anti-Fraud Disclaimer",
    categoryHint: "Legitimate + Anti-Fraud Notice",
    lang: "en",
    isDemo: true,
    text: "Company: Infosys Limited\nRole: Specialist Programmer\nSalary: 9.5 LPA\nLocation: Pune\nUrgent reminder: please confirm your interview slot for Thursday at 11:00 AM via careers@infosys.com or https://www.infosys.com/careers/.\nImportant Notice: Infosys does not charge any fee at any stage of the recruitment process. Never pay any registration fee or security deposit during recruitment.",
    jobUrl: "https://www.infosys.com/careers/",
  },
  {
    id: "demo-incomplete-ad",
    label: "Demo 10: Incomplete Job Advertisement Requiring Verification",
    categoryHint: "Unverified / Incomplete Listing",
    lang: "en",
    isDemo: true,
    text: "Hiring immediately for office assistant and back-office support roles. Good salary package. Freshers welcome. Call +91 98765 11223 for interview timing.",
  },
];
