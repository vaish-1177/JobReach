export interface QuizQuestion {
  id: string;
  sender: string;
  message: string;
  correctChoice: "scam" | "legitimate";
  explanation: string;
}

export const QUIZ_SETS: Record<string, { title: string; questions: QuizQuestion[] }> = {
  set1: {
    title: "Set 1: Advance Fees, Disclaimers & Career URLs",
    questions: [
      {
        id: "jg-q1",
        sender: "WhatsApp HR (+91 98112 44019)",
        message: "Congratulations! Selected for Data Entry WFH at ₹45,000/month without interview. Pay ₹999 refundable registration fee today to confirm your seat.",
        correctChoice: "scam",
        explanation: "Fraudulent: Combines guaranteed selection without interview, unrealistic WFH pay, and an upfront 'refundable' registration fee.",
      },
      {
        id: "jg-q2",
        sender: "careers@infosys.com",
        message: "Urgent reminder: your technical interview for Specialist Programmer is scheduled for tomorrow at 11 AM. Important: Infosys never charges any registration fee during recruitment.",
        correctChoice: "legitimate",
        explanation: "Legitimate: Comes from the official corporate domain, schedules a real interview, and includes a standard anti-fraud disclaimer (not a fee demand).",
      },
      {
        id: "jg-q3",
        sender: "SMS Recruitment Alert",
        message: "Apply for TCS Campus Drive 2026 now at https://tcs.careers-verification.xyz/apply within 2 hours.",
        correctChoice: "scam",
        explanation: "Fraudulent: Lookalike URL impersonating TCS — the true registrable domain is 'careers-verification.xyz', not 'tcs.com'.",
      },
      {
        id: "jg-q4",
        sender: "recruiting@razorpay.com",
        message: "Thank you for applying for Backend Engineer (Req ID: RZP-4092). Please review the interview prep guide at https://razorpay.com/jobs/.",
        correctChoice: "legitimate",
        explanation: "Legitimate: Official corporate email and official domain alignment, specific requisition ID, and no fee or sensitive-data demands.",
      },
      {
        id: "jg-q5",
        sender: "Telegram @VIP_HR_Tasks",
        message: "Earn ₹6,000 daily liking YouTube videos! Recharge ₹3,000 for VIP prepaid task #4 to unlock your ₹14,000 wallet balance.",
        correctChoice: "scam",
        explanation: "Fraudulent: Classic Telegram prepaid task & recharge scam.",
      },
    ],
  },
  set2: {
    title: "Set 2: Hindi/Hinglish, Internships & Remote Access",
    questions: [
      {
        id: "jg-q6",
        sender: "WhatsApp Recruiter",
        message: "Job ke liye pehle ₹1500 registration fees jama karo, bina interview ke direct joining letter mil jayega.",
        correctChoice: "scam",
        explanation: "Fraudulent: Hinglish advance registration fee demand paired with direct joining without interview.",
      },
      {
        id: "jg-q7",
        sender: "HR Onboarding Caller",
        message: "To activate your salary account and WFH laptop portal, install AnyDesk and share the 9-digit code plus your UPI PIN.",
        correctChoice: "scam",
        explanation: "Fraudulent: Demands remote-access software (AnyDesk) and UPI PIN, which legitimate HR never requests.",
      },
      {
        id: "jg-q8",
        sender: "College Placement Cell",
        message: "Reminder: Wipro pre-placement talk is tomorrow at 10 AM in Seminar Hall 2. Official applications are open only on careers.wipro.com with zero fees.",
        correctChoice: "legitimate",
        explanation: "Legitimate: Campus notice pointing to Wipro's official careers domain with zero fee.",
      },
      {
        id: "jg-q9",
        sender: "Hindi Internship Forward",
        message: "बिना इंटरव्यू के नौकरी पाने के लिए ₹2,000 सिक्योरिटी डिपॉजिट दें और आज ही जॉइन करें।",
        correctChoice: "scam",
        explanation: "Fraudulent: Hindi security-deposit demand promising selection without an interview.",
      },
      {
        id: "jg-q10",
        sender: "Hiring Manager (Startup)",
        message: "Hi Aarav, we liked your GitHub portfolio for the Frontend Intern role (₹15,000/month stipend). Are you free Thursday at 4 PM for a 30-min Google Meet technical interview?",
        correctChoice: "legitimate",
        explanation: "Legitimate: Realistic stipend, specific portfolio reference, standard technical interview, and zero payment or credential demands.",
      },
    ],
  },
};
