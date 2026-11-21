/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: { DEFAULT: "#10213A", deep: "#0B1728", card: "#111F36" },
        teal: { DEFAULT: "#167D82", soft: "#E5F4F1", bright: "#2DD4BF" },
      },
    },
  },
  plugins: [],
};
