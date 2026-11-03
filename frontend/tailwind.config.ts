import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      animation: {
        'draw-line': 'draw-line 10s linear infinite',
        'draw-line-reverse': 'draw-line 14s linear infinite reverse',
        'fade-in-up': 'fade-in-up 0.8s ease-out forwards',
        'spin-slow': 'spin-slow 20s linear infinite',
        'reverse-spin': 'reverse-spin 25s linear infinite',
      },
      keyframes: {
        'draw-line': {
          '0%': { strokeDasharray: '3000', strokeDashoffset: '3000' },
          '100%': { strokeDasharray: '3000', strokeDashoffset: '0' },
        },
        'fade-in-up': {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'spin-slow': {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        'reverse-spin': {
          '0%': { transform: 'rotate(360deg)' },
          '100%': { transform: 'rotate(0deg)' },
        }
      },

      colors: {
        secure: {
          bg: "#0E0524",
          surface: "#333452",
          border: "#454B68",
          text: "#ADAFC4",
          accent: "#1733AE",
          neon: "#588F9A",
          lavender: "#797AB1",
        }
      },
    },
  },
  plugins: [],
};
export default config;
