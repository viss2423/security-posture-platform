/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['var(--font-sans)', 'system-ui', 'sans-serif'],
      },
      colors: {
        bg: '#070b12',
        surface: '#0c1118',
        'surface-soft': '#0f1520',
        'surface-elevated': '#131d2e',
        muted: '#5a6880',
        accent: '#22d3ee',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#f43f5e',
      },
      animation: {
        'fade-in': 'fadeIn 0.4s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
        'neon-pulse': 'neonPulse 3s ease-in-out infinite',
        'pulse-dot': 'pulseDot 2s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        neonPulse: {
          '0%, 100%': { boxShadow: '0 0 8px rgba(34,211,238,0.3)' },
          '50%': { boxShadow: '0 0 24px rgba(34,211,238,0.65), 0 0 48px rgba(34,211,238,0.2)' },
        },
        pulseDot: {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.55', transform: 'scale(0.82)' },
        },
      },
      boxShadow: {
        glow: '0 0 20px rgba(34,211,238,0.25)',
        'glow-lg': '0 0 40px rgba(34,211,238,0.38)',
        'glow-green': '0 0 16px rgba(16,185,129,0.3)',
        'glow-red': '0 0 16px rgba(244,63,94,0.3)',
      },
    },
  },
  plugins: [],
};
