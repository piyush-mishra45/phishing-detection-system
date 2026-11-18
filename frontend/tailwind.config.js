/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: { navy: { 950: '#050a1a', 900: '#070d1f', 800: '#0a1128', 700: '#0f1b3d', 600: '#16254f', 500: '#223468' } },
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'], mono: ['JetBrains Mono', 'ui-monospace', 'monospace'] },
      keyframes: { fadeUp: { '0%': { opacity: 0, transform: 'translateY(8px)' }, '100%': { opacity: 1, transform: 'none' } } },
      animation: { 'fade-up': 'fadeUp .4s ease-out both' },
    },
  },
  plugins: [],
}
