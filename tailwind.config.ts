import type { Config } from 'tailwindcss';
// Same palette as the customer app so the two feel like one product. Dark mode follows the device setting (no JS needed).
const config: Config = {
  darkMode: 'media',
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        navy: { 50: '#EEF2F8', 100: '#D5DFEE', 500: '#1E3A66', 700: '#12274A', 900: '#0B1B36' },
        brand: { orange: '#FF7A1A', purple: '#6D3BD2' },
      },
      fontFamily: { sans: ['var(--font-inter)', 'system-ui', 'sans-serif'] },
      borderRadius: { card: '1rem' },
    },
  },
  plugins: [],
};
export default config;
