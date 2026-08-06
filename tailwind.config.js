/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Nostter のようなミニマルなダークテーマの配色
        bg: '#0e1012',
        surface: '#171a1f',
        'surface-2': '#20252d',
        border: '#2e3440',
        primary: '#4da0ff',
        'primary-hover': '#3a89d6',
      },
    },
  },
  plugins: [],
};
