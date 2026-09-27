/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        background: '#07080a',
        surface: '#0d1014',
        'surface-panel': '#111419',
        ink: '#f3efe9',
        'ink-dim': '#9a9ca1',
        accent: '#ff6a2c',
        'border-line': 'rgba(255,255,255,0.08)',
        success: '#4ADE80',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        heading: ['"Space Grotesk"', 'Inter', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      borderRadius: { panel: '14px' },
    },
  },
  plugins: [],
};
