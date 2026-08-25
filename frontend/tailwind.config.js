/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // A vault interior: deep blue-black plate steel with brass hardware.
        vault: '#0E1015',
        plate: '#161A22',
        raised: '#1D222C',
        edge: '#2A313E',
        brass: {
          DEFAULT: '#C79A3C',
          bright: '#E3B85A',
          dim: '#8A6C2A',
        },
        chalk: '#E8E6E1',
        muted: '#8D93A1',
        sealed: '#5E8C7D',
        breach: '#C4574B',
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        plate: '0 1px 0 0 rgba(255,255,255,0.04) inset, 0 12px 32px -12px rgba(0,0,0,0.8)',
      },
      keyframes: {
        'seal-break': {
          '0%': { transform: 'scale(1) rotate(0deg)', opacity: '1' },
          '55%': { transform: 'scale(1.12) rotate(-8deg)', opacity: '0.5' },
          '100%': { transform: 'scale(0.9) rotate(4deg)', opacity: '0' },
        },
        'rise': {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-in': {
          from: { transform: 'translateX(24px)', opacity: '0' },
          to: { transform: 'translateX(0)', opacity: '1' },
        },
      },
      animation: {
        'seal-break': 'seal-break 420ms ease-in forwards',
        rise: 'rise 220ms ease-out both',
        'slide-in': 'slide-in 240ms cubic-bezier(0.2, 0.8, 0.2, 1) both',
      },
    },
  },
  plugins: [],
}
