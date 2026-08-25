/** @type {import('tailwindcss').Config} */

// Every colour resolves through a CSS variable so the whole interface can be
// repainted for the light theme without touching a single class name.
const themed = (name) => `rgb(var(--${name}) / <alpha-value>)`

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        vault: themed('vault'),
        plate: themed('plate'),
        raised: themed('raised'),
        edge: themed('edge'),
        brass: {
          DEFAULT: themed('brass'),
          bright: themed('brass-bright'),
          dim: themed('brass-dim'),
        },
        chalk: themed('chalk'),
        muted: themed('muted'),
        sealed: themed('sealed'),
        breach: themed('breach'),
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        plate: 'var(--plate-shadow)',
      },
      keyframes: {
        'seal-break': {
          '0%': { transform: 'scale(1) rotate(0deg)', opacity: '1' },
          '55%': { transform: 'scale(1.12) rotate(-8deg)', opacity: '0.5' },
          '100%': { transform: 'scale(0.9) rotate(4deg)', opacity: '0' },
        },
        rise: {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'seal-break': 'seal-break 420ms ease-in forwards',
        rise: 'rise 220ms ease-out both',
      },
    },
  },
  plugins: [],
}
