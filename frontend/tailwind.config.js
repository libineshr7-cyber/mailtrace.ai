/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Background layers
        bg: {
          primary: '#0d1117',
          secondary: '#161b22',
          tertiary: '#21262d',
          hover: '#1c2128',
        },
        // Borders
        border: {
          DEFAULT: '#30363d',
          subtle: '#21262d',
          muted: '#161b22',
        },
        // Text
        text: {
          primary: '#e6edf3',
          secondary: '#8b949e',
          muted: '#6e7681',
          inverse: '#0d1117',
        },
        // Accent
        accent: {
          blue: '#388bfd',
          'blue-light': '#58a6ff',
          'blue-muted': '#1f4270',
        },
        // Semantic
        critical: {
          DEFAULT: '#f85149',
          muted: '#3d1a19',
          border: '#6e1f1e',
        },
        warning: {
          DEFAULT: '#d29922',
          muted: '#2f2108',
          border: '#5a3e0a',
        },
        success: {
          DEFAULT: '#3fb950',
          muted: '#0f2d13',
          border: '#1a4d20',
        },
        info: {
          DEFAULT: '#388bfd',
          muted: '#0d2040',
        },
      },
      fontFamily: {
        sans: ['Inter', 'IBM Plex Sans', 'system-ui', 'sans-serif'],
        mono: ['IBM Plex Mono', 'JetBrains Mono', 'Fira Code', 'monospace'],
      },
      fontSize: {
        '2xs': '0.65rem',
        xs: '0.75rem',
        sm: '0.8125rem',
        base: '0.875rem',
        lg: '1rem',
        xl: '1.125rem',
        '2xl': '1.25rem',
      },
      spacing: {
        sidebar: '220px',
        topbar: '48px',
      },
      borderRadius: {
        DEFAULT: '4px',
        sm: '2px',
        md: '6px',
        lg: '8px',
      },
      boxShadow: {
        panel: '0 1px 3px rgba(0,0,0,0.4), 0 0 0 1px rgba(48,54,61,0.5)',
        drawer: '0 8px 32px rgba(0,0,0,0.6)',
        dropdown: '0 4px 16px rgba(0,0,0,0.5), 0 0 0 1px rgba(48,54,61,0.8)',
      },
    },
  },
  plugins: [],
}
