const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: v("bg"),
        panel: v("panel"),
        raised: v("raised"),
        line: v("line"),
        ink: v("ink"),
        mute: v("mute"),
        faint: v("faint"),
        accent: v("accent"),
        allow: v("allow"),
        cond: v("cond"),
        quar: v("quar"),
        block: v("block"),
      },
      fontFamily: {
        sans: ['"Inter Tight Variable"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      fontSize: { xs: ["12px", "16px"], sm: ["13px", "20px"], base: ["14px", "22px"] },
    },
  },
  plugins: [],
};
