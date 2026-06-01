module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
    // Minify the compiled CSS in production builds only. `build:webpack` sets
    // NODE_ENV=production; the dev watch build leaves CSS unminified for readability.
    ...(process.env.NODE_ENV === 'production' ? { cssnano: {} } : {}),
  }
}
