const { defineConfig } = require('cypress')

module.exports = defineConfig({
  e2e: {
    baseUrl: 'http://rancher.local',
    supportFile: 'cypress/support/commands.js',
    video: true,
    screenshotsFolder: 'cypress/screenshots',
    videosFolder: 'cypress/videos',
    viewportWidth: 1280,
    viewportHeight: 720,
    retries: {
      runMode: process.env.CI ? 2 : 0,
      openMode: 0,
    },
    env: {
      rancherUsername: 'admin',
      rancherPassword: 'mytestcluster',
    },
    setupNodeEvents(on, config) {
    },
    defaultCommandTimeout: 45000,
  },
}) 