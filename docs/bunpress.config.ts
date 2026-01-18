import type { BunpressConfig } from 'bunpress'

const config: BunpressConfig = {
  name: 'ts-auth',
  description: 'Native WebAuthn and OTP authentication library built with Bun',
  url: 'https://ts-auth.stacksjs.org',

  theme: {
    primaryColor: '#0A0ABC',
  },

  nav: [
    { text: 'Guide', link: '/guide/getting-started' },
    { text: 'API', link: '/api/webauthn' },
    { text: 'GitHub', link: 'https://github.com/stacksjs/ts-auth' },
  ],

  sidebar: [
    {
      text: 'Introduction',
      items: [
        { text: 'What is ts-auth?', link: '/index' },
        { text: 'Getting Started', link: '/guide/getting-started' },
        { text: 'Installation', link: '/guide/installation' },
        { text: 'CLI Usage', link: '/guide/cli' },
      ],
    },
    {
      text: 'Guide',
      items: [
        { text: 'WebAuthn/Passkeys', link: '/guide/webauthn' },
        { text: 'TOTP/2FA Setup', link: '/guide/totp' },
      ],
    },
    {
      text: 'WebAuthn / Passkeys',
      items: [
        { text: 'Overview', link: '/webauthn/overview' },
        { text: 'Server-side Registration', link: '/webauthn/registration' },
        { text: 'Server-side Authentication', link: '/webauthn/authentication' },
        { text: 'Browser Integration', link: '/webauthn/browser' },
        { text: 'Credential Management', link: '/webauthn/credentials' },
      ],
    },
    {
      text: 'TOTP / 2FA',
      items: [
        { text: 'Overview', link: '/totp/overview' },
        { text: 'Generating Secrets', link: '/totp/secrets' },
        { text: 'Code Verification', link: '/totp/verification' },
        { text: 'QR Code Generation', link: '/totp/qr-codes' },
      ],
    },
    {
      text: 'Session Management',
      items: [
        { text: 'Overview', link: '/session/overview' },
        { text: 'Session Manager', link: '/session/manager' },
        { text: 'Middleware', link: '/session/middleware' },
        { text: 'CSRF Protection', link: '/session/csrf' },
      ],
    },
    {
      text: 'JWT Tokens',
      items: [
        { text: 'Overview', link: '/jwt/overview' },
        { text: 'Signing Tokens', link: '/jwt/signing' },
        { text: 'Verifying Tokens', link: '/jwt/verification' },
        { text: 'Token Pairs', link: '/jwt/token-pairs' },
      ],
    },
    {
      text: 'OAuth Providers',
      items: [
        { text: 'Overview', link: '/oauth/overview' },
        { text: 'Google', link: '/oauth/google' },
        { text: 'GitHub', link: '/oauth/github' },
        { text: 'Other Providers', link: '/oauth/providers' },
      ],
    },
    {
      text: 'Security',
      items: [
        { text: 'Best Practices', link: '/security/best-practices' },
        { text: 'Rate Limiting', link: '/security/rate-limiting' },
        { text: 'Token Blacklist', link: '/security/token-blacklist' },
        { text: 'Audit Logging', link: '/security/audit-logging' },
      ],
    },
    {
      text: 'API Reference',
      items: [
        { text: 'WebAuthn API', link: '/api/webauthn' },
        { text: 'TOTP API', link: '/api/totp' },
        { text: 'Session API', link: '/api/session' },
        { text: 'JWT API', link: '/api/jwt' },
        { text: 'Types', link: '/api/types' },
      ],
    },
  ],

  head: [
    ['meta', { name: 'author', content: 'Stacks.js' }],
    ['meta', { name: 'keywords', content: 'webauthn, passkeys, totp, 2fa, authentication, typescript, bun' }],
  ],

  socialLinks: [
    { icon: 'github', link: 'https://github.com/stacksjs/ts-auth' },
    { icon: 'discord', link: 'https://discord.gg/stacksjs' },
    { icon: 'twitter', link: 'https://twitter.com/stacksjs' },
  ],
}

export default config
