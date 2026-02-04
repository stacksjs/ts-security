import type { BunpressConfig } from 'bunpress'

const config: BunpressConfig = {
  name: 'ts-security',
  description: 'A comprehensive TypeScript security library providing cryptographic primitives, TLS/HTTPS support, and X.509 certificate management.',
  url: 'https://ts-security.stacksjs.org',

  theme: {
    primaryColor: '#2563EB',
  },

  nav: [
    { text: 'Guide', link: '/guide/getting-started' },
    { text: 'API', link: '/api/crypto' },
    { text: 'GitHub', link: 'https://github.com/stacksjs/ts-security' },
  ],

  sidebar: [
    {
      text: 'Introduction',
      items: [
        { text: 'What is ts-security?', link: '/index' },
        { text: 'Getting Started', link: '/guide/getting-started' },
        { text: 'Installation', link: '/install' },
      ],
    },
    {
      text: 'Guide',
      items: [
        { text: 'Certificate Management', link: '/guide/certificates' },
        { text: 'HTTPS Setup', link: '/guide/https' },
        { text: 'X.509 Operations', link: '/guide/x509' },
      ],
    },
    {
      text: 'Cryptography',
      items: [
        { text: 'AES Encryption', link: '/crypto/aes' },
        { text: 'RSA', link: '/crypto/rsa' },
        { text: 'Hashing (SHA)', link: '/crypto/hashing' },
        { text: 'HMAC', link: '/crypto/hmac' },
        { text: 'Random Numbers', link: '/crypto/random' },
      ],
    },
    {
      text: 'TLS/SSL',
      items: [
        { text: 'Overview', link: '/tls/overview' },
        { text: 'Connections', link: '/tls/connections' },
        { text: 'Cipher Suites', link: '/tls/ciphers' },
      ],
    },
    {
      text: 'Utilities',
      items: [
        { text: 'PEM Encoding', link: '/utils/pem' },
        { text: 'ASN.1', link: '/utils/asn1' },
        { text: 'Base64', link: '/utils/base64' },
      ],
    },
    {
      text: 'API Reference',
      items: [
        { text: 'Crypto API', link: '/api/crypto' },
        { text: 'PKI API', link: '/api/pki' },
        { text: 'TLS API', link: '/api/tls' },
        { text: 'Types', link: '/api/types' },
      ],
    },
  ],

  head: [
    ['meta', { name: 'author', content: 'Stacks.js' }],
    ['meta', { name: 'keywords', content: 'typescript, security, cryptography, tls, https, certificates, x509, aes, rsa, encryption' }],
  ],

  socialLinks: [
    { icon: 'github', link: 'https://github.com/stacksjs/ts-security' },
    { icon: 'discord', link: 'https://discord.gg/stacksjs' },
    { icon: 'twitter', link: 'https://twitter.com/stacksjs' },
  ],
}

export default config
