# Claude Code Guidelines

## About

ts-security is a comprehensive TypeScript cryptographic library providing AES encryption (128/192/256-bit with ECB, CBC, CFB, OFB, CTR, GCM modes), SHA-2 hashing (SHA-256/384/512), HMAC, RSA encryption/signing, and Ed25519 digital signatures. It also includes X.509 certificate management (PEM encoding, CSR creation, chain validation), a Fortuna CSPRNG implementation, TLS/SSL protocol support, and utilities for Base-N encoding, ASN.1, and BigInteger arithmetic. The library works in both browser and Bun/Node.js environments.

## Linting

- Use **pickier** for linting — never use eslint directly
- Run `bunx --bun pickier .` to lint, `bunx --bun pickier . --fix` to auto-fix
- When fixing unused variable warnings, prefer `// eslint-disable-next-line` comments over prefixing with `_`

## Frontend

- Use **stx** for templating — never write vanilla JS (`var`, `document.*`, `window.*`) in stx templates
- Use **crosswind** as the default CSS framework which enables standard Tailwind-like utility classes
- stx `<script>` tags should only contain stx-compatible code (signals, composables, directives)

## Dependencies

- **buddy-bot** handles dependency updates — not renovatebot
- **better-dx** provides shared dev tooling as peer dependencies — do not install its peers (e.g., `typescript`, `pickier`, `bun-plugin-dtsx`) separately if `better-dx` is already in `package.json`
- If `better-dx` is in `package.json`, ensure `bunfig.toml` includes `linker = "hoisted"`

## Commits

- Use conventional commit messages (e.g., `fix:`, `feat:`, `chore:`)
