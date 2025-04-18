import process from 'node:process'
import { dts } from 'bun-plugin-dtsx'

console.log('Building...')

const result = await Bun.build({
  entrypoints: ['./src/index.ts'],
  outdir: './dist',
  minify: true,
  plugins: [
    dts(),
  ],
})

if (!result.success) {
  console.error('Build failed')

  for (const message of result.logs) {
    // Bun will pretty print the message object
    console.error(message)
  }

  process.exit(1)
}

console.log('Build complete')
