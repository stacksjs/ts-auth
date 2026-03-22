import type { PickierConfig } from 'pickier'

const config: PickierConfig = {
  lint: {
    extensions: ['ts', 'js', 'json', 'md'],
  },
  format: {
    extensions: ['ts', 'js', 'json', 'md'],
    semi: false,
    quotes: 'single',
    indent: 2,
    trailingComma: true,
  },
}

export default config
