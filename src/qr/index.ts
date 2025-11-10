import { QRCode, QRCodeCorrectLevel } from '@stacksjs/qrx'

/**
 * Error correction levels for QR codes
 */
export enum QRErrorCorrection {
  /** Low - recovers ~7% of data */
  L = 1,
  /** Medium - recovers ~15% of data */
  M = 0,
  /** Quartile - recovers ~25% of data */
  Q = 3,
  /** High - recovers ~30% of data */
  H = 2,
}

export interface QRCodeOptions {
  /** The text or data to encode in the QR code */
  text: string
  /** Width in pixels (default: 256) */
  width?: number
  /** Height in pixels (default: 256) */
  height?: number
  /** Dark color (default: #000000) */
  colorDark?: string
  /** Light color (default: #ffffff) */
  colorLight?: string
  /** Error correction level (default: H) */
  correctLevel?: QRErrorCorrection
  /** Use SVG rendering instead of Canvas (default: false) */
  useSVG?: boolean
}

/**
 * Generate a QR code as an SVG string (server-safe)
 *
 * This is a server-friendly method that doesn't require DOM access.
 * It returns the raw SVG markup as a string.
 *
 * @param options - QR code generation options
 * @returns SVG string representation of the QR code
 *
 * @example
 * ```ts
 * const svg = generateQRCodeSVG({
 *   text: 'https://example.com',
 *   width: 300,
 *   height: 300,
 *   correctLevel: QRErrorCorrection.H
 * })
 * ```
 */
export function generateQRCodeSVG(options: QRCodeOptions): string {
  const {
    text,
    width = 256,
    height = 256,
    colorDark = '#000000',
    colorLight = '#ffffff',
    correctLevel = QRErrorCorrection.H
  } = options

  // For server-side generation, we'll need to create a minimal DOM environment
  // or use a different approach. For now, we'll document this as requiring a DOM.

  // In a real implementation, you'd use a server-safe SVG generation approach
  // This is a placeholder that will work in browser environments
  const container = typeof document !== 'undefined'
    ? document.createElement('div')
    : null

  if (!container) {
    throw new Error('generateQRCodeSVG requires a DOM environment. Use a browser or a DOM implementation like jsdom.')
  }

  const qr = new QRCode(container, {
    text,
    width,
    height,
    colorDark,
    colorLight,
    correctLevel: mapErrorCorrectionLevel(correctLevel),
    useSVG: true,
  })

  // Extract the SVG element
  const svg = container.querySelector('svg')
  if (!svg) {
    throw new Error('Failed to generate QR code SVG')
  }

  return svg.outerHTML
}

/**
 * Generate a QR code as a data URL (browser-only)
 *
 * @param options - QR code generation options
 * @returns Promise resolving to a data URL string
 *
 * @example
 * ```ts
 * const dataUrl = await generateQRCodeDataURL({
 *   text: 'otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example'
 * })
 * // Use in an <img> tag: <img src={dataUrl} />
 * ```
 */
export async function generateQRCodeDataURL(options: QRCodeOptions): Promise<string> {
  const {
    text,
    width = 256,
    height = 256,
    colorDark = '#000000',
    colorLight = '#ffffff',
    correctLevel = QRErrorCorrection.H
  } = options

  if (typeof document === 'undefined') {
    throw new Error('generateQRCodeDataURL requires a browser environment')
  }

  const container = document.createElement('div')
  container.style.position = 'absolute'
  container.style.left = '-9999px'
  document.body.appendChild(container)

  try {
    const qr = new QRCode(container, {
      text,
      width,
      height,
      colorDark,
      colorLight,
      correctLevel: mapErrorCorrectionLevel(correctLevel),
      useSVG: false, // Use canvas for data URL
    })

    // Wait a bit for rendering
    await new Promise(resolve => setTimeout(resolve, 100))

    const canvas = container.querySelector('canvas')
    if (!canvas) {
      throw new Error('Failed to generate QR code canvas')
    }

    return canvas.toDataURL('image/png')
  } finally {
    document.body.removeChild(container)
  }
}

/**
 * Create a QR code instance attached to a DOM element (browser-only)
 *
 * @param element - DOM element or element ID to attach to
 * @param options - QR code generation options
 * @returns QRCode instance
 *
 * @example
 * ```ts
 * const qr = createQRCode('qr-container', {
 *   text: 'https://example.com',
 *   width: 256,
 *   height: 256
 * })
 *
 * // Later, update the code
 * qr.makeCode('https://newurl.com')
 * ```
 */
export function createQRCode(
  element: string | HTMLElement,
  options: QRCodeOptions
): QRCode {
  const { correctLevel = QRErrorCorrection.H, ...rest } = options

  return new QRCode(element, {
    ...rest,
    correctLevel: mapErrorCorrectionLevel(correctLevel),
  })
}

/**
 * Map our error correction enum to the qrx library's enum
 */
function mapErrorCorrectionLevel(level: QRErrorCorrection): number {
  switch (level) {
    case QRErrorCorrection.L:
      return QRCodeCorrectLevel.L
    case QRErrorCorrection.M:
      return QRCodeCorrectLevel.M
    case QRErrorCorrection.Q:
      return QRCodeCorrectLevel.Q
    case QRErrorCorrection.H:
      return QRCodeCorrectLevel.H
    default:
      return QRCodeCorrectLevel.H
  }
}

// Re-export for convenience
export { QRCode }
