declare module '@stacksjs/qrx' {
  export interface QRCodeOptions {
    text?: string
    width?: number
    height?: number
    colorDark?: string
    colorLight?: string
    correctLevel?: number
    useSVG?: boolean
  }

  export class QRCode {
    constructor(element: string | HTMLElement, options?: QRCodeOptions)
    makeCode(text: string): void
    clear(): void
  }

  export const QRCodeCorrectLevel: {
    L: number
    M: number
    Q: number
    H: number
  }
}
