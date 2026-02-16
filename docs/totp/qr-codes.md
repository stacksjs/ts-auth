---
title: QR Code Generation
description: Generate QR codes for TOTP setup with authenticator apps
---

```

### URI Options

```typescript

const uri = totpKeyUri(
  'user@example.com',
  'MyApp',
  secret,
  {
    // Only include if different from defaults
    algorithm: 'SHA-256', // Default: SHA-1
    digits: 8,            // Default: 6
    period: 60,           // Default: 30
  }
)

```

## Generating QR Codes

### SVG Format (Browser)

```typescript

import { generateQRCodeSVG, QRErrorCorrection } from 'ts-auth'

const svg = generateQRCodeSVG({
  text: uri,
  width: 256,
  height: 256,
  correctLevel: QRErrorCorrection.H, // High error correction
})

// Use in HTML
document.getElementById('qr-container').innerHTML = svg

```

### Data URL Format

```typescript

import { generateQRCodeDataURL } from 'ts-auth'

const dataUrl = await generateQRCodeDataURL({
  text: uri,
  width: 256,
  height: 256,
})

// Use in an img tag
const img = document.createElement('img')
img.src = dataUrl
img.alt = 'Scan with your authenticator app'
document.getElementById('qr-container').appendChild(img)

```

### Attach to DOM Element

```typescript

import { createQRCode } from 'ts-auth'

// Render directly into a container
createQRCode(document.getElementById('qr-container'), {
  text: uri,
  width: 256,
  height: 256,
})

```

## QR Code Options

```typescript

interface QRCodeOptions {
  // The text/URL to encode
  text: string

  // Width in pixels
  width?: number // Default: 256

  // Height in pixels
  height?: number // Default: 256

  // Error correction level
  correctLevel?: QRErrorCorrection // Default: H

  // Colors (for some implementations)
  colorDark?: string  // Default: '#000000'
  colorLight?: string // Default: '#ffffff'
}

// Error correction levels
enum QRErrorCorrection {
  L = 1, // Low (~7% recovery)
  M = 0, // Medium (~15% recovery)
  Q = 3, // Quartile (~25% recovery)
  H = 2, // High (~30% recovery) - Recommended for TOTP
}

```

## Server-Side Generation

Generate QR codes on the server and send to the client:

```typescript

import { generateQRCodeDataURL, totpKeyUri, generateTOTPSecret } from 'ts-auth'

// API endpoint
app.post('/api/totp/setup', async (req, res) => {
  const user = req.user

  // Generate secret
  const secret = generateTOTPSecret()

  // Create URI
  const uri = totpKeyUri(user.email, 'MyApp', secret)

  // Generate QR code as data URL
  const qrCodeDataUrl = await generateQRCodeDataURL({
    text: uri,
    width: 256,
    height: 256,
  })

  // Store secret temporarily
  await session.put(`totp_setup_${user.id}`, {
    secret,
    expiresAt: Date.now() + 10 _ 60 _ 1000,
  })

  res.json({
    qrCode: qrCodeDataUrl,
    secret, // Show for manual entry
  })
})

```

## React Component Example

```tsx

import { useState, useEffect } from 'react'

interface TOTPSetupProps {
  userId: string
  email: string
}

function TOTPSetup({ userId, email }: TOTPSetupProps) {
  const [setup, setSetup] = useState<{
    qrCode: string
    secret: string
  } | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[]>([])

  useEffect(() => {
    // Start setup
    fetch('/api/totp/setup', { method: 'POST' })
      .then(r => r.json())
      .then(setSetup)
  }, [])

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault()
    setError('')

    const response = await fetch('/api/totp/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    })

    const result = await response.json()

    if (result.success) {
      setBackupCodes(result.backupCodes)
    } else {
      setError(result.error)
    }
  }

  if (backupCodes.length > 0) {
    return (
      <div className="backup-codes">
        <h2>Save Your Backup Codes</h2>
        <p>Store these codes somewhere safe. Each can only be used once.</p>
        <ul>
          {backupCodes.map((code, i) => (
            <li key={i}><code>{code}</code></li>
          ))}
        </ul>
        <button onClick={() => window.print()}>Print Codes</button>
      </div>
    )
  }

  if (!setup) {
    return <div>Loading...</div>
  }

  return (
    <div className="totp-setup">
      <h2>Set Up Two-Factor Authentication</h2>

      <div className="qr-section">
        <img src={setup.qrCode} alt="Scan this QR code" />
        <p>Scan with your authenticator app</p>
      </div>

      <details className="manual-entry">
        <summary>Can't scan? Enter manually</summary>
        <p>Account: {email}</p>
        <p>Secret: <code>{setup.secret}</code></p>
      </details>

      <form onSubmit={handleVerify}>
        <label>
          Enter the 6-digit code from your app:
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]{6}"
            maxLength={6}
            value={code}
            onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
            autoComplete="one-time-code"
          />
        </label>

        {error && <p className="error">{error}</p>}

        <button type="submit" disabled={code.length !== 6}>
          Verify and Enable
        </button>
      </form>
    </div>
  )
}

```

## Accessibility Considerations

Always provide an alternative to QR codes for users who cannot scan:

```html

<div class="totp-setup">
  <!-- QR Code -->
  <img
    src={qrCodeDataUrl}
    alt="QR code for authenticator app setup"
    role="img"
    aria-describedby="manual-entry"
  />

  <!-- Manual entry fallback -->
  <div id="manual-entry">
    <h3>Manual Setup</h3>
    <dl>
      <dt>Account</dt>
      <dd>user@example.com</dd>
      <dt>Secret Key</dt>
      <dd>
        <code aria-label="Secret key">{secret}</code>
        <button onclick="copyToClipboard(secret)">Copy</button>
      </dd>
    </dl>
  </div>
</div>

```

## Best Practices

1. **Use high error correction** - QRErrorCorrection.H ensures the code is scannable even with minor damage or distortion

2. **Provide manual entry** - Always show the secret for users who cannot scan

3. **Show backup codes after verification** - Only show backup codes once, after the user proves they can generate codes

4. **Use appropriate size** - 256x256 pixels is typically sufficient; larger may be needed for printing

5. **Secure the setup endpoint** - Require authentication before allowing TOTP setup

## Next Steps

- [Session Management](/session/overview)
- [Security Best Practices](/security/best-practices)
