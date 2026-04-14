---
title: WebAuthn Overview
description: Implement passwordless authentication with WebAuthn and Passkeys
---

```typescript

const options = generateRegistrationOptions({
  // ... other options
  authenticatorSelection: {
    authenticatorAttachment: 'platform',
    userVerification: 'required',
  },
})

```

### Roaming Authenticators

External security keys:

- **YubiKey**
- **Google Titan**
- **Feitian**

```typescript

const options = generateRegistrationOptions({
  // ... other options
  authenticatorSelection: {
    authenticatorAttachment: 'cross-platform',
  },
})

```

## Security Considerations

1. **Always use HTTPS** - WebAuthn only works in secure contexts
2. **Validate origin** - Verify the origin matches your domain
3. **Store credentials securely** - Protect public keys and credential IDs
4. **Track counters** - Detect cloned authenticators
5. **Handle multiple credentials** - Users may register multiple devices

## Browser Support

| Browser | Platform Auth | Roaming Auth | Conditional UI |
|---------|--------------|--------------|----------------|
| Chrome | Yes | Yes | Yes |
| Firefox | Yes | Yes | No |
| Safari | Yes | Yes | Yes |
| Edge | Yes | Yes | Yes |

## Next Steps

- [Server-side Registration](/webauthn/registration)
- [Server-side Authentication](/webauthn/authentication)
- [Browser Integration](/webauthn/browser)
- [Credential Management](/webauthn/credentials)
