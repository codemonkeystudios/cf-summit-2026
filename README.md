# ColdFusion Summit 2026 Authentication Demos

A small collection of ColdFusion authentication demos built for ColdFusion Summit 2026.

These examples are designed to show concepts, not to become the sacred authentication engine your company depends on until the sun burns out.

## What is in here?

This package contains simple demos for:

- Native ColdFusion passkeys
- Educational / hand-rolled passkey flow
- Magic-link login
- SSO / OAuth login
- MFA / TOTP
- A few helper pages and sanity checks

The goal is to make each authentication idea understandable without burying it under twelve layers of architecture, three service buses, a dependency injection container, and a meeting about naming conventions.

## What this is

This is demo code.

It is meant to be:

- Readable
- Small
- Easy to run
- Easy to explain
- Useful for learning
- Suitable for a conference talk, workshop, article, or mildly judgmental code walkthrough

It is intentionally not a complete production authentication system.

## What this is not

This is not:

- A drop-in authentication platform
- A replacement for your security team
- A full WebAuthn implementation
- A hardened OAuth client framework
- A distributed session-management strategy
- A database-backed identity provider
- Legal advice, tax advice, medical advice, or emotional support for debugging passkeys behind a load balancer

If you copy this directly into production and expose it to the internet, that faint noise you hear is your future incident response team quietly opening a ticket.

## Requirements

These demos expect:

- Adobe ColdFusion 2025
- A browser that supports the relevant authentication feature being tested
- Session management enabled through `Application.cfc`
- A public HTTPS origin for passkey and magic-link demos when testing outside localhost

Some demos may require additional configuration, such as OAuth client credentials or a browser-visible public base URL.

## Configuration

Review `demo_config.cfm` before running the demos.

You may need to update values such as:

- Public base URL
- Passkey relying party ID
- OAuth client ID
- OAuth client secret
- Callback URLs

For passkeys and magic links, the public URL matters. Not the URL your server thinks it has. Not the URL your reverse proxy whispers to itself in a dark corner. The URL the browser actually sees.

If you are using ngrok, Cloudflare Tunnel, nginx, Apache, ALB, or anything else between the user and ColdFusion, configure the demos accordingly.

## Running the demos

Place the folder somewhere ColdFusion can serve it, then open the relevant demo page in your browser.

Typical demo folders include:

```text
passkeys_cf/
passkeys_native/
magic_link/
sso/
mfa/
```

Exact paths may vary depending on how you unpacked the ZIP and where your web root points.

## Native ColdFusion passkey demo

The native passkey demo shows ColdFusion’s built-in passkey support.

Important conceptual distinction:

- Registration registers a passkey.
- Authentication signs the user in.

Those are not the same thing.

This matters because “success” does not always mean “the user is now logged in.” Sometimes it means “the user has registered a credential and should now authenticate.”

Authentication is fun like that.

## Educational passkey demo

The hand-rolled passkey demo exists to make the moving parts more visible.

It is not a full WebAuthn implementation.

It demonstrates pieces of the flow, including:

- Challenge creation
- Browser credential interaction
- Client data inspection
- Basic challenge/type/origin checks

It does not attempt to replace a real WebAuthn library or ColdFusion’s native passkey service.

Do not use it as production passkey verification unless your threat model is “the attacker gets bored and leaves.”

## Magic-link demo

The magic-link demo shows a simple email-link login flow.

It uses in-memory token storage because this is a demo. In a real system, magic-link tokens should be stored durably and consumed atomically, usually with a database update that succeeds exactly once.

The demo includes basic protections such as:

- Hashed tokens
- Expiration
- Single-use consumption
- Token cleanup
- Clean URL redirect after successful login

Still, production magic links deserve more care than “eh, it worked on stage.”

## SSO / OAuth demo

The SSO demo shows the general shape of an OAuth-based login.

You will need real provider credentials before this will do anything useful.

The demo includes state handling where practical, but provider behavior and ColdFusion runtime behavior may vary. Validate the final behavior with your actual provider configuration.

OAuth is one of those standards where everyone agrees on the general idea, and then every provider adds their own tiny haunted attic.

## MFA / TOTP demo

The MFA demo shows time-based one-time passwords.

It includes Base32 handling and a self-check page for known test vectors.

Before relying on the MFA demo during a presentation, run the self-check page on the actual ColdFusion runtime you plan to use. Static review is nice. Runtime verification is better. ColdFusion and Java interop occasionally enjoy reminding us who is really in charge.

## Security notes

These demos include a few basic safeguards so they teach the right ideas:

- Session rotation after login where supported
- Separate passkey registration and authentication handling
- Configurable public origins
- Basic token locking for magic-link consumption
- HTML attribute encoding where links are output
- Basic OAuth state handling
- Basic MFA Base32 self-checks

But again: demo code.

For production, you should consider:

- Durable user storage
- Durable credential storage
- HTTPS everywhere
- CSRF protection
- Rate limiting
- Replay protection
- Audit logging
- Secure email delivery
- Proper OAuth state and nonce validation
- Real WebAuthn verification
- Secret management
- Monitoring
- Alerting
- Backups
- Someone with “security” in their job title giving you the look

## Common gotchas

### Passkeys fail immediately

Check your relying party ID and browser-visible origin.

Passkeys are domain-bound. If your RP ID says `localhost` but your browser is on `demo.example.com`, the browser will not be amused.

### Magic links go to the wrong place

Check the public base URL.

If the generated link points to an internal hostname, HTTP instead of HTTPS, or a port your users cannot reach, the problem is not email. It is reality.

### OAuth does nothing useful

Check your client ID, client secret, redirect URI, provider setup, scopes, and whether the OAuth provider has decided today is a good day to be special.

### MFA codes do not validate

Check server time.

TOTP depends on time. If your server clock is wrong, the math will be wrong, and then everyone gets to pretend this is a security feature instead of a clock problem.

## Packaging notes

If you are creating a ZIP for sharing, exclude macOS metadata:

```bash
zip -r "CF Summit 2026.clean.zip" "CF Summit 2026" -x "__MACOSX/*" "*/.DS_Store"
```

Nobody attending a ColdFusion talk needs a bonus `__MACOSX` folder. They have suffered enough.

## Recommended demo flow

A reasonable presentation order:

1. Start with magic links because the concept is familiar.
2. Move to SSO because everyone has clicked “Sign in with Google” and then immediately forgotten how complicated it is.
3. Introduce MFA because passwords apparently needed side quests.
4. Finish with passkeys because that is where things get interesting.
5. Show the educational passkey demo only if the room still trusts you.

## Final reminder

These demos are here to teach authentication concepts in ColdFusion.

They are intentionally approachable.

They are intentionally incomplete.

They are intentionally not production infrastructure.

Use them to learn, explain, experiment, and build better things.

Do not use them as your company’s entire identity strategy unless your company is a lemonade stand and the lemonade stand is also fictional.