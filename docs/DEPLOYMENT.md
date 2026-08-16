# ShadeCheck deployment

ShadeCheck is a Next.js application with a static-friendly, client-only analyzer path. Vercel should build the repository with `npm ci` and `npm run build`; this contract is recorded in `vercel.json`.

## Production boundary

- The default browser path makes no chain requests.
- No wallet, seed phrase, viewing key, credential, or user input is required by the build.
- The optional adapter code remains outside the default React path.
- Production responses add a restrictive Content Security Policy, frame protection, referrer policy, permissions policy, and MIME-sniffing protection.

## Local release check

```bash
npm ci
npm run lint
npm test
npm run build
```

Deploy only from a pushed commit and verify the resulting URL separately from local readiness. A successful local build is not evidence that a Vercel project is connected or serving traffic.
