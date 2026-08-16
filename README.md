# ShadeCheck

ShadeCheck is a browser-first privacy linter for Zcash payment requests and checkout flows.

It helps builders catch accidental disclosure before shipping. The first release parses ZIP-321 payment request URIs and Zcash address shapes, then flags transparent routes, mixed privacy levels, network mismatches, missing amounts, invalid indexed payments, and memo review requirements.

## Hackathon demo

The Privacy Checkout Lab turns the analyzer into a short before-and-after demo. Run the transparent fallback scenario to see a blocked policy gate and the public exposure it can create, then run the shielded checkout scenario to see the safer local result and its verification limits.

Live demo: [zcash-hackathon.vercel.app](https://zcash-hackathon.vercel.app/)

The demo is intentionally local-only and does not require a wallet, key, or network endpoint.

## Privacy boundary

- Runs entirely in the browser.
- Does not request seed phrases, private keys, viewing keys, wallet connections, or funds.
- Does not upload or persist user input.
- Validates supported address encodings and outer checksums, but does not claim full receiver cryptographic validation or chain verification.
- Does not query the chain, sign transactions, or broadcast payments.
- The result is a product review aid, not a wallet security guarantee.

## Engineering notes

The visual contract is recorded in [brand.md](brand.md). Optional chain observations are kept behind an explicit trust boundary and are not part of the default browser path.

## Local development

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Verification

```bash
npm run lint
npm test
npm run build
```

The test suite covers ZIP-321 duplicate fields, leading-zero indexes, missing addresses, amount and asset collisions, memo restrictions, required parameters, mixed networks, supported transparent and shielded checksum validation, Unified receiver decoding for custom assets, the shape-only trust boundary, deterministic report metadata, and redacted fixture encoding.

Reviewed inputs can produce a local JSON report with tool/rule versions and an input hash. Redacted fixture links preserve the policy outcome without placing the original request, address, or amount in the shared artifact.

## CLI

The same analyzer can run without the browser. It returns exit code `0` for pass, `1` for block, `2` for review, and `64` for usage or input errors.

```bash
printf '%s' 'zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=1' | npm run shadecheck -- --mode uri
npm run shadecheck -- --file checkout-request.txt --json
npm run fixture-check
```

The fixture gate is also part of GitHub Actions. It keeps one pass, one review, and one block request in the repository so CI exercises the same exit-code contract as the CLI.

## Research anchors

- [Zcash Feature UX Checklist](https://zcash.readthedocs.io/en/latest/rtd_pages/ux_wallet_checklist.html)
- [ZIP 321: Payment Request URIs](https://zips.z.cash/zip-0321)
- [ZIP 316: Unified Addresses and Unified Viewing Keys](https://zips.z.cash/zip-0316)
- [Zcash ZIP registry](https://zips.z.cash/)
