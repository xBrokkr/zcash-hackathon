# Chain adapter observation boundary

ShadeCheck's default browser and CLI paths are local-only. Optional adapters are observation channels and never replace the local policy result.

## Contract

`adapters/chain.ts` defines a small `ChainAdapter` interface. Its output includes:

- adapter identity and trust class;
- payment entry scope and network;
- `match`, `not-found`, or `error` status;
- an explicit observation-only claim.

`evaluateWithAdapter()` returns both the local gate and the adapter observation. Adapter data cannot upgrade or replace a blocked local result, and the result remains `verification: not-verified`.

The fixture adapter performs no HTTP, gRPC, wallet, or chain access. The remote boundary is HTTPS-only and dependency-injected so transport, endpoint trust, freshness, network selection, and disclosure behavior can be tested independently before a network client is enabled.

Transparent address observations disclose their address scope explicitly. Shielded and Unified entries are not queried by the transparent observation adapter. No adapter is imported by the default React path.

## References

- [ZIP-307](https://zips.z.cash/zip-0307)
- [Zcash light wallet protocol](https://github.com/zcash/lightwallet-protocol)
