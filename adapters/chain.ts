import type { AddressClass, Analysis, Network, PaymentEntry } from "../packages/core/src/index";

export type AdapterTrust = "local-fixture" | "remote-untrusted";
export type ObservationStatus = "match" | "not-found" | "unsupported" | "error";
export type QueryPrivacy = "not-applicable" | "address-disclosed" | "unspecified";

export interface AdapterObservation {
  adapterId: string;
  trust: AdapterTrust;
  status: ObservationStatus;
  entryIndex: string;
  network: Network;
  claim: "observation-only";
  queryPrivacy: QueryPrivacy;
  detail: string;
}

export interface ChainAdapter {
  readonly id: string;
  readonly trust: AdapterTrust;
  inspect(entry: PaymentEntry): Promise<AdapterObservation>;
}

export interface FixtureRecord {
  address: string;
  network: Network;
  classification: AddressClass;
  detail: string;
}

export interface RemoteObservationTransport {
  inspect(entry: PaymentEntry): Promise<Pick<AdapterObservation, "status" | "network" | "detail">>;
}

export interface LightwalletdTransparentQuery {
  address: string;
  startHeight: number;
  endHeight: number;
}

export interface LightwalletdTransparentTransaction {
  txid: string;
  height: number;
}

export interface LightwalletdTransparentTransport {
  getAddressTransactions(query: LightwalletdTransparentQuery): Promise<readonly LightwalletdTransparentTransaction[]>;
}

export interface AdapterEvaluation {
  adapterId: string;
  trustBoundary: "local-policy-authority";
  localGate: Analysis["gate"];
  effectiveGate: Analysis["gate"];
  verification: "not-verified";
  observations: AdapterObservation[];
}

export class FixtureChainAdapter implements ChainAdapter {
  readonly id = "fixture-chain";
  readonly trust = "local-fixture" as const;

  constructor(private readonly records: readonly FixtureRecord[]) {}

  async inspect(entry: PaymentEntry): Promise<AdapterObservation> {
    const record = this.records.find((item) => item.address === entry.address && item.network === entry.network && item.classification === entry.classification);
    return {
      adapterId: this.id,
      trust: this.trust,
      status: record ? "match" : "not-found",
      entryIndex: entry.index,
      network: entry.network,
      claim: "observation-only",
      queryPrivacy: "not-applicable",
      detail: record?.detail ?? "No local fixture observation matched this payment entry.",
    };
  }
}

export class RemoteChainAdapter implements ChainAdapter {
  readonly id = "remote-chain";
  readonly trust = "remote-untrusted" as const;

  constructor(readonly endpoint: string, private readonly transport: RemoteObservationTransport) {
    const parsed = new URL(endpoint);
    if (parsed.protocol !== "https:") throw new Error("Remote chain adapters require an HTTPS endpoint.");
    if (parsed.username || parsed.password) throw new Error("Remote chain adapter endpoints must not contain embedded credentials.");
    if (parsed.hash) throw new Error("Remote chain adapter endpoints must not contain a URL fragment.");
  }

  async inspect(entry: PaymentEntry): Promise<AdapterObservation> {
    const observation = await this.transport.inspect(entry);
    if (observation.status === "match" && observation.network !== entry.network) {
      throw new Error("Remote observation network does not match the payment entry.");
    }
    return {
      adapterId: this.id,
      trust: this.trust,
      ...observation,
      entryIndex: entry.index,
      claim: "observation-only",
      queryPrivacy: "unspecified",
    };
  }
}

function assertRemoteEndpoint(endpoint: string): void {
  const parsed = new URL(endpoint);
  if (parsed.protocol !== "https:") throw new Error("Remote chain adapter endpoints require HTTPS.");
  if (parsed.username || parsed.password) throw new Error("Remote chain adapter endpoints must not contain embedded credentials.");
  if (parsed.hash) throw new Error("Remote chain adapter endpoints must not contain a URL fragment.");
}

export class LightwalletdTransparentAdapter implements ChainAdapter {
  readonly id = "lightwalletd-transparent";
  readonly trust = "remote-untrusted" as const;

  constructor(
    readonly endpoint: string,
    private readonly endpointNetwork: Exclude<Network, "unknown">,
    private readonly transport: LightwalletdTransparentTransport,
    private readonly range: Pick<LightwalletdTransparentQuery, "startHeight" | "endHeight">,
  ) {
    assertRemoteEndpoint(endpoint);
    if (!Number.isSafeInteger(range.startHeight) || !Number.isSafeInteger(range.endHeight) || range.startHeight < 0 || range.endHeight < range.startHeight) {
      throw new Error("Lightwalletd transparent queries require a bounded, ordered block range.");
    }
  }

  async inspect(entry: PaymentEntry): Promise<AdapterObservation> {
    if (entry.classification !== "transparent") {
      return {
        adapterId: this.id,
        trust: this.trust,
        status: "unsupported",
        entryIndex: entry.index,
        network: entry.network,
        claim: "observation-only",
        queryPrivacy: "not-applicable",
        detail: "This protocol adapter only observes transparent-address transactions; it does not scan shielded or Unified receivers.",
      };
    }
    if (entry.network !== this.endpointNetwork) throw new Error("Lightwalletd endpoint network does not match the payment entry.");

    const records = await this.transport.getAddressTransactions({ address: entry.address, ...this.range });
    for (const record of records) {
      if (!/^[0-9a-fA-F]{64}$/.test(record.txid) || !Number.isSafeInteger(record.height) || record.height < 0) {
        throw new Error("Lightwalletd returned a malformed transparent transaction record.");
      }
      if (record.height > 0 && (record.height < this.range.startHeight || record.height > this.range.endHeight)) {
        throw new Error("Lightwalletd returned a transaction outside the requested block range.");
      }
    }
    const mined = records.filter((record) => record.height > 0);
    return {
      adapterId: this.id,
      trust: this.trust,
      status: mined.length > 0 ? "match" : "not-found",
      entryIndex: entry.index,
      network: this.endpointNetwork,
      claim: "observation-only",
      queryPrivacy: "address-disclosed",
      detail: mined.length > 0
        ? `The endpoint reported ${mined.length} mined transaction${mined.length === 1 ? "" : "s"} in the requested block range.`
        : "The endpoint reported no mined transparent transaction in the requested block range.",
    };
  }
}

export async function evaluateWithAdapter(analysis: Analysis, adapter: ChainAdapter): Promise<AdapterEvaluation> {
  const observations = await Promise.all(analysis.entries.map(async (entry) => {
    try {
      return await adapter.inspect(entry);
    } catch {
      return {
        adapterId: adapter.id,
        trust: adapter.trust,
        status: "error" as const,
        entryIndex: entry.index,
        network: entry.network,
        claim: "observation-only" as const,
        queryPrivacy: "unspecified" as const,
        detail: "The adapter failed; local policy remains the only decision source.",
      };
    }
  }));

  return {
    adapterId: adapter.id,
    trustBoundary: "local-policy-authority",
    localGate: analysis.gate,
    effectiveGate: analysis.gate,
    verification: "not-verified",
    observations,
  };
}
