import type { AddressClass, Analysis, Network, PaymentEntry } from "../packages/core/src/index";

export type AdapterTrust = "local-fixture" | "remote-untrusted";
export type ObservationStatus = "match" | "not-found" | "error";

export interface AdapterObservation {
  adapterId: string;
  trust: AdapterTrust;
  status: ObservationStatus;
  entryIndex: string;
  network: Network;
  claim: "observation-only";
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
  }

  async inspect(entry: PaymentEntry): Promise<AdapterObservation> {
    const observation = await this.transport.inspect(entry);
    return {
      adapterId: this.id,
      trust: this.trust,
      ...observation,
      entryIndex: entry.index,
      claim: "observation-only",
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
