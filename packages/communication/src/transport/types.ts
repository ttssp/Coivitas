import type { NegotiationEnvelope } from '@coivitas/types';

export type EnvelopeHandler = (
    envelope: NegotiationEnvelope,
) => Promise<NegotiationEnvelope | null>;

export interface Transport {
    send(
        envelope: NegotiationEnvelope,
        endpoint: string,
    ): Promise<NegotiationEnvelope | null>;
    listen(port: number, handler: EnvelopeHandler): Promise<number>;
    close(): Promise<void>;
}
