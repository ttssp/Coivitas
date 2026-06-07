import type { EventEmitter } from 'node:events';
import type {
    AgentCard,
    DocumentUpdatedEvent,
    DID,
} from '@coivitas/types';

export interface AgentCardServiceOptions {
    agentDid: DID;
    buildCard: () => AgentCard | Promise<AgentCard>;
    eventEmitter: EventEmitter;
}

export class AgentCardService {
    private readonly agentDid: DID;
    private readonly buildCard: () => AgentCard | Promise<AgentCard>;
    private cache: AgentCard | null = null;

    public constructor(options: AgentCardServiceOptions) {
        this.agentDid = options.agentDid;
        this.buildCard = options.buildCard;
        options.eventEmitter.on(
            'documentUpdated',
            (event: DocumentUpdatedEvent) => {
                if (event.did === this.agentDid) {
                    this.cache = null;
                }
            },
        );
    }

    public async getCard(): Promise<AgentCard> {
        if (this.cache === null) {
            this.cache = await this.buildCard();
        }
        return this.cache;
    }

    public invalidate(): void {
        this.cache = null;
    }
}
