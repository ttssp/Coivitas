import type { AgentIdentityDocument, DID } from '@coivitas/types';

export const IDENTITY_ERROR_CODES = [
    'INVALID_DID_FORMAT',
    'INVALID_BINDING_PROOF',
    'BINDING_PROOF_EXPIRED',
    'PRINCIPAL_NOT_FOUND',
    'RESOLVER_UNAVAILABLE',
    'REGISTRATION_FAILED',
    'DEACTIVATED_AGENT',
] as const;

export type IdentityErrorCode = (typeof IDENTITY_ERROR_CODES)[number];

export type ResolveResult =
    | { found: true; document: AgentIdentityDocument }
    | { found: false; code: 'IDENTITY_NOT_FOUND' | 'DEACTIVATED' };

export type RegistrationResult =
    | { success: true; did: DID }
    | {
          success: false;
          code:
              | 'DID_ALREADY_EXISTS'
              | 'INVALID_BINDING_PROOF'
              | 'INVALID_REGISTRATION_PROOF'
              | 'INTERNAL_ERROR';
          message: string;
      };

export interface CreateAgentIdentityParams {
    principalDid: DID;
    principalPrivateKey: string;
    capabilities?: string[];
    serviceEndpoints?: Array<{ id: string; type: string; url: string }>;
    createdAt?: string;
}

export interface CreateAgentIdentityResult {
    document: AgentIdentityDocument;
    privateKey: string;
}

