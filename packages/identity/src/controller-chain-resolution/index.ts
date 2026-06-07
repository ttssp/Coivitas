/**
 * ControllerChainResolution (CCR) v0.1 — L2 barrel export
 */
export {
    resolveControllerChain,
    verifyChainIntegrityProof,
    validateCcrRequest,
} from './controller-chain-resolution.js';
export type {
    DidDocumentResolver,
    RfpVerifierPort,
    ControllerRevocationChecker,
    CcrResolverOptions,
} from './controller-chain-resolution.js';
