import type {
    AllowlistScope,
    CumulativeLimitScope,
    DID,
    NumericLimitScope,
    RecurringWindow,
    Scope,
    TemporalScope,
} from '@coivitas/types';

import type { CumulativeTracker } from './cumulative-tracker.js';
import {
    computeWindowStart,
    METER_FIELD_REGISTRY,
} from './cumulative-tracker.js';
import {
    BUILT_IN_SCOPE_TYPES,
    type ScopeEvaluatorRegistry,
    globalScopeEvaluatorRegistry,
} from '../scope/scope-evaluator-registry.js';

export interface ScopeEvaluationResult {
    allowed: boolean;
    reason?: string;
}

// Plugin interface: both synchronous and asynchronous evaluators can be registered
export type EvaluatorFn = (
    scope: Scope,
    params: Record<string, unknown>,
    now: Date,
    tracker?: CumulativeTracker,
) => ScopeEvaluationResult | Promise<ScopeEvaluationResult>;

export class ScopeEvaluator {
    readonly #evaluators: Map<string, EvaluatorFn> = new Map();
    readonly #registry: ScopeEvaluatorRegistry;

    /**
     * @param tracker Cumulative metering tracker (required by cumulative_limit)
     * @param registry Third-party Scope evaluator registry (defaults to the global registry)
     */
    public constructor(
        private readonly tracker?: CumulativeTracker,
        registry?: ScopeEvaluatorRegistry,
    ) {
        // Use the passed-in registry or the global registry (an isolated instance can be injected in tests)
        this.#registry = registry ?? globalScopeEvaluatorRegistry;

        // Built-in type registration (bypasses ScopeEvaluatorRegistry, written directly into the private Map)
        this.#evaluators.set('allowlist', (scope, params) =>
            evaluateAllowlist(
                (scope as AllowlistScope).field,
                (scope as AllowlistScope).values,
                params,
            ),
        );
        this.#evaluators.set('numeric_limit', (scope, params) =>
            evaluateNumericLimit(
                (scope as NumericLimitScope).field,
                (scope as NumericLimitScope).max,
                params,
            ),
        );
        this.#evaluators.set('temporal_scope', (scope, _params, now) =>
            evaluateTemporalScope(scope as TemporalScope, now),
        );
        this.#evaluators.set(
            'cumulative_limit',
            (scope, params, now, tracker) =>
                evaluateCumulativeLimit(
                    scope as CumulativeLimitScope,
                    params,
                    now,
                    tracker,
                ),
        );
    }

    public async evaluate(
        scope: Scope,
        params: Record<string, unknown>,
        now?: Date,
    ): Promise<ScopeEvaluationResult> {
        const effectiveNow = now ?? new Date();

        // Check built-in types first
        let fn = this.#evaluators.get(scope.type);

        // On a built-in type miss, query the plugin registry (DSL extension point)
        if (!fn) {
            fn = this.#registry.get(scope.type);
        }

        if (!fn) {
            return {
                allowed: false,
                reason: `Unknown scope type: ${scope.type}`,
            };
        }
        return await fn(scope, params, effectiveNow, this.tracker);
    }

    public async evaluateAll(
        scopes: Scope[],
        params: Record<string, unknown>,
        now?: Date,
    ): Promise<ScopeEvaluationResult> {
        for (const scope of scopes) {
            const result = await this.evaluate(scope, params, now);
            if (!result.allowed) {
                return result;
            }
        }

        return { allowed: true };
    }

    /**
     * Register an evaluator on the current ScopeEvaluator instance (instance-level, does not affect
     * the global registry).
     *
     * Security constraint: registration of built-in types is rejected (consistent with
     * ScopeEvaluatorRegistry behavior). For global registration, use
     * globalScopeEvaluatorRegistry.register().
     *
     * @deprecated Prefer ScopeEvaluatorRegistry.register() for global registration.
     *             Instance-level registration is provided only for backward compatibility and special use cases.
     */
    public registerScopeEvaluator(type: string, fn: EvaluatorFn): void {
        if (BUILT_IN_SCOPE_TYPES.has(type)) {
            throw new Error(
                `ScopeEvaluator.registerScopeEvaluator: type "${type}" conflicts with built-in scope type and cannot be overridden.`,
            );
        }
        this.#evaluators.set(type, fn);
    }
}

function evaluateAllowlist(
    field: string,
    values: string[],
    params: Record<string, unknown>,
): ScopeEvaluationResult {
    if (values.length === 0) {
        return {
            allowed: false,
            reason: `${field} allowlist is empty`,
        };
    }

    const actualValue = params[field];
    if (typeof actualValue !== 'string') {
        return {
            allowed: false,
            reason: `${field} is missing or not a string`,
        };
    }

    const matches = values.some((candidate) =>
        matchAllowlistValue(actualValue, candidate),
    );
    return matches
        ? { allowed: true }
        : {
              allowed: false,
              reason: `${field} is not in the allowlist`,
          };
}

function evaluateNumericLimit(
    field: string,
    max: number,
    params: Record<string, unknown>,
): ScopeEvaluationResult {
    const actualValue = params[field];

    if (actualValue === undefined || actualValue === null) {
        return { allowed: true };
    }

    if (typeof actualValue !== 'number' || Number.isNaN(actualValue)) {
        return {
            allowed: false,
            reason: `${field} is not a number`,
        };
    }

    return actualValue <= max
        ? { allowed: true }
        : {
              allowed: false,
              reason: `${field} exceeds max ${max}`,
          };
}

export function evaluateTemporalScope(
    scope: TemporalScope,
    now: Date,
): ScopeEvaluationResult {
    const nowMs = now.getTime();

    if (nowMs < new Date(scope.notBefore).getTime()) {
        return {
            allowed: false,
            reason: 'temporal_scope: not yet active (before notBefore)',
        };
    }
    if (nowMs >= new Date(scope.notAfter).getTime()) {
        return {
            allowed: false,
            reason: 'temporal_scope: expired (at or after notAfter)',
        };
    }

    if (!scope.recurringWindow) {
        return { allowed: true };
    }

    return evaluateRecurringWindow(scope.recurringWindow, now);
}

function evaluateRecurringWindow(
    rw: RecurringWindow,
    now: Date,
): ScopeEvaluationResult {
    // Strictly validate the HH:MM format (hour 00-23, minute 00-59)
    const HH_MM = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;
    if (!HH_MM.test(rw.startTime) || !HH_MM.test(rw.endTime)) {
        return {
            allowed: false,
            reason: 'temporal_scope: invalid time format',
        };
    }

    let fmtTime: Intl.DateTimeFormat;
    let fmtDay: Intl.DateTimeFormat;
    try {
        fmtTime = new Intl.DateTimeFormat('en-CA', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: false,
            timeZone: rw.timezone,
        });
        fmtDay = new Intl.DateTimeFormat('en-CA', {
            weekday: 'short',
            timeZone: rw.timezone,
        });
    } catch {
        return {
            allowed: false,
            reason: 'temporal_scope: invalid timezone',
        };
    }

    // A successful Intl construction does not mean the timezone is a canonical IANA name (aliases
    // such as CST/EST get silently aliased away).
    // If resolvedOptions().timeZone differs from the input, the input was an alias and must be rejected.
    if (fmtTime.resolvedOptions().timeZone !== rw.timezone) {
        return {
            allowed: false,
            reason: 'temporal_scope: invalid timezone',
        };
    }

    const localHHMM = fmtTime.format(now); // "HH:MM"
    const localWeekday = fmtDay.format(now); // "Mon","Tue",...

    const isoDay = weekdayToISO(localWeekday); // 1=Monday,...,7=Sunday

    // Cross-midnight check
    const crossesMidnight = rw.startTime > rw.endTime;

    const inWindow = crossesMidnight
        ? localHHMM >= rw.startTime || localHHMM < rw.endTime
        : localHHMM >= rw.startTime && localHHMM < rw.endTime;

    if (!inWindow) {
        return {
            allowed: false,
            reason: 'temporal_scope: outside recurring window (time)',
        };
    }

    // An explicitly provided empty array → reject all days of week (rather than skipping the check)
    if (rw.daysOfWeek !== undefined) {
        // Cross-midnight day attribution rule: the after-midnight segment is attributed to the previous day
        let effectiveDay = isoDay;
        if (crossesMidnight && localHHMM < rw.endTime) {
            effectiveDay = isoDay === 1 ? 7 : isoDay - 1;
        }

        if (!rw.daysOfWeek.includes(effectiveDay)) {
            return {
                allowed: false,
                reason: 'temporal_scope: outside recurring window (day of week)',
            };
        }
    }

    return { allowed: true };
}

// Map the abbreviated English weekday to its ISO 8601 number (1=Monday, 7=Sunday)
function weekdayToISO(weekday: string): number {
    const map: Record<string, number> = {
        Mon: 1,
        Tue: 2,
        Wed: 3,
        Thu: 4,
        Fri: 5,
        Sat: 6,
        Sun: 7,
    };
    const day = map[weekday];
    if (day === undefined) {
        throw new Error(`unexpected weekday: ${weekday}`);
    }
    return day;
}

function matchAllowlistValue(actualValue: string, candidate: string): boolean {
    if (candidate.startsWith('*') && candidate.length > 1) {
        return actualValue.endsWith(candidate.slice(1));
    }

    return actualValue === candidate;
}

export async function evaluateScope(
    scope: Scope,
    params: Record<string, unknown>,
): Promise<ScopeEvaluationResult> {
    return new ScopeEvaluator().evaluate(scope, params);
}

async function evaluateCumulativeLimit(
    scope: CumulativeLimitScope,
    params: Record<string, unknown>,
    now: Date,
    tracker: CumulativeTracker | undefined,
): Promise<ScopeEvaluationResult> {
    if (!tracker) {
        return {
            allowed: false,
            reason: 'cumulative_limit: no CumulativeTracker injected',
        };
    }

    // MeterFieldRef.source tri-state fail-closed
    // Only the 'action_record' evaluator is implemented; 'external_witness' / 'consensus_meter'
    // are implemented by ExternalWitnessEvaluator (still a stub), and are rejected directly here to
    // avoid reaching the ActionRecord ledger path, consistent with the scope-extensions spec
    // fail-closed requirement
    if (scope.meterField.source !== 'action_record') {
        return {
            allowed: false,
            reason: `cumulative_limit: METRIC_SOURCE_NOT_IMPLEMENTED — source='${scope.meterField.source}' evaluator not implemented (fail-closed)`,
        };
    }

    const entry = METER_FIELD_REGISTRY[scope.meterField.metric];
    if (!entry) {
        return {
            allowed: false,
            reason: `cumulative_limit: unregistered meter field: ${scope.meterField.metric}`,
        };
    }

    const windowStart = computeWindowStart(scope.window, now);
    // Workaround: agentDid / recordId are injected into params by RuntimeGuard
    // TODO: replace with a typed EvaluationContext parameter.
    const agentDid = (params['__agentDid'] as DID | undefined) ?? ('' as DID);
    const recordId = (params['__recordId'] as string | undefined) ?? '';

    // Determine reserveAmount (the amount reserved during the check-and-reserve phase)
    let reserveAmount: number;
    if (entry.aggregation === 'COUNT') {
        reserveAmount = 1;
    } else {
        const raw = params[entry.requestField!];
        if (typeof raw !== 'number' || Number.isNaN(raw)) {
            return {
                allowed: false,
                reason: `cumulative_limit: cannot extract meter value '${entry.requestField}' from params for metric '${scope.meterField.metric}'`,
            };
        }
        reserveAmount = raw;
    }

    // Atomic check-and-reserve (replaces the TOCTOU-prone getCumulativeValue path)
    // tracker.checkAndReserve, within a single DB transaction, takes an advisory lock, queries the
    // cumulative total (including PENDING reservation rows), checks for overrun, and writes a PENDING
    // reservation row, ensuring concurrent requests never read the same baseline at the same time.
    const reserveResult = await tracker.checkAndReserve(
        recordId,
        agentDid,
        scope.meterField,
        windowStart,
        now,
        scope.max,
        reserveAmount,
    );

    if (!reserveResult.allowed) {
        const projected = reserveResult.currentCumulative + reserveAmount;
        return {
            allowed: false,
            reason: `cumulative_limit exceeded: ${reserveResult.currentCumulative} + ${reserveAmount} = ${projected} > ${scope.max} (window: ${scope.window})`,
        };
    }

    return { allowed: true };
}
