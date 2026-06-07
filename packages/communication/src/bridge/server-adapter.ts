/**
 * MCP Bridge — server adapter
 *
 * This file = the MCP server transport adapter + lifecycle implementation.
 * Integrates @modelcontextprotocol/sdk v1.29.0:
 * - the low-level `Server` API + `setRequestHandler` (avoids high-level zod shape inference noise;
 *   keeps full control over the `tools/list` / `tools/call` handler paths — so later injecting binding lookup +
 *   envelope wrapping does not require bypassing the SDK's input schema validation)
 * - `StdioServerTransport` (local agent mode)
 * - `StreamableHTTPServerTransport` (HTTP mode; corresponds to outbox / streaming flows)
 *
 * This file does **not** implement:
 * - the holder binding registration flow (PoP credential deferred to a later release)
 * - the MCP → AP envelope conversion
 * - outbox / scope validator
 * - cross-hop authority transition (the fail-closed implementation is wired in later)
 *
 * This file **implements**:
 * - `MCPServerAdapter`: the lifecycle state machine (created→starting→running→stopping→stopped)
 * - tool registration + dispatch (tools/list + tools/call go through setRequestHandler)
 * - http / stdio transport selection + startup + shutdown
 *
 * Design principles:
 * 1. the lifecycle is strictly idempotent — start when running = noop; stop when stopped = noop
 * 2. start fail → state='error'; partial running is not allowed (fail-closed)
 * 3. tool registration must happen before start; registering after start throws (race prevention)
 * 4. transport decoupling — the adapter holds the SDK instance + state; the transport is decided by config
 */

import { createServer, type Server as NodeHttpServer } from 'node:http';

import { Server as McpSdkServer } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Transport as SdkTransport } from '@modelcontextprotocol/sdk/shared/transport.js';
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
    type CallToolRequest,
    type CallToolResult,
    type ListToolsResult,
} from '@modelcontextprotocol/sdk/types.js';

import {
    MCP_ERROR,
    type MCPBridgeError,
    type MCPCallParams,
    type MCPServerConfig,
    type MCPServerLifecycle,
    type MCPServerLifecycleState,
    type MCPToolDescriptor,
    type MCPToolHandler,
    makeMcpError,
} from './types.js';

// ─── lifecycle implementation ────────────────────────────────────────────────

/**
 * MCPServerAdapter — lifecycle implementation
 *
 * Usage:
 *   const adapter = new MCPServerAdapter({
 *     serverId: 'srv-1',
 *     serverDid: 'did:agent:...',
 *     transport: 'http',
 *     http: { port: 0 },
 *   });
 *   adapter.registerTool({ name: 'echo', handler: async (params) => ({ ok: true, result: params.arguments }) });
 *   await adapter.start();
 *   // ... server running ...
 *   await adapter.stop();
 *
 * Later, dispatchTool's wrapping will be extended: before calling the user handler, first do
 * binding lookup + envelope conversion + cross-hop fail-closed;
 * and the outbox + scope validator sync will be extended too.
 */
export class MCPServerAdapter implements MCPServerLifecycle {
    private _state: MCPServerLifecycleState = 'created';
    private readonly _config: MCPServerConfig;
    private readonly _tools: Map<string, MCPToolDescriptor> = new Map();
    private _mcpServer: McpSdkServer | null = null;
    private _sdkTransport: SdkTransport | null = null;
    private _httpServer: NodeHttpServer | null = null;
    /** the port actually bound after http listen (used in tests for the port=0 auto-allocation scenario) */
    private _resolvedPort: number | null = null;

    constructor(config: MCPServerConfig) {
        validateConfig(config);
        this._config = config;
    }

    get state(): MCPServerLifecycleState {
        return this._state;
    }

    get config(): MCPServerConfig {
        return this._config;
    }

    /** non-null only when transport='http' and after start completes; for tests */
    get resolvedPort(): number | null {
        return this._resolvedPort;
    }

    /** Register an MCP tool (must be called before start) */
    registerTool(descriptor: MCPToolDescriptor): void {
        if (this._state !== 'created') {
            throw new Error(
                `[MCPServerAdapter] cannot registerTool when state=${this._state}; tool registration must be done before start()`,
            );
        }
        if (!descriptor.name || typeof descriptor.handler !== 'function') {
            throw new Error(
                `[MCPServerAdapter] invalid tool descriptor: missing name or handler`,
            );
        }
        if (this._tools.has(descriptor.name)) {
            throw new Error(
                `[MCPServerAdapter] tool '${descriptor.name}' already registered`,
            );
        }
        this._tools.set(descriptor.name, descriptor);
    }

    /** List registered tools (test helper; non-normative) */
    listTools(): readonly MCPToolDescriptor[] {
        return Array.from(this._tools.values());
    }

    async start(): Promise<void> {
        // idempotent: noop while running
        if (this._state === 'running') return;
        if (this._state === 'stopped' || this._state === 'error') {
            throw new Error(
                `[MCPServerAdapter] cannot start from terminal state=${this._state}; create a new adapter instance`,
            );
        }
        if (this._state !== 'created') {
            throw new Error(
                `[MCPServerAdapter] cannot start from state=${this._state}`,
            );
        }

        this._state = 'starting';

        try {
            // 1. construct the SDK Server (low-level)
            this._mcpServer = new McpSdkServer(
                {
                    name:
                        this._config.serverName ?? 'coivitas-mcp-bridge',
                    version: this._config.serverVersion ?? '0.2.0',
                },
                {
                    capabilities: {
                        tools: {},
                    },
                },
            );

            // 2. register the request handlers — tools/list + tools/call
            this._mcpServer.setRequestHandler(
                ListToolsRequestSchema,
                (): Promise<ListToolsResult> => {
                    return Promise.resolve({
                        tools: Array.from(this._tools.values()).map((t) => {
                            // SDK ListToolsResult.tools[].inputSchema requires the type='object' literal
                            const baseSchema: {
                                type: 'object';
                                properties?: Record<string, object>;
                                required?: string[];
                                [k: string]: unknown;
                            } = {
                                type: 'object',
                                additionalProperties: true,
                            };
                            const inputSchema =
                                t.inputSchema &&
                                typeof t.inputSchema === 'object'
                                    ? {
                                          ...baseSchema,
                                          ...t.inputSchema,
                                          type: 'object' as const,
                                      }
                                    : baseSchema;
                            return {
                                name: t.name,
                                description: t.description ?? `tool ${t.name}`,
                                inputSchema,
                            };
                        }),
                    });
                },
            );

            this._mcpServer.setRequestHandler(
                CallToolRequestSchema,
                async (request: CallToolRequest): Promise<CallToolResult> => {
                    return this._dispatchTool(request);
                },
            );

            // 3. construct the transport
            if (this._config.transport === 'stdio') {
                this._sdkTransport = new StdioServerTransport();
                await this._mcpServer.connect(this._sdkTransport);
            } else if (this._config.transport === 'http') {
                if (!this._config.http) {
                    throw new Error(
                        `[MCPServerAdapter] transport='http' but config.http missing`,
                    );
                }
                const httpTransport = new StreamableHTTPServerTransport({
                    sessionIdGenerator: undefined, // stateless mode; session audit is handled by the outbox; the transport layer stays stateless
                });
                await this._mcpServer.connect(httpTransport);
                this._sdkTransport = httpTransport;

                const host = this._config.http.host ?? '127.0.0.1';
                const port = this._config.http.port;
                const httpServer = createServer((req, res) => {
                    void this._handleHttpRequest(req, res, httpTransport);
                });
                await new Promise<void>((resolve, reject) => {
                    const onError = (err: Error) => {
                        httpServer.removeListener('listening', onListening);
                        reject(err);
                    };
                    const onListening = () => {
                        httpServer.removeListener('error', onError);
                        const addr = httpServer.address();
                        if (addr && typeof addr === 'object') {
                            this._resolvedPort = addr.port;
                        }
                        resolve();
                    };
                    httpServer.once('error', onError);
                    httpServer.once('listening', onListening);
                    httpServer.listen(port, host);
                });
                this._httpServer = httpServer;
            } else {
                throw new Error(
                    `[MCPServerAdapter] unknown transport mode: ${
                        (this._config as { transport: string }).transport
                    }`,
                );
            }

            this._state = 'running';
        } catch (err) {
            await this._silentCleanup();
            this._state = 'error';
            throw err;
        }
    }

    async stop(): Promise<void> {
        if (
            this._state === 'stopped' ||
            this._state === 'created' ||
            this._state === 'error'
        ) {
            return;
        }

        this._state = 'stopping';
        try {
            await this._silentCleanup();
            this._state = 'stopped';
        } catch (err) {
            this._state = 'error';
            throw err;
        }
    }

    /**
     * tools/call dispatcher — finds the registered tool and calls its handler;
     * converts MCPBridgeError → SDK CallToolResult;
     * later, binding lookup + envelope wrapping + scope validator will be inserted here.
     */
    private async _dispatchTool(
        request: CallToolRequest,
    ): Promise<CallToolResult> {
        const toolName = request.params.name;
        const args = (request.params.arguments ?? {}) as Record<
            string,
            unknown
        >;

        const descriptor = this._tools.get(toolName);
        if (!descriptor) {
            const err: MCPBridgeError = makeMcpError(
                MCP_ERROR.SETTLEMENT_FAILED,
                'TOOL_NOT_FOUND',
                `tool '${toolName}' not registered`,
            );
            return errorToCallToolResult(err);
        }

        // construct MCPCallParams (a binding lookup guard will later be inserted before this)
        const params: MCPCallParams = {
            tool: toolName,
            arguments: args as MCPCallParams['arguments'],
        };

        let result: Awaited<ReturnType<MCPToolHandler>>;
        try {
            result = await descriptor.handler(params);
        } catch (err) {
            // handler throws → convert to settlement_failed (fail-closed)
            const e: MCPBridgeError = makeMcpError(
                MCP_ERROR.SETTLEMENT_FAILED,
                'HANDLER_THREW',
                err instanceof Error
                    ? err.message
                    : 'tool handler threw non-Error',
            );
            return errorToCallToolResult(e);
        }

        if (result.ok) {
            return {
                content: [
                    {
                        type: 'text',
                        text:
                            typeof result.result === 'string'
                                ? result.result
                                : JSON.stringify(result.result),
                    },
                ],
            };
        } else {
            return errorToCallToolResult(result.error);
        }
    }

    /**
     * HTTP request routing — only accepts POST /mcp or POST / to the transport
     */
    private async _handleHttpRequest(
        req: import('node:http').IncomingMessage,
        res: import('node:http').ServerResponse,
        transport: StreamableHTTPServerTransport,
    ): Promise<void> {
        try {
            if (
                req.method === 'POST' &&
                (req.url === '/mcp' || req.url === '/' || req.url === undefined)
            ) {
                const body = await readBodyJson(req);
                await transport.handleRequest(req, res, body);
            } else {
                res.statusCode = 404;
                res.end();
            }
        } catch (err) {
            if (!res.headersSent) {
                res.statusCode = 500;
                res.setHeader('content-type', 'application/json');
                res.end(
                    JSON.stringify({
                        error: 'mcp_bridge_internal_error',
                        message: err instanceof Error ? err.message : 'unknown',
                    }),
                );
            }
        }
    }

    /**
     * Clean up the SDK instance + transport + http server (does not throw; the caller decides the state transition)
     */
    private async _silentCleanup(): Promise<void> {
        if (this._mcpServer) {
            try {
                await this._mcpServer.close();
            } catch {
                // ignore; best-effort cleanup
            }
            this._mcpServer = null;
        }
        if (this._httpServer) {
            await new Promise<void>((resolve) => {
                this._httpServer!.close(() => resolve());
            });
            this._httpServer = null;
        }
        this._sdkTransport = null;
        this._resolvedPort = null;
    }
}

// ─── helper: error → CallToolResult ──────────────────────────────────────────

function errorToCallToolResult(err: MCPBridgeError): CallToolResult {
    return {
        content: [
            {
                type: 'text',
                text: JSON.stringify({
                    mcp_code: err.mcp_code,
                    internal_code: err.internal_code,
                    message: err.message,
                }),
            },
        ],
        isError: true,
    };
}

// ─── helper: HTTP body parsing ───────────────────────────────────────────────

async function readBodyJson(
    req: import('node:http').IncomingMessage,
): Promise<unknown> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
        chunks.push(chunk as Buffer);
    }
    if (chunks.length === 0) return undefined;
    const body = Buffer.concat(chunks).toString('utf8');
    if (body.length === 0) return undefined;
    return JSON.parse(body);
}

// ─── helper: config validation (fail-closed) ─────────────────────────────────

function validateConfig(config: MCPServerConfig): void {
    if (!config.serverId || typeof config.serverId !== 'string') {
        throw new Error('[MCPServerAdapter] serverId required');
    }
    if (!config.serverDid || typeof config.serverDid !== 'string') {
        throw new Error('[MCPServerAdapter] serverDid required');
    }
    if (config.transport !== 'http' && config.transport !== 'stdio') {
        throw new Error(
            `[MCPServerAdapter] unknown transport: ${
                (config as { transport: string }).transport
            }`,
        );
    }
    if (config.transport === 'http') {
        if (!config.http || typeof config.http.port !== 'number') {
            throw new Error(
                '[MCPServerAdapter] transport=http requires config.http.port',
            );
        }
        if (
            !Number.isInteger(config.http.port) ||
            config.http.port < 0 ||
            config.http.port > 65535
        ) {
            throw new Error(
                `[MCPServerAdapter] invalid port ${config.http.port}`,
            );
        }
    }
}

// ─── default fallback handler (for tests / unrecognized tool) ──────────────────

/**
 * Default fallback handler — returns an unsupported error when the tool is unrecognized
 *
 * Once the envelope flow is entered, this fallback is inlined inside dispatchTool.
 */
export const defaultFallbackHandler: MCPToolHandler = (
    params,
): Promise<{ ok: false; error: MCPBridgeError }> => {
    return Promise.resolve({
        ok: false as const,
        error: makeMcpError(
            MCP_ERROR.SETTLEMENT_FAILED,
            'TOOL_UNSUPPORTED',
            `tool '${params.tool}' not supported by this MCP bridge instance`,
        ),
    });
};
