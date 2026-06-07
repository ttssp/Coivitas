import cors, { type CorsOptions } from 'cors';
import express, { type Application } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

import { errorHandler, requestLogger } from './middleware/index.js';

export interface CreateAppConfig {
    corsOrigins?: string[];
    bodySizeLimit?: string;
}

export function createApp(config: CreateAppConfig = {}): Application {
    const app = express();
    const apiRouter = express.Router();
    const corsOptions = createCorsOptions(config.corsOrigins);
    const originalUse = app.use.bind(app);

    app.use(express.json({ limit: config.bodySizeLimit ?? '1mb' }));
    app.use(requestLogger);
    app.use(cors(corsOptions));
    app.use(helmet());
    app.use(
        rateLimit({
            limit: 100,
            windowMs: 60_000,
            standardHeaders: 'draft-8',
            legacyHeaders: false,
            handler(_request, response) {
                response.status(429).json({
                    error: {
                        code: 'RATE_LIMIT_EXCEEDED',
                        message: 'Too many requests',
                    },
                });
            },
        }),
    );

    app.get('/health', (_request, response) => {
        response.status(200).json({ status: 'ok' });
    });

    originalUse(apiRouter);
    originalUse(errorHandler);
    mountRouterApi(app, apiRouter);

    return app;
}

function mountRouterApi(
    app: Application,
    apiRouter: ReturnType<typeof express.Router>,
): void {
    app.use = ((...args: Parameters<Application['use']>) => {
        apiRouter.use(...args);
        return app;
    }) as Application['use'];

    app.route = ((...args: Parameters<Application['route']>) =>
        apiRouter.route(...args)) as Application['route'];

    for (const method of [
        'all',
        'delete',
        'head',
        'options',
        'patch',
        'post',
        'put',
    ] as const) {
        app[method] = ((...args: Parameters<Application[typeof method]>) => {
            apiRouter[method](...args);
            return app;
        }) as Application[typeof method];
    }

    const originalGet = app.get.bind(app);
    app.get = ((...args: Parameters<Application['get']>) => {
        const runtimeArgs = args as unknown[];

        if (runtimeArgs.length === 1 && typeof runtimeArgs[0] === 'string') {
            const setting = originalGet(runtimeArgs[0]) as ReturnType<
                Application['get']
            >;
            return setting;
        }

        apiRouter.get(...args);
        return app;
    }) as Application['get'];
}

function createCorsOptions(corsOrigins?: string[]): CorsOptions {
    if (!corsOrigins || corsOrigins.length === 0) {
        return {};
    }

    return {
        origin(origin, callback) {
            if (!origin || corsOrigins.includes(origin)) {
                callback(null, true);
                return;
            }

            callback(new Error(`Origin ${origin} is not allowed by CORS`));
        },
    };
}
