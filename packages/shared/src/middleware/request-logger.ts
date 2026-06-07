import type { NextFunction, Request, Response } from 'express';

export function requestLogger(
    request: Request,
    response: Response,
    next: NextFunction,
): void {
    const startedAt = process.hrtime.bigint();

    response.on('finish', () => {
        const durationMs =
            Number(process.hrtime.bigint() - startedAt) / 1_000_000;
        console.info(
            `${request.method} ${request.originalUrl} ${response.statusCode} ${durationMs.toFixed(2)}ms`,
        );
    });

    next();
}
