export interface PlaceholderCommandContext {
    commandPath: string;
    summary: string;
    args: Record<string, string | boolean | undefined>;
}

export const createPlaceholderHandler =
    (commandPath: string, summary: string) =>
    (args: Record<string, string | boolean | undefined>): void => {
        const payload: PlaceholderCommandContext = {
            commandPath,
            summary,
            args,
        };

        console.log(`[placeholder] ${payload.commandPath}: ${payload.summary}`);

        if (Object.keys(payload.args).length > 0) {
            console.log(JSON.stringify(payload.args, null, 2));
        }
    };
