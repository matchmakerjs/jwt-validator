export type ErrorSender = (
    statusCode: number,
    response: unknown
) => void;
