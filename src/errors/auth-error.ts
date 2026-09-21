
export type AuthErrorCode =
    | "USER_ALREADY_EXISTS"
    | "USER_NOT_FOUND"
    | "INVALID_CREDENTIALS"
    | "INVALID_INPUT"
    | "AUTHENTICATION_FAILED";

/**
 * Fine-grained cause of an `AUTHENTICATION_FAILED` error. `code` stays
 * coarse so existing handlers keep working; switch on `reason` when you
 * need to tell, say, an expired access token from a tampered one.
 */
export type AuthErrorReason =
    | "TOKEN_INVALID"
    | "TOKEN_EXPIRED"
    | "REFRESH_TOKEN_INVALID"
    | "REFRESH_TOKEN_EXPIRED"
    | "REFRESH_TOKEN_REUSED"
    | "SESSION_EXPIRED"
    | "USER_NOT_FOUND";

export interface AuthErrorOptions {
    reason?: AuthErrorReason;
    cause?: unknown;
}

export class AuthError extends Error {
    public code: AuthErrorCode;
    public reason?: AuthErrorReason;

    constructor(message: string, code: AuthErrorCode, options: AuthErrorOptions = {}) {
        super(message, options.cause === undefined ? undefined : { cause: options.cause });
        this.name = "AuthError";
        this.code = code;
        if (options.reason !== undefined) this.reason = options.reason;
    }
}
