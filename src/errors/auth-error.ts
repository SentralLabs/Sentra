
export type AuthErrorCode =
    | "USER_ALREADY_EXISTS"
    | "USER_NOT_FOUND"
    | "INVALID_CREDENTIALS"
    | "INVALID_INPUT"
    | "INVALID_TOKEN"
    | "EMAIL_NOT_VERIFIED"
    | "AUTHENTICATION_FAILED";

/**
 * Fine-grained cause of an `AUTHENTICATION_FAILED` or `INVALID_TOKEN`
 * error. `code` stays coarse so existing handlers keep working; switch on
 * `reason` when you need to tell, say, an expired token from a tampered one.
 */
export type AuthErrorReason =
    | "TOKEN_INVALID"
    | "TOKEN_EXPIRED"
    | "REFRESH_TOKEN_INVALID"
    | "REFRESH_TOKEN_EXPIRED"
    | "REFRESH_TOKEN_REUSED"
    | "SESSION_EXPIRED"
    | "USER_NOT_FOUND"
    | "RESET_TOKEN_INVALID"
    | "RESET_TOKEN_EXPIRED"
    | "VERIFICATION_TOKEN_INVALID"
    | "VERIFICATION_TOKEN_EXPIRED";

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
