import type { User } from "./adapter.js";

type Hook<T> = (data: T) => void | Promise<void>;

export interface SignUpHookData {
    email: string;
}

export interface LoginFailedHookData {
    email: string;
    reason: "USER_NOT_FOUND" | "INVALID_PASSWORD";
}

export interface ReuseDetectedHookData {
    userId: string;
    familyId: string;
    /** The already-revoked session whose token was presented. */
    sessionId: string;
}

/**
 * `before*` hooks run before the operation and abort it by throwing.
 * `after*` and `on*` hooks run for side effects; if they throw, the error
 * is logged and the operation's result is still returned.
 */
export interface AuthHooks {
    beforeSignUp?: Hook<SignUpHookData>;
    afterSignUp?: Hook<User>;

    beforeLogin?: Hook<User>;
    afterLogin?: Hook<User>;
    /** A login attempt was rejected. Useful for rate limiting and lockout. */
    onLoginFailed?: Hook<LoginFailedHookData>;

    /** Runs after the refresh token is validated and before it is rotated. */
    beforeRefresh?: Hook<User>;
    afterRefresh?: Hook<User>;
    /** A revoked refresh token was presented and its family has been revoked. */
    onReuseDetected?: Hook<ReuseDetectedHookData>;

    afterPasswordChange?: Hook<User>;
}
