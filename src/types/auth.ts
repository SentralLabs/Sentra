import type { User, UserAdapter,RefreshTokenAdapter } from "./adapter.js";
import type { AuthHooks } from "./hooks.js";

export interface AuthConfig{
    adapter: UserAdapter;
    refreshTokenAdapter: RefreshTokenAdapter;
    secret: string;
    /** Access token lifetime, e.g. "15m", "1h", "7d". Defaults to "7d". */
    tokenExpiry?: string;
    /** Sliding refresh token lifetime, renewed on every refresh. Defaults to "30d". */
    refreshTokenExpiry?: string;
    /**
     * Hard cap on how long a login session can be kept alive by refreshing,
     * e.g. "90d". Disabled when omitted.
     */
    absoluteSessionExpiry?: string;
    /**
     * Window after a refresh token is rotated during which presenting the
     * old token again is treated as a concurrent legitimate refresh rather
     * than reuse, e.g. "10s". Requires `refreshTokenAdapter.findSessionsByFamilyId`.
     * Disabled when omitted.
     */
    refreshTokenGracePeriod?: string;
    /**
     * How emails are normalised before lookup and storage. `true` (default)
     * trims and lowercases; `false` uses the email verbatim; a function
     * supplies custom normalisation.
     */
    normalizeEmail?: boolean | ((email: string) => string);
    hooks?: AuthHooks;
}

export interface SignUpData{
    email: string;
    password: string;
}

export interface LoginData{
    email: string;
    password: string;
}  

export interface AuthResult{
    user: User;
    token: string;
    refreshToken: string;
}
