interface RefreshSession {
    sessionId: string;
    familyId: string;
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
    revokedAt: Date | null;
    /**
     * Hard upper bound on the lifetime of the whole refresh-token family.
     * Only present when `absoluteSessionExpiry` is configured; adapters
     * that do not persist it simply lose the absolute limit.
     */
    absoluteExpiresAt?: Date;
}

interface User {
    id: string;
    email: string;
}
interface UserRecord extends User {
    passwordHash: string;
}
interface CreateUser {
    email: string;
    passwordHash: string;
}
interface UserAdapter {
    findUserByEmail(email: string): Promise<UserRecord | null>;
    createUser(data: CreateUser): Promise<UserRecord>;
    findUserById(userId: string): Promise<UserRecord | null>;
}
interface RefreshTokenAdapter {
    findSessionByTokenHash(refreshTokenHash: string): Promise<RefreshSession | null>;
    revokeSession(sessionId: string): Promise<void>;
    createSession(session: RefreshSession): Promise<RefreshSession>;
    revokeFamily(familyId: string): Promise<void>;
    /**
     * Required when `refreshTokenGracePeriod` is configured. Used to confirm
     * that a family is still healthy before tolerating a concurrent refresh.
     */
    findSessionsByFamilyId?(familyId: string): Promise<RefreshSession[]>;
}

type Hook<T> = (data: T) => void | Promise<void>;
interface AuthHooks {
    beforeLogin?: Hook<User>;
    afterLogin?: Hook<User>;
    beforeSignUp?: Hook<SignUpHookData>;
    afterSignUp?: Hook<User>;
}
interface SignUpHookData {
    email: string;
}

interface AuthConfig {
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
interface SignUpData {
    email: string;
    password: string;
}
interface LoginData {
    email: string;
    password: string;
}
interface AuthResult {
    user: User;
    token: string;
    refreshToken: string;
}

interface AuthOptions {
    adapter: UserAdapter;
    refreshTokenAdapter: RefreshTokenAdapter;
    secret: string;
    tokenExpiry: string;
    /** Milliseconds. */
    refreshTokenExpiryMs: number;
    /** Milliseconds, or null when disabled. */
    absoluteSessionExpiryMs: number | null;
    /** Milliseconds, 0 when disabled. */
    refreshTokenGracePeriodMs: number;
    normalizeEmail: boolean | ((email: string) => string);
    hooks?: AuthHooks;
}
declare class Auth {
    private adapter;
    private secret;
    private expiry;
    private refreshTokenAdapter;
    private refreshTokenExpiryMs;
    private absoluteSessionExpiryMs;
    private refreshTokenGracePeriodMs;
    private emailNormalizer;
    private hooks?;
    private dummyHash?;
    constructor(options: AuthOptions);
    signUp(data: SignUpData): Promise<User>;
    login(data: LoginData): Promise<AuthResult>;
    authenticate(token: string): Promise<User>;
    refresh(refreshToken: string): Promise<AuthResult>;
    /**
     * Creates and stores a new refresh session in `familyId` and returns the
     * raw refresh token. `expiresAt` is capped by `absoluteExpiresAt`.
     */
    private issueSession;
    /**
     * A revoked session presented within the grace period counts as a
     * concurrent refresh (two clients racing with the same token) rather
     * than reuse, but only while the family still has a live session. A
     * family that was revoked outright has none, so its tokens stay dead.
     */
    private isConcurrentRefresh;
    private normalizeEmail;
    private getDummyHash;
}

type AuthErrorCode = "USER_ALREADY_EXISTS" | "INVALID_CREDENTIALS" | "AUTHENTICATION_FAILED";
declare class AuthError extends Error {
    code: AuthErrorCode;
    constructor(message: string, code: AuthErrorCode);
}

declare function createAuth(config: AuthConfig): Auth;

export { type AuthConfig, AuthError, type AuthErrorCode, type AuthHooks, type AuthResult, type CreateUser, type LoginData, type RefreshSession, type RefreshTokenAdapter, type SignUpData, type SignUpHookData, type User, type UserAdapter, type UserRecord, createAuth };
