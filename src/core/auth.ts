import { AuthError } from "../errors/auth-error.js";
import { generateRefreshToken, hashRefreshToken } from "../jwt/refresh-token.js";
import { createToken, verifyToken } from "../jwt/token.js";
import type { JwtOptions, TokenPayload } from "../jwt/token.js";
import { ActionTokenError, createActionToken, deriveActionKey, peekActionToken, verifyActionToken } from "../jwt/action-token.js";
import type { ActionTokenPurpose } from "../jwt/action-token.js";
import type { UserAdapter, User, RefreshTokenAdapter, UserRecord } from "../types/adapter.js";
import type { AuthResult, ChangePasswordData, LoginData, Logger, SignUpData } from "../types/auth.js";
import type { RefreshSession } from "../types/session.js";
import type { PasswordHasher } from "../password/hasher.js";
import { randomBytes } from "node:crypto";
import type { AuthHooks, DeliveryHookData } from "../types/hooks.js";

export interface AuthOptions {
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
    passwordResetExpiry: string;
    emailVerificationExpiry: string;
    requireEmailVerification: boolean;
    jwt: JwtOptions;
    passwordHasher: PasswordHasher;
    logger: Logger;
    hooks?: AuthHooks;
}

class Auth {
    private adapter: UserAdapter;
    private secret: string;
    private expiry: string;
    private refreshTokenAdapter: RefreshTokenAdapter;
    private refreshTokenExpiryMs: number;
    private absoluteSessionExpiryMs: number | null;
    private refreshTokenGracePeriodMs: number;
    private emailNormalizer: boolean | ((email: string) => string);
    private passwordResetExpiry: string;
    private emailVerificationExpiry: string;
    private requireEmailVerification: boolean;
    private jwt: JwtOptions;
    private hasher: PasswordHasher;
    private logger: Logger;
    private hooks?: AuthHooks;
    private dummyHash?: string;

    constructor(options: AuthOptions) {
        this.adapter = options.adapter;
        this.secret = options.secret;
        this.expiry = options.tokenExpiry;
        this.refreshTokenAdapter = options.refreshTokenAdapter;
        this.refreshTokenExpiryMs = options.refreshTokenExpiryMs;
        this.absoluteSessionExpiryMs = options.absoluteSessionExpiryMs;
        this.refreshTokenGracePeriodMs = options.refreshTokenGracePeriodMs;
        this.emailNormalizer = options.normalizeEmail;
        this.passwordResetExpiry = options.passwordResetExpiry;
        this.emailVerificationExpiry = options.emailVerificationExpiry;
        this.requireEmailVerification = options.requireEmailVerification;
        this.jwt = options.jwt;
        this.hasher = options.passwordHasher;
        this.logger = options.logger;
        this.hooks = options.hooks;
    }

    async signUp(data: SignUpData): Promise<User> {

        const email = this.normalizeEmail(this.requireString(data.email, "email"));
        const password = this.requireString(data.password, "password");

        if (this.hooks?.beforeSignUp) {
            await this.hooks.beforeSignUp({ email });
        }

        const user = await this.adapter.findUserByEmail(email);

        if (user != null) {
            throw new AuthError("User already exists with same mail", "USER_ALREADY_EXISTS");
        }

        const passwordHash = await this.hasher.hash(password);

        const newUser = await this.adapter.createUser({
            email,
            passwordHash
        });

        const result = toUser(newUser);

        await this.runSideEffectHook("afterSignUp", result);

        // Delivery failure must not undo the signup: the account exists and
        // the user can ask for the link again via requestEmailVerification.
        if (this.hooks?.sendEmailVerification && !newUser.emailVerifiedAt) {
            try {
                await this.deliverEmailVerification(newUser);
            } catch (error) {
                this.logger.error("Sentra: sendEmailVerification hook failed during signUp", error);
            }
        }

        return result;

    }

    async login(data: LoginData): Promise<AuthResult> {
        const email = this.normalizeEmail(this.requireString(data.email, "email"));
        const password = this.requireString(data.password, "password");
        const user = await this.adapter.findUserByEmail(email);

        if (user == null) {
            // Burn the same hashing cost as a real comparison so that an
            // unknown email is not distinguishable from a wrong password
            // by response time.
            await this.hasher.compare(password, await this.getDummyHash());
            await this.runSideEffectHook("onLoginFailed", { email, reason: "USER_NOT_FOUND" });
            throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");
        }

        if (this.hooks?.beforeLogin) await this.hooks.beforeLogin(toUser(user));

        const valid = await this.hasher.compare(password, user.passwordHash);

        if (!valid) {
            await this.runSideEffectHook("onLoginFailed", { email, reason: "INVALID_PASSWORD" });
            throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");
        }

        // Only after the password check, so an attacker cannot learn
        // verification status from a bare email. Not a credential failure,
        // so onLoginFailed stays quiet.
        if (this.requireEmailVerification && !user.emailVerifiedAt) {
            throw new AuthError("Email address has not been verified", "EMAIL_NOT_VERIFIED");
        }

        const now = Date.now();
        const familyId = randomBytes(16).toString("hex");
        const absoluteExpiresAt = this.absoluteSessionExpiryMs === null
            ? undefined
            : new Date(now + this.absoluteSessionExpiryMs);

        const refreshToken = await this.issueSession(user.id, familyId, absoluteExpiresAt, now);

        const token = await createToken(user.id, this.secret, this.expiry, this.jwt);

        const result: AuthResult = {
            user: toUser(user),
            token,
            refreshToken
        };

        await this.runSideEffectHook("afterLogin", result.user);

        return result;

    }

    /**
     * Verifies an access token without touching the database. Use this on
     * hot paths where a deleted user being accepted until their token
     * expires is acceptable; otherwise use `authenticate`.
     */
    async verify(token: string): Promise<TokenPayload> {
        return verifyToken(token, this.secret, this.jwt);
    }

    async authenticate(token: string): Promise<User> {
        const { userId } = await verifyToken(token, this.secret, this.jwt);
        const user = await this.adapter.findUserById(userId);
        if (user == null) throw new AuthError("Authorization failed", "AUTHENTICATION_FAILED", { reason: "USER_NOT_FOUND" });

        return toUser(user);
    }

    async refresh(refreshToken: string): Promise<AuthResult> {

        const refreshTokenHash = hashRefreshToken(this.requireString(refreshToken, "refreshToken"));
        const session = await this.refreshTokenAdapter.findSessionByTokenHash(refreshTokenHash);

        if (session == null) {
            throw new AuthError("Invalid refresh token", "AUTHENTICATION_FAILED", { reason: "REFRESH_TOKEN_INVALID" });
        }

        const now = Date.now();

        if (session.revokedAt !== null) {
            const concurrent = await this.isConcurrentRefresh(session, now);

            if (!concurrent) {
                await this.refreshTokenAdapter.revokeFamily(
                    session.familyId
                );

                await this.runSideEffectHook("onReuseDetected", {
                    userId: session.userId,
                    familyId: session.familyId,
                    sessionId: session.sessionId
                });

                throw new AuthError(
                    "Refresh token reuse detected",
                    "AUTHENTICATION_FAILED",
                    { reason: "REFRESH_TOKEN_REUSED" }
                );
            }
        }

        if (session.expiresAt.getTime() <= now) {
            throw new AuthError("Refresh token has expired", "AUTHENTICATION_FAILED", { reason: "REFRESH_TOKEN_EXPIRED" });
        }
        if (session.absoluteExpiresAt !== undefined && session.absoluteExpiresAt.getTime() <= now) {
            throw new AuthError("Session has reached its maximum lifetime", "AUTHENTICATION_FAILED", { reason: "SESSION_EXPIRED" });
        }

        const user = await this.adapter.findUserById(session.userId);
        if (user == null) {
            throw new AuthError("User no longer exists", "AUTHENTICATION_FAILED", { reason: "USER_NOT_FOUND" });
        }

        if (this.hooks?.beforeRefresh) await this.hooks.beforeRefresh(toUser(user));

        // A session tolerated under the grace period is already revoked;
        // revoking it again would reset `revokedAt` and extend the window.
        if (session.revokedAt === null) {
            await this.refreshTokenAdapter.revokeSession(session.sessionId);
        }

        const newRefreshToken = await this.issueSession(user.id, session.familyId, session.absoluteExpiresAt, now);

        const token = await createToken(
            user.id,
            this.secret,
            this.expiry,
            this.jwt
        );

        const result: AuthResult = {
            user: toUser(user),
            token,
            refreshToken: newRefreshToken
        };

        await this.runSideEffectHook("afterRefresh", result.user);

        return result;
    }

    /**
     * Ends the session the refresh token belongs to, on every client that
     * shares it. Unknown or already-revoked tokens are ignored so that a
     * client can safely call this without checking state first.
     */
    async logout(refreshToken: string): Promise<void> {
        if (typeof refreshToken !== "string" || refreshToken.length === 0) return;

        const session = await this.refreshTokenAdapter.findSessionByTokenHash(hashRefreshToken(refreshToken));

        if (session == null) return;

        await this.refreshTokenAdapter.revokeFamily(session.familyId);
    }

    /**
     * Revokes every refresh session belonging to the user. Access tokens
     * already issued stay valid until they expire; keep `tokenExpiry`
     * short if that matters.
     */
    async logoutAll(userId: string): Promise<void> {
        this.requireString(userId, "userId");
        await this.requireAdapterMethod(this.refreshTokenAdapter, "revokeUserSessions", "logoutAll")(userId);
    }

    /**
     * Verifies the current password, stores the new hash, and signs the
     * user out everywhere when the refresh-token adapter supports it.
     */
    async changePassword(userId: string, data: ChangePasswordData): Promise<void> {
        this.requireString(userId, "userId");
        const currentPassword = this.requireString(data.currentPassword, "currentPassword");
        const newPassword = this.requireString(data.newPassword, "newPassword");

        const updatePassword = this.requireAdapterMethod(this.adapter, "updatePassword", "changePassword");

        const user = await this.adapter.findUserById(userId);
        if (user == null) {
            throw new AuthError("User not found", "USER_NOT_FOUND");
        }

        const valid = await this.hasher.compare(currentPassword, user.passwordHash);
        if (!valid) {
            throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");
        }

        await updatePassword(userId, await this.hasher.hash(newPassword));

        if (typeof this.refreshTokenAdapter.revokeUserSessions === "function") {
            await this.refreshTokenAdapter.revokeUserSessions(userId);
        }

        await this.runSideEffectHook("afterPasswordChange", toUser(user));
    }

    /**
     * Issues a password-reset token and hands it to the `sendPasswordReset`
     * hook. Always resolves, whether or not the email is known, so it
     * cannot be used to enumerate accounts.
     */
    async requestPasswordReset(email: string): Promise<void> {
        const send = this.requireHook("sendPasswordReset", "requestPasswordReset");
        const normalized = this.normalizeEmail(this.requireString(email, "email"));

        const user = await this.adapter.findUserByEmail(normalized);
        if (user == null) return;

        const key = this.actionKey("password-reset", user);
        const { token, expiresAt } = await createActionToken(key, "password-reset", user.id, this.passwordResetExpiry);

        await send({ user: toUser(user), token, expiresAt });
    }

    /**
     * Completes a password reset. The token is bound to the user's current
     * password hash, so it stops working the moment the password changes,
     * whether through this method or `changePassword`.
     */
    async resetPassword(token: string, newPassword: string): Promise<void> {
        this.requireString(token, "token");
        const password = this.requireString(newPassword, "newPassword");
        const updatePassword = this.requireAdapterMethod(this.adapter, "updatePassword", "resetPassword");

        const user = await this.resolveActionToken(token, "password-reset");

        await updatePassword(user.id, await this.hasher.hash(password));

        if (typeof this.refreshTokenAdapter.revokeUserSessions === "function") {
            await this.refreshTokenAdapter.revokeUserSessions(user.id);
        }

        await this.runSideEffectHook("afterPasswordReset", toUser(user));
    }

    /**
     * Re-sends the verification link. A no-op for unknown or already
     * verified emails so it cannot be used to enumerate accounts.
     */
    async requestEmailVerification(email: string): Promise<void> {
        this.requireHook("sendEmailVerification", "requestEmailVerification");
        const normalized = this.normalizeEmail(this.requireString(email, "email"));

        const user = await this.adapter.findUserByEmail(normalized);
        if (user == null || user.emailVerifiedAt) return;

        await this.deliverEmailVerification(user);
    }

    /**
     * Marks the email verified. The token is bound to the address it was
     * issued for, so changing the email invalidates it. Verifying an
     * already-verified user succeeds without touching the adapter.
     */
    async verifyEmail(token: string): Promise<User> {
        this.requireString(token, "token");
        const setEmailVerified = this.requireAdapterMethod(this.adapter, "setEmailVerified", "verifyEmail");

        const user = await this.resolveActionToken(token, "email-verification");

        if (user.emailVerifiedAt) return toUser(user);

        const verifiedAt = new Date();
        await setEmailVerified(user.id, verifiedAt);

        const result = toUser({ ...user, emailVerifiedAt: verifiedAt });

        await this.runSideEffectHook("afterEmailVerified", result);

        return result;
    }

    private async deliverEmailVerification(user: UserRecord): Promise<void> {
        const send = this.requireHook("sendEmailVerification", "requestEmailVerification");
        const key = this.actionKey("email-verification", user);
        const { token, expiresAt } = await createActionToken(key, "email-verification", user.id, this.emailVerificationExpiry);

        await send({ user: toUser(user), token, expiresAt });
    }

    /**
     * The key for an action token mixes in the state the action changes,
     * which is what makes the token single-use without any storage.
     */
    private actionKey(purpose: ActionTokenPurpose, user: UserRecord): Uint8Array {
        const state = purpose === "password-reset" ? user.passwordHash : user.email;
        return deriveActionKey(this.secret, purpose, user.id, state);
    }

    /**
     * Looks up the token's user, derives their current key and verifies the
     * token against it. Every failure maps to the same `INVALID_TOKEN`
     * code so the caller learns nothing about which step rejected it,
     * beyond expiry (which is safe to show).
     */
    private async resolveActionToken(token: string, purpose: ActionTokenPurpose): Promise<UserRecord> {
        const reasonPrefix = purpose === "password-reset" ? "RESET_TOKEN" : "VERIFICATION_TOKEN";

        const userId = peekActionToken(token, purpose);
        const user = userId === null ? null : await this.adapter.findUserById(userId);

        if (user == null) {
            throw new AuthError("Invalid token", "INVALID_TOKEN", { reason: `${reasonPrefix}_INVALID` });
        }

        try {
            await verifyActionToken(token, this.actionKey(purpose, user), purpose, user.id);
        } catch (error) {
            if (error instanceof ActionTokenError && error.failure === "expired") {
                throw new AuthError("Token has expired", "INVALID_TOKEN", { reason: `${reasonPrefix}_EXPIRED`, cause: error });
            }
            throw new AuthError("Invalid token", "INVALID_TOKEN", { reason: `${reasonPrefix}_INVALID`, cause: error });
        }

        return user;
    }

    private requireHook<K extends "sendPasswordReset" | "sendEmailVerification">(name: K, operation: string): (data: DeliveryHookData) => void | Promise<void> {
        const hook = this.hooks?.[name];
        if (typeof hook !== "function") {
            throw new Error(`Sentra: ${operation}() requires the ${name} hook to be configured`);
        }
        return hook;
    }

    /**
     * Creates and stores a new refresh session in `familyId` and returns the
     * raw refresh token. `expiresAt` is capped by `absoluteExpiresAt`.
     */
    private async issueSession(userId: string, familyId: string, absoluteExpiresAt: Date | undefined, now: number): Promise<string> {
        const refreshToken = generateRefreshToken();

        let expiresAt = new Date(now + this.refreshTokenExpiryMs);
        if (absoluteExpiresAt !== undefined && absoluteExpiresAt.getTime() < expiresAt.getTime()) {
            expiresAt = absoluteExpiresAt;
        }

        const session: RefreshSession = {
            sessionId: randomBytes(16).toString("hex"),
            familyId,
            userId,
            refreshTokenHash: hashRefreshToken(refreshToken),
            expiresAt,
            revokedAt: null
        };
        // Only add the key when the feature is on, so adapters that reject
        // unknown columns (e.g. Prisma) keep working without a migration.
        if (absoluteExpiresAt !== undefined) {
            session.absoluteExpiresAt = absoluteExpiresAt;
        }

        await this.refreshTokenAdapter.createSession(session);

        return refreshToken;
    }

    /**
     * A revoked session presented within the grace period counts as a
     * concurrent refresh (two clients racing with the same token) rather
     * than reuse, but only while the family still has a live session. A
     * family that was revoked outright has none, so its tokens stay dead.
     */
    private async isConcurrentRefresh(session: RefreshSession, now: number): Promise<boolean> {
        if (this.refreshTokenGracePeriodMs === 0 || session.revokedAt === null) return false;
        if (now - session.revokedAt.getTime() > this.refreshTokenGracePeriodMs) return false;

        const family = await this.refreshTokenAdapter.findSessionsByFamilyId!(session.familyId);

        return family.some(
            member => member.revokedAt === null && member.expiresAt.getTime() > now
        );
    }

    /**
     * Runs an `after*` / `on*` hook. These exist for side effects, so a
     * failure is logged rather than allowed to break the caller's flow.
     */
    private async runSideEffectHook<K extends SideEffectHook>(
        name: K,
        data: Parameters<NonNullable<AuthHooks[K]>>[0]
    ): Promise<void> {
        const hook = this.hooks?.[name] as ((data: Parameters<NonNullable<AuthHooks[K]>>[0]) => void | Promise<void>) | undefined;
        if (!hook) return;

        try {
            await hook(data);
        } catch (error) {
            this.logger.error(`Sentra: ${name} hook failed`, error);
        }
    }

    private requireAdapterMethod<A extends object, K extends keyof A>(
        adapter: A,
        method: K,
        operation: string
    ): NonNullable<A[K]> & ((...args: never[]) => unknown) {
        const fn = adapter[method];
        if (typeof fn !== "function") {
            throw new Error(`Sentra: ${operation}() requires the adapter to implement ${String(method)}()`);
        }
        return fn.bind(adapter) as NonNullable<A[K]> & ((...args: never[]) => unknown);
    }

    private requireString(value: unknown, field: string): string {
        if (typeof value !== "string" || value.length === 0) {
            throw new AuthError(`${field} must be a non-empty string`, "INVALID_INPUT");
        }
        return value;
    }

    private normalizeEmail(email: string): string {
        if (this.emailNormalizer === false) return email;
        if (typeof this.emailNormalizer === "function") return this.emailNormalizer(email);
        return email.trim().toLowerCase();
    }

    private async getDummyHash(): Promise<string> {
        this.dummyHash ??= await this.hasher.hash("sentra-dummy-password");
        return this.dummyHash;
    }

}

type SideEffectHook =
    | "afterSignUp"
    | "afterLogin"
    | "afterRefresh"
    | "afterPasswordChange"
    | "afterPasswordReset"
    | "afterEmailVerified"
    | "onLoginFailed"
    | "onReuseDetected";

function toUser(record: UserRecord): User {
    const user: User = { id: record.id, email: record.email };
    // Only mirror the field when the adapter tracks it, so consumers can
    // tell "not tracked" (undefined) from "not verified" (null).
    if (record.emailVerifiedAt !== undefined) user.emailVerifiedAt = record.emailVerifiedAt;
    return user;
}

export { Auth };
