import { AuthError } from "../errors/auth-error.js";
import { generateRefreshToken, hashRefreshToken } from "../jwt/refresh-token.js";
import { createToken, verifyToken } from "../jwt/token.js";
import type { UserAdapter, User, RefreshTokenAdapter } from "../types/adapter.js";
import type { AuthResult, LoginData, SignUpData } from "../types/auth.js";
import bcrypt from "bcrypt";
import type { RefreshSession } from "../types/session.js";
import { randomBytes } from "node:crypto";
import { AuthHooks } from "../types/hooks.js";

const BCRYPT_COST = 10;

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
        this.hooks = options.hooks;
    }

    async signUp(data: SignUpData): Promise<User> {

        const email = this.normalizeEmail(data.email);

        if (this.hooks?.beforeSignUp) {
            await this.hooks.beforeSignUp({ email });
        }

        const user = await this.adapter.findUserByEmail(email);

        if (user != null) {
            throw new AuthError("User already exists with same mail", "USER_ALREADY_EXISTS");
        }

        const passwordHash = await bcrypt.hash(data.password, BCRYPT_COST);

        const newUser = await this.adapter.createUser({
            email,
            passwordHash
        });

        const result: User = {
            id: newUser.id,
            email: newUser.email
        };

        if (this.hooks?.afterSignUp) {
            try {
                await this.hooks.afterSignUp(result);
            } catch (error) {
                console.error("after signup hook failed", error);
            }
        }

        return result;

    }

    async login(data: LoginData): Promise<AuthResult> {
        const email = this.normalizeEmail(data.email);
        const user = await this.adapter.findUserByEmail(email);

        if (user == null) {
            // Burn the same bcrypt cost as a real comparison so that an
            // unknown email is not distinguishable from a wrong password
            // by response time.
            await bcrypt.compare(data.password, await this.getDummyHash());
            throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");
        }

        if (this.hooks?.beforeLogin) await this.hooks.beforeLogin({ id: user.id, email: user.email });

        const valid = await bcrypt.compare(data.password, user.passwordHash);

        if (!valid) throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");

        const now = Date.now();
        const familyId = randomBytes(16).toString("hex");
        const absoluteExpiresAt = this.absoluteSessionExpiryMs === null
            ? undefined
            : new Date(now + this.absoluteSessionExpiryMs);

        const refreshToken = await this.issueSession(user.id, familyId, absoluteExpiresAt, now);

        const token = await createToken(user.id, this.secret, this.expiry)

        const result: AuthResult = {
            user: {
                id: user.id,
                email: user.email,
            },
            token,
            refreshToken
        };

        if (this.hooks?.afterLogin) {
            try {
                await this.hooks.afterLogin(result.user);
            } catch (error) {
                console.error("After login hook failed", error);
            }
        }

        return result;

    }

    async authenticate(token: string): Promise<User> {
        const userId = await verifyToken(token, this.secret);
        const user = await this.adapter.findUserById(userId);
        if (user == null) throw new AuthError("Authorization failed", "AUTHENTICATION_FAILED");

        return {
            id: user.id,
            email: user.email
        };
    }

    async refresh(refreshToken: string): Promise<AuthResult> {

        const refreshTokenHash = hashRefreshToken(refreshToken);
        const session = await this.refreshTokenAdapter.findSessionByTokenHash(refreshTokenHash);

        if (session == null) {
            throw new AuthError("Invalid refresh token", "AUTHENTICATION_FAILED");
        }

        const now = Date.now();

        if (session.revokedAt !== null) {
            const concurrent = await this.isConcurrentRefresh(session, now);

            if (!concurrent) {
                await this.refreshTokenAdapter.revokeFamily(
                    session.familyId
                );

                throw new AuthError(
                    "Refresh token reuse detected",
                    "AUTHENTICATION_FAILED"
                );
            }
        }

        if (session.expiresAt.getTime() <= now) {
            throw new AuthError("Refresh token has expired", "AUTHENTICATION_FAILED");
        }
        if (session.absoluteExpiresAt !== undefined && session.absoluteExpiresAt.getTime() <= now) {
            throw new AuthError("Session has reached its maximum lifetime", "AUTHENTICATION_FAILED");
        }

        const user = await this.adapter.findUserById(session.userId);
        if (user == null) {
            throw new AuthError("User no longer exists", "AUTHENTICATION_FAILED");
        }

        // A session tolerated under the grace period is already revoked;
        // revoking it again would reset `revokedAt` and extend the window.
        if (session.revokedAt === null) {
            await this.refreshTokenAdapter.revokeSession(session.sessionId);
        }

        const newRefreshToken = await this.issueSession(user.id, session.familyId, session.absoluteExpiresAt, now);

        const token = await createToken(
            user.id,
            this.secret,
            this.expiry
        );

        return {
            user: {
                id: user.id,
                email: user.email
            },
            token,
            refreshToken: newRefreshToken
        };
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

    private normalizeEmail(email: string): string {
        if (this.emailNormalizer === false) return email;
        if (typeof this.emailNormalizer === "function") return this.emailNormalizer(email);
        return email.trim().toLowerCase();
    }

    private async getDummyHash(): Promise<string> {
        this.dummyHash ??= await bcrypt.hash("sentra-dummy-password", BCRYPT_COST);
        return this.dummyHash;
    }

}
export { Auth };
