import { AuthError, createAuth } from "../src/index.js";
import { UserRecord, CreateUser } from "../src/types/adapter.js";
import { RefreshSession } from "../src/types/session.js";
import { expect, it, describe, vi, afterEach } from "vitest";
import bcrypt from "bcrypt";
import { hashRefreshToken } from "../src/jwt/refresh-token.js";
import { MemoryAdapter } from "../src/adapters/memory.js";

const secret = "test-secret-that-is-at-least-32-bytes-long";

const pass = bcrypt.hashSync("akash", 10);
const pass2 = bcrypt.hashSync("rahul", 10);

const db: UserRecord[] = [
    {
        id: "1",
        email: "akash@gmail.com",
        passwordHash: pass
    },
    {
        id: "2",
        email: "rahul@gmail.com",
        passwordHash: pass2
    }
];

const adapter = {
    db: [...db],
    sessions: [] as RefreshSession[],

    findUserByEmail(email: string): Promise<UserRecord | null> {
        return Promise.resolve(
            this.db.find(user => user.email === email) ?? null
        );
    },

    createUser(data: CreateUser): Promise<UserRecord> {
        const user = {
            id: Math.random().toString(),
            ...data
        };

        this.db.push(user);

        return Promise.resolve(user);
    },

    findUserById(userId: string): Promise<UserRecord | null> {
        return Promise.resolve(
            this.db.find(user => user.id === userId) ?? null
        );
    },

    findSessionByTokenHash(
        refreshTokenHash: string
    ): Promise<RefreshSession | null> {
        return Promise.resolve(
            this.sessions.find(
                session => session.refreshTokenHash === refreshTokenHash
            ) ?? null
        );
    },

    createSession(
        session: RefreshSession
    ): Promise<RefreshSession> {
        this.sessions.push(session);
        return Promise.resolve(session);
    },

    revokeSession(sessionId: string): Promise<void> {
        const session = this.sessions.find(
            session => session.sessionId === sessionId
        );

        if (session) {
            session.revokedAt = new Date();
        }

        return Promise.resolve();
    },

    revokeFamily(familyId: string): Promise<void> {
        for (const session of this.sessions) {
            if (session.familyId === familyId) {
                session.revokedAt = new Date();
            }
        }

        return Promise.resolve();
    },

    getSessions(): RefreshSession[] {
        return this.sessions;
    }



};


const auth = createAuth({
    adapter,
    refreshTokenAdapter: adapter,
    secret
});


describe("Login", () => {

    it("Successful login", async () => {
        const res = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        expect(res.user.email).toBe("akash@gmail.com");
        expect(res.user.id).toBeDefined();
        expect(res.token).toBeTypeOf("string");
        expect(res.refreshToken).toBeTypeOf("string");
    });


    it("Nonexistent user", async () => {
        try {
            await auth.login({
                email: "aakash@gmail.com",
                password: "akash"
            });

            expect.fail("expected autherror to throw");

        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("INVALID_CREDENTIALS");
        }
    });


    it("wrong password", async () => {
        try {
            await auth.login({
                email: "akash@gmail.com",
                password: "wrong-password"
            });

            expect.fail("expected autherror to throw");

        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("INVALID_CREDENTIALS");
        }
    });


    it("should not expose the password hash to the caller", async () => {
        const res = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        expect(res.user).not.toHaveProperty("passwordHash");
    });


    it("Successful login for another user", async () => {
        const res = await auth.login({
            email: "rahul@gmail.com",
            password: "rahul"
        });

        expect(res.user.email).toBe("rahul@gmail.com");
        expect(res.user.id).toBeDefined();
        expect(res.token).toBeTypeOf("string");
        expect(res.refreshToken).toBeTypeOf("string");
    });


    it("should create a refresh session", async () => {
        const before = adapter.getSessions().length;

        await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const after = adapter.getSessions().length;

        expect(after).toBe(before + 1);
    });


    it("should create a session for the logged-in user", async () => {
        const result = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();
        const session = sessions[sessions.length - 1]!;

        expect(session.userId).toBe(result.user.id);
    });


    it("should not store the raw refresh token", async () => {
        const result = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();
        const session = sessions[sessions.length - 1]!;

        expect(session.refreshTokenHash)
            .not.toBe(result.refreshToken);
    });


    it("should store a valid bcrypt refresh token hash", async () => {
        const result = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();
        const session = sessions[sessions.length - 1]!;

        expect(session.refreshTokenHash).toBe(hashRefreshToken(result.refreshToken));
    });


    it("should create a non-revoked session", async () => {
        await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();
        const session = sessions[sessions.length - 1]!;

        expect(session.revokedAt).toBeNull();
    });


    it("should set refresh token expiration in the future", async () => {
        await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();
        const session = sessions[sessions.length - 1]!;

        expect(session.expiresAt.getTime())
            .toBeGreaterThan(Date.now());
    });

    it("should call beforeLogin hook", async () => {
        const beforeLogin = vi.fn().mockResolvedValue(undefined);

        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret,
            hooks: {
                beforeLogin
            }
        });

        await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        expect(beforeLogin).toHaveBeenCalledWith({
            id: expect.any(String),
            email: "akash@gmail.com",
            emailVerifiedAt: null
        });
    });

    it("should stop login when beforeLogin throws", async () => {
        const beforeLogin = vi
            .fn()
            .mockRejectedValue(
                new AuthError(
                    "Account is disabled",
                    "AUTHENTICATION_FAILED"
                )
            );

        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret,
            hooks: {
                beforeLogin
            }
        });

        await expect(
            auth.login({
                email: "akash@gmail.com",
                password: "akash"
            })
        ).rejects.toMatchObject({
            code: "AUTHENTICATION_FAILED"
        });
    });

    it("should call afterLogin hook after successful login", async () => {
        const afterLogin = vi.fn().mockResolvedValue(undefined);

        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret,
            hooks: {
                afterLogin
            }
        });

        const result = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        expect(afterLogin).toHaveBeenCalledOnce();

        expect(afterLogin).toHaveBeenCalledWith(result.user);
        const hookUser = afterLogin.mock.calls[0]![0];

        expect(hookUser).not.toHaveProperty("passwordHash");
    });

    it("should not call afterLogin when login fails", async () => {
        const afterLogin = vi.fn().mockResolvedValue(undefined);

        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret,
            hooks: {
                afterLogin
            }
        });

        await expect(
            auth.login({
                email: "akash@gmail.com",
                password: "wrong-password"
            })
        ).rejects.toMatchObject({
            code: "INVALID_CREDENTIALS"
        });

        expect(afterLogin).not.toHaveBeenCalled();
    });

    it("should still return successful login if afterLogin hook throws", async () => {
        const afterLogin = vi
            .fn()
            .mockRejectedValue(new Error("Analytics service failed"));

        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret,
            hooks: {
                afterLogin
            }
        });

        const result = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        expect(result.user.email).toBe("akash@gmail.com");
        expect(result.token).toBeTypeOf("string");
        expect(result.refreshToken).toBeTypeOf("string");
    });
});
describe("Login hardening", () => {

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("should run a bcrypt comparison even when the user does not exist", async () => {
        const adapter = new MemoryAdapter();

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret
        });

        const compare = vi.spyOn(bcrypt, "compare");

        await expect(
            auth.login({ email: "nobody@gmail.com", password: "whatever" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        expect(compare).toHaveBeenCalledTimes(1);
        expect(compare.mock.calls[0]![0]).toBe("whatever");
    });

    it("should normalise the email before lookup", async () => {
        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret
        });

        const result = await auth.login({
            email: "  Akash@Gmail.com ",
            password: "akash"
        });

        expect(result.user.email).toBe("akash@gmail.com");
    });

    it("should use the email verbatim when normalisation is disabled", async () => {
        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "Akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret,
            normalizeEmail: false
        });

        await expect(
            auth.login({ email: "akash@gmail.com", password: "akash" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        const result = await auth.login({ email: "Akash@gmail.com", password: "akash" });
        expect(result.user.email).toBe("Akash@gmail.com");
    });

    it("should support a custom email normaliser", async () => {
        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret,
            // Strip gmail dots
            normalizeEmail: email => email.toLowerCase().replace(/\.(?=.*@)/g, "")
        });

        const result = await auth.login({
            email: "a.k.a.s.h@gmail.com",
            password: "akash"
        });

        expect(result.user.email).toBe("akash@gmail.com");
    });

    it("should accept synchronous hooks", async () => {
        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const calls: string[] = [];

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret,
            hooks: {
                beforeLogin: () => { calls.push("before"); },
                afterLogin: () => { calls.push("after"); }
            }
        });

        await auth.login({ email: "akash@gmail.com", password: "akash" });

        expect(calls).toEqual(["before", "after"]);
    });

});
