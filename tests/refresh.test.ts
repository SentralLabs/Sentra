import { createAuth, AuthError } from "../src/index.js";
import { MemoryAdapter } from "../examples/memory-adapter.js";
import { describe, it, expect } from "vitest";
import bcrypt from "bcrypt";

const secret = "test-secret-that-is-at-least-32-bytes-long";

describe("Refresh", () => {

    it("should refresh a valid refresh token", async () => {
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

        const loginResult = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const result = await auth.refresh(
            loginResult.refreshToken
        );

        expect(result.user.email).toBe("akash@gmail.com");
        expect(result.user.id).toBe(loginResult.user.id);
        expect(result.token).toBeTypeOf("string");
        expect(result.refreshToken).not.toBe(loginResult.refreshToken
        );

        expect(result.refreshToken).toBeTypeOf("string");
    });

    it("should reject an invalid refresh token", async () => {
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

        try {
            await auth.refresh("invalid-refresh-token");

            expect.fail("Expected authentication error");
        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("AUTHENTICATION_FAILED");
        }
    });
    it("should reject a revoked refresh token", async () => {
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

        const loginResult = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();

        const session = sessions[0];

        await adapter.revokeSession(session.sessionId);

        try {
            await auth.refresh(loginResult.refreshToken);

            expect.fail("Expected authentication error");
        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("AUTHENTICATION_FAILED");
        }
    });
    it("should reject an expired refresh token", async () => {
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

        const loginResult = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();

        sessions[0].expiresAt = new Date(Date.now() - 1000);

        try {
            await auth.refresh(loginResult.refreshToken);

            expect.fail("Expected authentication error");
        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("AUTHENTICATION_FAILED");
        }
    });
    it("should reject refresh when the user no longer exists", async () => {
        const adapter = new MemoryAdapter();

        const user = await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret
        });

        const loginResult = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        adapter.deleteUser(user.id);

        try {
            await auth.refresh(loginResult.refreshToken);

            expect.fail("Expected authentication error");
        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("AUTHENTICATION_FAILED");
        }
    });
    it("should invalidate the old refresh token after rotation", async () => {
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

        const firstLogin = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const firstRefresh = await auth.refresh(
            firstLogin.refreshToken
        );

        await expect(
            auth.refresh(firstLogin.refreshToken)
        ).rejects.toMatchObject({
            code: "AUTHENTICATION_FAILED"
        });

        expect(firstRefresh.refreshToken)
            .not.toBe(firstLogin.refreshToken);
    });

    it("should allow the newly rotated refresh token to be used", async () => {
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

        const firstLogin = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const secondResult = await auth.refresh(
            firstLogin.refreshToken
        );

        const thirdResult = await auth.refresh(
            secondResult.refreshToken
        );

        expect(thirdResult.user.id)
            .toBe(firstLogin.user.id);

        expect(thirdResult.token)
            .toBeTypeOf("string");

        expect(thirdResult.refreshToken)
            .toBeTypeOf("string");

        expect(thirdResult.refreshToken)
            .not.toBe(secondResult.refreshToken);
    });

    it("should preserve the refresh token family during rotation", async () => {
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

        const loginResult = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const firstSession = adapter.getSessions()[0];

        const refreshResult = await auth.refresh(
            loginResult.refreshToken
        );

        const sessions = adapter.getSessions();

        const secondSession =
            sessions.find(
                session => session.sessionId !== firstSession.sessionId
            )!;

        expect(secondSession.familyId)
            .toBe(firstSession.familyId);

        expect(secondSession.sessionId)
            .not.toBe(firstSession.sessionId);
    });

    it("should revoke the entire family when a refresh token is reused", async () => {
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

        const firstLogin = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const secondResult = await auth.refresh(
            firstLogin.refreshToken
        );

        // Reuse the already-revoked token
        await expect(
            auth.refresh(firstLogin.refreshToken)
        ).rejects.toMatchObject({
            code: "AUTHENTICATION_FAILED"
        });

        const sessions = adapter.getSessions();

        for (const session of sessions) {
            expect(session.revokedAt).not.toBeNull();
        }
    });

    it("should invalidate the entire token family after reuse", async () => {
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

        const firstLogin = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const secondResult = await auth.refresh(
            firstLogin.refreshToken
        );

        // Attacker reuses old token
        await expect(
            auth.refresh(firstLogin.refreshToken)
        ).rejects.toMatchObject({
            code: "AUTHENTICATION_FAILED"
        });

        // Legitimate user's current token is now also invalid
        await expect(
            auth.refresh(secondResult.refreshToken)
        ).rejects.toMatchObject({
            code: "AUTHENTICATION_FAILED"
        });
    });
});
async function loggedInAuth(extra: Partial<Parameters<typeof createAuth>[0]> = {}) {
    const adapter = new MemoryAdapter();

    await adapter.createUser({
        email: "akash@gmail.com",
        passwordHash: await bcrypt.hash("akash", 10)
    });

    const auth = createAuth({
        adapter,
        refreshTokenAdapter: adapter,
        secret,
        ...extra
    });

    const login = await auth.login({
        email: "akash@gmail.com",
        password: "akash"
    });

    return { adapter, auth, login };
}

describe("Refresh grace period", () => {

    it("should be disabled by default", async () => {
        const { auth, login } = await loggedInAuth();

        await auth.refresh(login.refreshToken);

        await expect(
            auth.refresh(login.refreshToken)
        ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    });

    it("should tolerate a second refresh with the same token inside the window", async () => {
        const { adapter, auth, login } = await loggedInAuth({ refreshTokenGracePeriod: "10s" });

        // Two clients (e.g. browser tabs) present the same refresh token;
        // the second one arrives after the first has already rotated it.
        const first = await auth.refresh(login.refreshToken);
        const second = await auth.refresh(login.refreshToken);

        expect(adapter.getSessions()[0]!.revokedAt).not.toBeNull();
        expect(first.refreshToken).not.toBe(second.refreshToken);

        // Both replacement tokens are live and belong to the same family
        const firstNext = await auth.refresh(first.refreshToken);
        const secondNext = await auth.refresh(second.refreshToken);

        expect(firstNext.user.id).toBe(login.user.id);
        expect(secondNext.user.id).toBe(login.user.id);

        const families = new Set(adapter.getSessions().map(s => s.familyId));
        expect(families.size).toBe(1);
    });

    it("should not reset the revocation time when tolerating a concurrent refresh", async () => {
        const { adapter, auth, login } = await loggedInAuth({ refreshTokenGracePeriod: "10s" });

        await auth.refresh(login.refreshToken);
        const revokedAt = adapter.getSessions()[0]!.revokedAt;

        await auth.refresh(login.refreshToken);

        expect(adapter.getSessions()[0]!.revokedAt).toBe(revokedAt);
    });

    it("should treat reuse after the window as a breach", async () => {
        const { adapter, auth, login } = await loggedInAuth({ refreshTokenGracePeriod: "10s" });

        const rotated = await auth.refresh(login.refreshToken);

        // Push the original session's revocation outside the window
        adapter.getSessions()[0]!.revokedAt = new Date(Date.now() - 11_000);

        await expect(
            auth.refresh(login.refreshToken)
        ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });

        await expect(
            auth.refresh(rotated.refreshToken)
        ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    });

    it("should not resurrect a family that was revoked outright", async () => {
        const { adapter, auth, login } = await loggedInAuth({ refreshTokenGracePeriod: "10s" });

        const rotated = await auth.refresh(login.refreshToken);

        // e.g. logout-everywhere or a detected breach
        await adapter.revokeFamily(adapter.getSessions()[0]!.familyId);

        // Both tokens were revoked "just now", well inside the window,
        // but the family has no live session so neither may be used.
        await expect(
            auth.refresh(login.refreshToken)
        ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });

        await expect(
            auth.refresh(rotated.refreshToken)
        ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    });

    it("should not tolerate a token whose replacement has expired", async () => {
        const { adapter, auth, login } = await loggedInAuth({ refreshTokenGracePeriod: "10s" });

        await auth.refresh(login.refreshToken);

        const replacement = adapter.getSessions().find(s => s.revokedAt === null)!;
        replacement.expiresAt = new Date(Date.now() - 1000);

        await expect(
            auth.refresh(login.refreshToken)
        ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    });

});

describe("Absolute session expiry", () => {

    it("should not add absoluteExpiresAt to sessions when disabled", async () => {
        const { adapter } = await loggedInAuth();

        expect("absoluteExpiresAt" in adapter.getSessions()[0]!).toBe(false);
    });

    it("should stamp the session with an absolute expiry when enabled", async () => {
        const before = Date.now();
        const { adapter } = await loggedInAuth({ absoluteSessionExpiry: "90d" });
        const after = Date.now();

        const session = adapter.getSessions()[0]!;
        const ninetyDays = 90 * 86_400_000;

        expect(session.absoluteExpiresAt).toBeInstanceOf(Date);
        expect(session.absoluteExpiresAt!.getTime()).toBeGreaterThanOrEqual(before + ninetyDays);
        expect(session.absoluteExpiresAt!.getTime()).toBeLessThanOrEqual(after + ninetyDays);
    });

    it("should carry the absolute expiry across rotations unchanged", async () => {
        const { adapter, auth, login } = await loggedInAuth({ absoluteSessionExpiry: "90d" });

        const original = adapter.getSessions()[0]!.absoluteExpiresAt!;

        const second = await auth.refresh(login.refreshToken);
        await auth.refresh(second.refreshToken);

        for (const session of adapter.getSessions()) {
            expect(session.absoluteExpiresAt!.getTime()).toBe(original.getTime());
        }
    });

    it("should cap the sliding expiry at the absolute expiry", async () => {
        const { adapter } = await loggedInAuth({
            refreshTokenExpiry: "30d",
            absoluteSessionExpiry: "1h"
        });

        const session = adapter.getSessions()[0]!;

        expect(session.expiresAt.getTime()).toBe(session.absoluteExpiresAt!.getTime());
    });

    it("should reject refresh once the absolute expiry has passed", async () => {
        const { adapter, auth, login } = await loggedInAuth({ absoluteSessionExpiry: "90d" });

        const session = adapter.getSessions()[0]!;
        session.absoluteExpiresAt = new Date(Date.now() - 1000);

        await expect(
            auth.refresh(login.refreshToken)
        ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    });

});
