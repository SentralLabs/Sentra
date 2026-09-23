import { describe, it, expect, vi } from "vitest";
import { createAuth, AuthError, MemoryAdapter } from "../src/index.js";
import bcrypt from "bcrypt";

const secret = "test-secret-that-is-at-least-32-bytes-long";

async function setup(extra: Partial<Parameters<typeof createAuth>[0]> = {}) {
    const adapter = new MemoryAdapter();

    const user = await adapter.createUser({
        email: "akash@gmail.com",
        passwordHash: await bcrypt.hash("akash", 10)
    });

    const auth = createAuth({
        adapter,
        refreshTokenAdapter: adapter,
        secret,
        ...extra
    });

    return { adapter, auth, user };
}

function withoutOptionalMethods(adapter: MemoryAdapter) {
    return {
        findUserByEmail: adapter.findUserByEmail.bind(adapter),
        findUserById: adapter.findUserById.bind(adapter),
        createUser: adapter.createUser.bind(adapter),
        findSessionByTokenHash: adapter.findSessionByTokenHash.bind(adapter),
        createSession: adapter.createSession.bind(adapter),
        revokeSession: adapter.revokeSession.bind(adapter),
        revokeFamily: adapter.revokeFamily.bind(adapter)
    };
}

describe("logout", () => {

    it("should revoke the session so the refresh token can no longer be used", async () => {
        const { auth } = await setup();

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });

        await auth.logout(login.refreshToken);

        await expect(
            auth.refresh(login.refreshToken)
        ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    });

    it("should revoke the whole family, including grace-period siblings", async () => {
        const { adapter, auth } = await setup({ refreshTokenGracePeriod: "10s" });

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });
        const tabA = await auth.refresh(login.refreshToken);
        const tabB = await auth.refresh(login.refreshToken);

        await auth.logout(tabA.refreshToken);

        expect(adapter.getSessions().every(s => s.revokedAt !== null)).toBe(true);

        await expect(
            auth.refresh(tabB.refreshToken)
        ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    });

    it("should not affect other logins of the same user", async () => {
        const { auth } = await setup();

        const phone = await auth.login({ email: "akash@gmail.com", password: "akash" });
        const laptop = await auth.login({ email: "akash@gmail.com", password: "akash" });

        await auth.logout(phone.refreshToken);

        const result = await auth.refresh(laptop.refreshToken);
        expect(result.user.email).toBe("akash@gmail.com");
    });

    it("should be a no-op for unknown, empty or already-revoked tokens", async () => {
        const { auth } = await setup();

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });

        await expect(auth.logout("not-a-token")).resolves.toBeUndefined();
        await expect(auth.logout("")).resolves.toBeUndefined();
        await auth.logout(login.refreshToken);
        await expect(auth.logout(login.refreshToken)).resolves.toBeUndefined();
    });

    it("should not trigger reuse detection when a logged-out token is presented", async () => {
        const onReuseDetected = vi.fn();
        const { auth } = await setup({ hooks: { onReuseDetected } });

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });
        await auth.logout(login.refreshToken);

        await expect(auth.refresh(login.refreshToken)).rejects.toMatchObject({
            reason: "REFRESH_TOKEN_REUSED"
        });

        // The family is already dead; the hook still fires so the app can
        // decide whether a post-logout replay is worth alerting on.
        expect(onReuseDetected).toHaveBeenCalledTimes(1);
    });

});

describe("logoutAll", () => {

    it("should revoke every session of the user", async () => {
        const { auth, user } = await setup();

        const phone = await auth.login({ email: "akash@gmail.com", password: "akash" });
        const laptop = await auth.login({ email: "akash@gmail.com", password: "akash" });

        await auth.logoutAll(user.id);

        await expect(auth.refresh(phone.refreshToken)).rejects.toBeInstanceOf(AuthError);
        await expect(auth.refresh(laptop.refreshToken)).rejects.toBeInstanceOf(AuthError);
    });

    it("should leave other users' sessions alone", async () => {
        const { adapter, auth, user } = await setup();

        await adapter.createUser({
            email: "rahul@gmail.com",
            passwordHash: await bcrypt.hash("rahul", 10)
        });

        const rahul = await auth.login({ email: "rahul@gmail.com", password: "rahul" });
        await auth.login({ email: "akash@gmail.com", password: "akash" });

        await auth.logoutAll(user.id);

        const result = await auth.refresh(rahul.refreshToken);
        expect(result.user.email).toBe("rahul@gmail.com");
    });

    it("should reject an empty user id", async () => {
        const { auth } = await setup();

        await expect(auth.logoutAll("")).rejects.toMatchObject({ code: "INVALID_INPUT" });
    });

    it("should throw a clear error when the adapter lacks revokeUserSessions", async () => {
        const adapter = new MemoryAdapter();
        const plain = withoutOptionalMethods(adapter);

        const auth = createAuth({ adapter: plain, refreshTokenAdapter: plain, secret });

        await expect(auth.logoutAll("1")).rejects.toThrow(/revokeUserSessions/);
    });

});

describe("changePassword", () => {

    it("should replace the password hash", async () => {
        const { adapter, auth, user } = await setup();

        const before = adapter.getUsers()[0]!.passwordHash;

        await auth.changePassword(user.id, { currentPassword: "akash", newPassword: "new-password" });

        const after = adapter.getUsers()[0]!.passwordHash;
        expect(after).not.toBe(before);
        expect(after).not.toContain("new-password");
        expect(await bcrypt.compare("new-password", after)).toBe(true);
    });

    it("should allow login with the new password only", async () => {
        const { auth, user } = await setup();

        await auth.changePassword(user.id, { currentPassword: "akash", newPassword: "new-password" });

        await expect(
            auth.login({ email: "akash@gmail.com", password: "akash" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        const result = await auth.login({ email: "akash@gmail.com", password: "new-password" });
        expect(result.user.id).toBe(user.id);
    });

    it("should reject a wrong current password without changing anything", async () => {
        const { adapter, auth, user } = await setup();

        const before = adapter.getUsers()[0]!.passwordHash;

        await expect(
            auth.changePassword(user.id, { currentPassword: "wrong", newPassword: "new-password" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        expect(adapter.getUsers()[0]!.passwordHash).toBe(before);
    });

    it("should sign the user out everywhere", async () => {
        const { auth, user } = await setup();

        const phone = await auth.login({ email: "akash@gmail.com", password: "akash" });

        await auth.changePassword(user.id, { currentPassword: "akash", newPassword: "new-password" });

        await expect(auth.refresh(phone.refreshToken)).rejects.toBeInstanceOf(AuthError);
    });

    it("should still work when the refresh adapter cannot revoke by user", async () => {
        const adapter = new MemoryAdapter();
        const user = await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });
        const refreshOnly = withoutOptionalMethods(adapter);

        const auth = createAuth({ adapter, refreshTokenAdapter: refreshOnly, secret });

        const phone = await auth.login({ email: "akash@gmail.com", password: "akash" });

        await auth.changePassword(user.id, { currentPassword: "akash", newPassword: "new-password" });

        // Sessions survive because the adapter cannot revoke them
        const result = await auth.refresh(phone.refreshToken);
        expect(result.user.id).toBe(user.id);
    });

    it("should reject an unknown user", async () => {
        const { auth } = await setup();

        await expect(
            auth.changePassword("nope", { currentPassword: "akash", newPassword: "x" })
        ).rejects.toMatchObject({ code: "USER_NOT_FOUND" });
    });

    it("should reject empty passwords", async () => {
        const { auth, user } = await setup();

        await expect(
            auth.changePassword(user.id, { currentPassword: "akash", newPassword: "" })
        ).rejects.toMatchObject({ code: "INVALID_INPUT" });

        await expect(
            auth.changePassword(user.id, { currentPassword: "", newPassword: "x" })
        ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    });

    it("should throw a clear error when the adapter lacks updatePassword", async () => {
        const adapter = new MemoryAdapter();
        const plain = withoutOptionalMethods(adapter);

        const auth = createAuth({ adapter: plain, refreshTokenAdapter: plain, secret });

        await expect(
            auth.changePassword("1", { currentPassword: "a", newPassword: "b" })
        ).rejects.toThrow(/updatePassword/);
    });

    it("should call afterPasswordChange", async () => {
        const afterPasswordChange = vi.fn();
        const { auth, user } = await setup({ hooks: { afterPasswordChange } });

        await auth.changePassword(user.id, { currentPassword: "akash", newPassword: "new-password" });

        expect(afterPasswordChange).toHaveBeenCalledWith({ id: user.id, email: "akash@gmail.com", emailVerifiedAt: null });
    });

});

describe("verify", () => {

    it("should return the token payload without hitting the database", async () => {
        const { adapter, auth, user } = await setup();

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });

        const findUserById = vi.spyOn(adapter, "findUserById");

        const payload = await auth.verify(login.token);

        expect(payload.userId).toBe(user.id);
        expect(payload.issuedAt).toBeInstanceOf(Date);
        expect(payload.expiresAt.getTime()).toBeGreaterThan(Date.now());
        expect(findUserById).not.toHaveBeenCalled();
    });

    it("should still accept a token after the user is deleted, unlike authenticate", async () => {
        const { adapter, auth, user } = await setup();

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });
        adapter.deleteUser(user.id);

        await expect(auth.verify(login.token)).resolves.toMatchObject({ userId: user.id });
        await expect(auth.authenticate(login.token)).rejects.toMatchObject({ reason: "USER_NOT_FOUND" });
    });

    it("should reject invalid tokens with a reason", async () => {
        const { auth } = await setup();

        await expect(auth.verify("garbage")).rejects.toMatchObject({
            code: "AUTHENTICATION_FAILED",
            reason: "TOKEN_INVALID"
        });
    });

    it("should honour jwt issuer and audience config", async () => {
        const { auth } = await setup({ jwt: { issuer: "sentra", audience: "api" } });
        const { auth: other } = await setup({ jwt: { issuer: "other" } });

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });

        await expect(auth.verify(login.token)).resolves.toMatchObject({ userId: expect.any(String) });
        await expect(other.verify(login.token)).rejects.toMatchObject({ reason: "TOKEN_INVALID" });
    });

});
