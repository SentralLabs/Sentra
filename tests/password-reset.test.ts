import { describe, it, expect, vi } from "vitest";
import { createAuth, AuthError, MemoryAdapter } from "../src/index.js";
import type { DeliveryHookData, Logger, PasswordHasher } from "../src/index.js";
import bcrypt from "bcrypt";

const secret = "test-secret-that-is-at-least-32-bytes-long";

function silentLogger() {
    return { warn: vi.fn<Logger["warn"]>(), error: vi.fn<Logger["error"]>() };
}

async function setup(extra: Partial<Parameters<typeof createAuth>[0]> = {}) {
    const adapter = new MemoryAdapter();
    const sendPasswordReset = vi.fn<(data: DeliveryHookData) => void>();

    const user = await adapter.createUser({
        email: "akash@gmail.com",
        passwordHash: await bcrypt.hash("akash", 4)
    });

    const auth = createAuth({
        adapter,
        refreshTokenAdapter: adapter,
        secret,
        bcryptCost: 4,
        ...extra,
        hooks: { sendPasswordReset, ...extra.hooks }
    });

    async function requestToken(): Promise<string> {
        await auth.requestPasswordReset("akash@gmail.com");
        return sendPasswordReset.mock.calls.at(-1)![0].token;
    }

    return { adapter, auth, user, sendPasswordReset, requestToken };
}

describe("requestPasswordReset", () => {

    it("should hand the user, a token and an expiry to the delivery hook", async () => {
        const { auth, user, sendPasswordReset } = await setup({ passwordResetExpiry: "30m" });

        const before = Date.now();
        await auth.requestPasswordReset("akash@gmail.com");

        expect(sendPasswordReset).toHaveBeenCalledTimes(1);
        const data = sendPasswordReset.mock.calls[0]![0];

        expect(data.user).toEqual({ id: user.id, email: "akash@gmail.com", emailVerifiedAt: null });
        expect(data.user).not.toHaveProperty("passwordHash");
        expect(data.token).toBeTypeOf("string");
        expect(data.token.split(".")).toHaveLength(3);
        expect(data.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 30 * 60_000 - 1000);
        expect(data.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 30 * 60_000);
    });

    it("should normalise the email", async () => {
        const { auth, sendPasswordReset } = await setup();

        await auth.requestPasswordReset("  Akash@Gmail.com ");

        expect(sendPasswordReset).toHaveBeenCalledTimes(1);
    });

    it("should resolve silently for an unknown email without calling the hook", async () => {
        const { auth, sendPasswordReset } = await setup();

        await expect(auth.requestPasswordReset("nobody@gmail.com")).resolves.toBeUndefined();

        expect(sendPasswordReset).not.toHaveBeenCalled();
    });

    it("should reject an empty email", async () => {
        const { auth } = await setup();

        await expect(auth.requestPasswordReset("")).rejects.toMatchObject({ code: "INVALID_INPUT" });
    });

    it("should propagate a delivery failure", async () => {
        const { auth } = await setup({
            hooks: { sendPasswordReset: () => { throw new Error("smtp down"); } }
        });

        await expect(auth.requestPasswordReset("akash@gmail.com")).rejects.toThrow("smtp down");
    });

    it("should throw a clear error when the hook is not configured", async () => {
        const adapter = new MemoryAdapter();
        const auth = createAuth({ adapter, refreshTokenAdapter: adapter, secret });

        await expect(auth.requestPasswordReset("akash@gmail.com")).rejects.toThrow(/sendPasswordReset/);
    });

});

describe("resetPassword", () => {

    it("should replace the password so only the new one logs in", async () => {
        const { adapter, auth, user, requestToken } = await setup();

        const before = adapter.getUsers()[0]!.passwordHash;
        await auth.resetPassword(await requestToken(), "new-password");

        expect(adapter.getUsers()[0]!.passwordHash).not.toBe(before);

        await expect(
            auth.login({ email: "akash@gmail.com", password: "akash" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        const result = await auth.login({ email: "akash@gmail.com", password: "new-password" });
        expect(result.user.id).toBe(user.id);
    });

    it("should make the token single-use", async () => {
        const { auth, requestToken } = await setup();

        const token = await requestToken();
        await auth.resetPassword(token, "new-password");

        await expect(
            auth.resetPassword(token, "another")
        ).rejects.toMatchObject({ code: "INVALID_TOKEN", reason: "RESET_TOKEN_INVALID" });
    });

    it("should invalidate every outstanding token once one is used", async () => {
        const { auth, requestToken } = await setup();

        const first = await requestToken();
        const second = await requestToken();
        expect(first).not.toBe(second);

        await auth.resetPassword(second, "new-password");

        await expect(auth.resetPassword(first, "x")).rejects.toMatchObject({ reason: "RESET_TOKEN_INVALID" });
    });

    it("should invalidate the token when the password changes another way", async () => {
        const { auth, user, requestToken } = await setup();

        const token = await requestToken();
        await auth.changePassword(user.id, { currentPassword: "akash", newPassword: "changed" });

        await expect(auth.resetPassword(token, "x")).rejects.toMatchObject({ reason: "RESET_TOKEN_INVALID" });
    });

    it("should report an expired token distinctly", async () => {
        const { auth, requestToken } = await setup({ passwordResetExpiry: "0s" });

        await expect(
            auth.resetPassword(await requestToken(), "x")
        ).rejects.toMatchObject({ code: "INVALID_TOKEN", reason: "RESET_TOKEN_EXPIRED" });
    });

    it("should reject garbage, empty and tampered tokens", async () => {
        const { auth, requestToken } = await setup();

        await expect(auth.resetPassword("garbage", "x")).rejects.toMatchObject({ reason: "RESET_TOKEN_INVALID" });
        await expect(auth.resetPassword("", "x")).rejects.toMatchObject({ code: "INVALID_INPUT" });

        const parts = (await requestToken()).split(".");
        parts[1] = parts[1] + "x";
        await expect(auth.resetPassword(parts.join("."), "x")).rejects.toMatchObject({ reason: "RESET_TOKEN_INVALID" });
    });

    it("should reject an access token", async () => {
        const { auth } = await setup();

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });

        await expect(auth.resetPassword(login.token, "x")).rejects.toMatchObject({ reason: "RESET_TOKEN_INVALID" });
    });

    it("should reject a token for a user that no longer exists", async () => {
        const { adapter, auth, user, requestToken } = await setup();

        const token = await requestToken();
        adapter.deleteUser(user.id);

        await expect(auth.resetPassword(token, "x")).rejects.toMatchObject({ reason: "RESET_TOKEN_INVALID" });
    });

    it("should reject an empty new password without consuming the token", async () => {
        const { auth, requestToken } = await setup();

        const token = await requestToken();

        await expect(auth.resetPassword(token, "")).rejects.toMatchObject({ code: "INVALID_INPUT" });

        await expect(auth.resetPassword(token, "fine")).resolves.toBeUndefined();
    });

    it("should sign the user out everywhere", async () => {
        const { auth, requestToken } = await setup();

        const phone = await auth.login({ email: "akash@gmail.com", password: "akash" });
        const laptop = await auth.login({ email: "akash@gmail.com", password: "akash" });

        await auth.resetPassword(await requestToken(), "new-password");

        await expect(auth.refresh(phone.refreshToken)).rejects.toBeInstanceOf(AuthError);
        await expect(auth.refresh(laptop.refreshToken)).rejects.toBeInstanceOf(AuthError);
    });

    it("should still work when the refresh adapter cannot revoke by user", async () => {
        const adapter = new MemoryAdapter();
        await adapter.createUser({ email: "akash@gmail.com", passwordHash: await bcrypt.hash("akash", 4) });
        const sendPasswordReset = vi.fn<(data: DeliveryHookData) => void>();

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: {
                findSessionByTokenHash: adapter.findSessionByTokenHash.bind(adapter),
                createSession: adapter.createSession.bind(adapter),
                revokeSession: adapter.revokeSession.bind(adapter),
                revokeFamily: adapter.revokeFamily.bind(adapter)
            },
            secret,
            bcryptCost: 4,
            hooks: { sendPasswordReset }
        });

        const phone = await auth.login({ email: "akash@gmail.com", password: "akash" });
        await auth.requestPasswordReset("akash@gmail.com");

        await auth.resetPassword(sendPasswordReset.mock.calls[0]![0].token, "new-password");

        const result = await auth.refresh(phone.refreshToken);
        expect(result.user.email).toBe("akash@gmail.com");
    });

    it("should throw a clear error when the adapter lacks updatePassword", async () => {
        const adapter = new MemoryAdapter();
        await adapter.createUser({ email: "akash@gmail.com", passwordHash: "x" });
        const sendPasswordReset = vi.fn<(data: DeliveryHookData) => void>();

        const auth = createAuth({
            adapter: {
                findUserByEmail: adapter.findUserByEmail.bind(adapter),
                findUserById: adapter.findUserById.bind(adapter),
                createUser: adapter.createUser.bind(adapter)
            },
            refreshTokenAdapter: adapter,
            secret,
            hooks: { sendPasswordReset }
        });

        await auth.requestPasswordReset("akash@gmail.com");

        await expect(
            auth.resetPassword(sendPasswordReset.mock.calls[0]![0].token, "x")
        ).rejects.toThrow(/updatePassword/);
    });

    it("should use the configured password hasher", async () => {
        const hasher: PasswordHasher = {
            hash: async password => `fake:${password}`,
            compare: async (password, hash) => hash === `fake:${password}`
        };
        const { adapter, auth, requestToken } = await setup({ passwordHasher: hasher });

        // The existing user has a bcrypt hash; the reset token is bound to it
        await auth.resetPassword(await requestToken(), "new-password");

        expect(adapter.getUsers()[0]!.passwordHash).toBe("fake:new-password");
    });

    it("should call afterPasswordReset and survive its failure", async () => {
        const logger = silentLogger();
        const afterPasswordReset = vi.fn(() => { throw new Error("boom"); });
        const { auth, user, requestToken } = await setup({ logger, hooks: { afterPasswordReset } });

        await expect(auth.resetPassword(await requestToken(), "new-password")).resolves.toBeUndefined();

        expect(afterPasswordReset).toHaveBeenCalledWith({ id: user.id, email: "akash@gmail.com", emailVerifiedAt: null });
        expect(logger.error).toHaveBeenCalledWith(expect.stringContaining("afterPasswordReset"), expect.any(Error));
    });

});
