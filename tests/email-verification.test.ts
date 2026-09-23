import { describe, it, expect, vi } from "vitest";
import { createAuth, MemoryAdapter } from "../src/index.js";
import type { DeliveryHookData, Logger } from "../src/index.js";

const secret = "test-secret-that-is-at-least-32-bytes-long";

function silentLogger() {
    return { warn: vi.fn<Logger["warn"]>(), error: vi.fn<Logger["error"]>() };
}

function setup(extra: Partial<Parameters<typeof createAuth>[0]> = {}) {
    const adapter = new MemoryAdapter();
    const sendEmailVerification = vi.fn<(data: DeliveryHookData) => void>();

    const auth = createAuth({
        adapter,
        refreshTokenAdapter: adapter,
        secret,
        bcryptCost: 4,
        ...extra,
        hooks: { sendEmailVerification, ...extra.hooks }
    });

    function lastToken(): string {
        return sendEmailVerification.mock.calls.at(-1)![0].token;
    }

    return { adapter, auth, sendEmailVerification, lastToken };
}

describe("signUp with email verification", () => {

    it("should send a verification link when the hook is configured", async () => {
        const { auth, sendEmailVerification } = setup({ emailVerificationExpiry: "2h" });

        const before = Date.now();
        const user = await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        expect(sendEmailVerification).toHaveBeenCalledTimes(1);
        const data = sendEmailVerification.mock.calls[0]![0];

        expect(data.user).toEqual({ id: user.id, email: "akash@gmail.com", emailVerifiedAt: null });
        expect(data.token).toBeTypeOf("string");
        expect(data.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 2 * 3_600_000 - 1000);
    });

    it("should not send anything when the hook is not configured", async () => {
        const adapter = new MemoryAdapter();
        const auth = createAuth({ adapter, refreshTokenAdapter: adapter, secret, bcryptCost: 4 });

        const user = await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        expect(user.emailVerifiedAt).toBeNull();
    });

    it("should still create the account when delivery fails", async () => {
        const logger = silentLogger();
        const { adapter, auth } = setup({
            logger,
            hooks: { sendEmailVerification: () => { throw new Error("smtp down"); } }
        });

        const user = await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        expect(adapter.getUsers()[0]!.id).toBe(user.id);
        expect(logger.error).toHaveBeenCalledWith(expect.stringContaining("sendEmailVerification"), expect.any(Error));
    });

    it("should return emailVerifiedAt as null on the new user", async () => {
        const { auth } = setup();

        const user = await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        expect(user.emailVerifiedAt).toBeNull();
    });

});

describe("requestEmailVerification", () => {

    it("should resend a fresh token for an unverified user", async () => {
        const { auth, sendEmailVerification } = setup();

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        await auth.requestEmailVerification(" Akash@Gmail.com ");

        expect(sendEmailVerification).toHaveBeenCalledTimes(2);
        const [first, second] = sendEmailVerification.mock.calls.map(call => call[0].token);
        expect(first).not.toBe(second);
    });

    it("should be a no-op for an unknown email", async () => {
        const { auth, sendEmailVerification } = setup();

        await expect(auth.requestEmailVerification("nobody@gmail.com")).resolves.toBeUndefined();

        expect(sendEmailVerification).not.toHaveBeenCalled();
    });

    it("should be a no-op for an already verified email", async () => {
        const { auth, sendEmailVerification, lastToken } = setup();

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        await auth.verifyEmail(lastToken());

        await auth.requestEmailVerification("akash@gmail.com");

        expect(sendEmailVerification).toHaveBeenCalledTimes(1);
    });

    it("should propagate a delivery failure", async () => {
        const { auth } = setup({
            logger: silentLogger(),
            hooks: { sendEmailVerification: () => { throw new Error("smtp down"); } }
        });

        // Signup swallows the failure; an explicit resend must surface it
        await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        await expect(auth.requestEmailVerification("akash@gmail.com")).rejects.toThrow("smtp down");
    });

    it("should throw a clear error when the hook is not configured", async () => {
        const adapter = new MemoryAdapter();
        const auth = createAuth({ adapter, refreshTokenAdapter: adapter, secret });

        await expect(auth.requestEmailVerification("akash@gmail.com")).rejects.toThrow(/sendEmailVerification/);
    });

});

describe("verifyEmail", () => {

    it("should mark the email verified and return the user", async () => {
        const { adapter, auth, lastToken } = setup();

        const created = await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        const before = Date.now();

        const user = await auth.verifyEmail(lastToken());

        expect(user.id).toBe(created.id);
        expect(user.emailVerifiedAt).toBeInstanceOf(Date);
        expect(user.emailVerifiedAt!.getTime()).toBeGreaterThanOrEqual(before);
        expect(adapter.getUsers()[0]!.emailVerifiedAt).toEqual(user.emailVerifiedAt);
    });

    it("should be idempotent", async () => {
        const { adapter, auth, lastToken } = setup();
        const setEmailVerified = vi.spyOn(adapter, "setEmailVerified");

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        const token = lastToken();

        const first = await auth.verifyEmail(token);
        const second = await auth.verifyEmail(token);

        expect(second.emailVerifiedAt).toEqual(first.emailVerifiedAt);
        expect(setEmailVerified).toHaveBeenCalledTimes(1);
    });

    it("should report an expired token distinctly", async () => {
        const { auth, lastToken } = setup({ emailVerificationExpiry: "0s" });

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        await expect(auth.verifyEmail(lastToken())).rejects.toMatchObject({
            code: "INVALID_TOKEN",
            reason: "VERIFICATION_TOKEN_EXPIRED"
        });
    });

    it("should reject garbage, empty and tampered tokens", async () => {
        const { auth, lastToken } = setup();

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        await expect(auth.verifyEmail("garbage")).rejects.toMatchObject({ reason: "VERIFICATION_TOKEN_INVALID" });
        await expect(auth.verifyEmail("")).rejects.toMatchObject({ code: "INVALID_INPUT" });

        const parts = lastToken().split(".");
        parts[2] = parts[2]!.slice(0, -2) + "xx";
        await expect(auth.verifyEmail(parts.join("."))).rejects.toMatchObject({ reason: "VERIFICATION_TOKEN_INVALID" });
    });

    it("should reject a password-reset token", async () => {
        const sendPasswordReset = vi.fn<(data: DeliveryHookData) => void>();
        const { auth } = setup({ hooks: { sendPasswordReset } });

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        await auth.requestPasswordReset("akash@gmail.com");

        await expect(
            auth.verifyEmail(sendPasswordReset.mock.calls[0]![0].token)
        ).rejects.toMatchObject({ reason: "VERIFICATION_TOKEN_INVALID" });
    });

    it("should reject the token after the email address changes", async () => {
        const { adapter, auth, lastToken } = setup();

        const user = await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        const token = lastToken();

        adapter.setEmail(user.id, "other@gmail.com");

        await expect(auth.verifyEmail(token)).rejects.toMatchObject({ reason: "VERIFICATION_TOKEN_INVALID" });
    });

    it("should reject a token for a deleted user", async () => {
        const { adapter, auth, lastToken } = setup();

        const user = await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        adapter.deleteUser(user.id);

        await expect(auth.verifyEmail(lastToken())).rejects.toMatchObject({ reason: "VERIFICATION_TOKEN_INVALID" });
    });

    it("should throw a clear error when the adapter lacks setEmailVerified", async () => {
        const adapter = new MemoryAdapter();
        const sendEmailVerification = vi.fn<(data: DeliveryHookData) => void>();

        const auth = createAuth({
            adapter: {
                findUserByEmail: adapter.findUserByEmail.bind(adapter),
                findUserById: adapter.findUserById.bind(adapter),
                createUser: adapter.createUser.bind(adapter)
            },
            refreshTokenAdapter: adapter,
            secret,
            bcryptCost: 4,
            hooks: { sendEmailVerification }
        });

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        await expect(
            auth.verifyEmail(sendEmailVerification.mock.calls[0]![0].token)
        ).rejects.toThrow(/setEmailVerified/);
    });

    it("should call afterEmailVerified and survive its failure", async () => {
        const logger = silentLogger();
        const afterEmailVerified = vi.fn(() => { throw new Error("boom"); });
        const { auth, lastToken } = setup({ logger, hooks: { afterEmailVerified } });

        const created = await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        const user = await auth.verifyEmail(lastToken());

        expect(afterEmailVerified).toHaveBeenCalledWith({ id: created.id, email: "akash@gmail.com", emailVerifiedAt: user.emailVerifiedAt });
        expect(logger.error).toHaveBeenCalledWith(expect.stringContaining("afterEmailVerified"), expect.any(Error));
    });

});

describe("requireEmailVerification", () => {

    it("should be off by default", async () => {
        const { auth } = setup();

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        const result = await auth.login({ email: "akash@gmail.com", password: "akash" });
        expect(result.user.emailVerifiedAt).toBeNull();
    });

    it("should block login for an unverified user", async () => {
        const { auth } = setup({ requireEmailVerification: true });

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        await expect(
            auth.login({ email: "akash@gmail.com", password: "akash" })
        ).rejects.toMatchObject({ code: "EMAIL_NOT_VERIFIED" });
    });

    it("should allow login once verified", async () => {
        const { auth, lastToken } = setup({ requireEmailVerification: true });

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        await auth.verifyEmail(lastToken());

        const result = await auth.login({ email: "akash@gmail.com", password: "akash" });
        expect(result.user.emailVerifiedAt).toBeInstanceOf(Date);
    });

    it("should check the password before revealing verification status", async () => {
        const onLoginFailed = vi.fn();
        const { auth } = setup({ requireEmailVerification: true, hooks: { onLoginFailed } });

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        await expect(
            auth.login({ email: "akash@gmail.com", password: "wrong" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        expect(onLoginFailed).toHaveBeenCalledWith({ email: "akash@gmail.com", reason: "INVALID_PASSWORD" });
    });

    it("should not count the gate as a failed login", async () => {
        const onLoginFailed = vi.fn();
        const { auth } = setup({ requireEmailVerification: true, hooks: { onLoginFailed } });

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        await expect(auth.login({ email: "akash@gmail.com", password: "akash" })).rejects.toBeDefined();

        expect(onLoginFailed).not.toHaveBeenCalled();
    });

    it("should not affect refresh of an existing session", async () => {
        const adapter = new MemoryAdapter();
        const open = createAuth({ adapter, refreshTokenAdapter: adapter, secret, bcryptCost: 4 });
        await open.signUp({ email: "akash@gmail.com", password: "akash" });
        const login = await open.login({ email: "akash@gmail.com", password: "akash" });

        // Verification becomes required after the user is already logged in
        const gated = createAuth({ adapter, refreshTokenAdapter: adapter, secret, bcryptCost: 4, requireEmailVerification: true });

        const result = await gated.refresh(login.refreshToken);
        expect(result.user.email).toBe("akash@gmail.com");
    });

    it("should treat an adapter that does not track verification as unverified", async () => {
        const adapter = new MemoryAdapter();
        await adapter.createUser({ email: "akash@gmail.com", passwordHash: await (await import("bcrypt")).default.hash("akash", 4) });
        delete adapter.getUsers()[0]!.emailVerifiedAt;

        const auth = createAuth({ adapter, refreshTokenAdapter: adapter, secret, requireEmailVerification: true });

        await expect(
            auth.login({ email: "akash@gmail.com", password: "akash" })
        ).rejects.toMatchObject({ code: "EMAIL_NOT_VERIFIED" });
    });

});

describe("emailVerifiedAt on User", () => {

    it("should be omitted when the adapter does not track it", async () => {
        const adapter = new MemoryAdapter();
        await adapter.createUser({ email: "akash@gmail.com", passwordHash: await (await import("bcrypt")).default.hash("akash", 4) });
        delete adapter.getUsers()[0]!.emailVerifiedAt;

        const auth = createAuth({ adapter, refreshTokenAdapter: adapter, secret });

        const result = await auth.login({ email: "akash@gmail.com", password: "akash" });
        expect("emailVerifiedAt" in result.user).toBe(false);

        const authenticated = await auth.authenticate(result.token);
        expect("emailVerifiedAt" in authenticated).toBe(false);
    });

    it("should be mirrored through login, authenticate and refresh", async () => {
        const { auth, lastToken } = setup();

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        const verified = await auth.verifyEmail(lastToken());

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });
        expect(login.user.emailVerifiedAt).toEqual(verified.emailVerifiedAt);

        const authenticated = await auth.authenticate(login.token);
        expect(authenticated.emailVerifiedAt).toEqual(verified.emailVerifiedAt);

        const refreshed = await auth.refresh(login.refreshToken);
        expect(refreshed.user.emailVerifiedAt).toEqual(verified.emailVerifiedAt);
    });

});
