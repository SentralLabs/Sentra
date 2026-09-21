import { describe, it, expect, vi } from "vitest";
import { createAuth, MemoryAdapter } from "../src/index.js";
import type { Logger } from "../src/index.js";
import bcrypt from "bcrypt";

const secret = "test-secret-that-is-at-least-32-bytes-long";

function silentLogger() {
    return {
        warn: vi.fn<Logger["warn"]>(),
        error: vi.fn<Logger["error"]>()
    };
}

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

describe("onLoginFailed", () => {

    it("should fire with USER_NOT_FOUND for an unknown email", async () => {
        const onLoginFailed = vi.fn();
        const { auth } = await setup({ hooks: { onLoginFailed } });

        await expect(
            auth.login({ email: "Nobody@Gmail.com", password: "x" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        expect(onLoginFailed).toHaveBeenCalledWith({ email: "nobody@gmail.com", reason: "USER_NOT_FOUND" });
    });

    it("should fire with INVALID_PASSWORD for a wrong password", async () => {
        const onLoginFailed = vi.fn();
        const { auth } = await setup({ hooks: { onLoginFailed } });

        await expect(
            auth.login({ email: "akash@gmail.com", password: "wrong" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        expect(onLoginFailed).toHaveBeenCalledWith({ email: "akash@gmail.com", reason: "INVALID_PASSWORD" });
    });

    it("should not fire on a successful login", async () => {
        const onLoginFailed = vi.fn();
        const { auth } = await setup({ hooks: { onLoginFailed } });

        await auth.login({ email: "akash@gmail.com", password: "akash" });

        expect(onLoginFailed).not.toHaveBeenCalled();
    });

    it("should not fire when beforeLogin aborts the login", async () => {
        const onLoginFailed = vi.fn();
        const { auth } = await setup({
            hooks: {
                onLoginFailed,
                beforeLogin: () => { throw new Error("suspended"); }
            }
        });

        await expect(
            auth.login({ email: "akash@gmail.com", password: "akash" })
        ).rejects.toThrow("suspended");

        expect(onLoginFailed).not.toHaveBeenCalled();
    });

    it("should still reject the login if the hook throws", async () => {
        const logger = silentLogger();
        const { auth } = await setup({
            logger,
            hooks: { onLoginFailed: () => { throw new Error("boom"); } }
        });

        await expect(
            auth.login({ email: "akash@gmail.com", password: "wrong" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        expect(logger.error).toHaveBeenCalledTimes(1);
    });

});

describe("onReuseDetected", () => {

    it("should fire with the family and session of the replayed token", async () => {
        const onReuseDetected = vi.fn();
        const { adapter, auth, user } = await setup({ hooks: { onReuseDetected } });

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });
        await auth.refresh(login.refreshToken);

        await expect(
            auth.refresh(login.refreshToken)
        ).rejects.toMatchObject({ reason: "REFRESH_TOKEN_REUSED" });

        const original = adapter.getSessions()[0]!;

        expect(onReuseDetected).toHaveBeenCalledWith({
            userId: user.id,
            familyId: original.familyId,
            sessionId: original.sessionId
        });
    });

    it("should fire after the family has been revoked", async () => {
        const { adapter, auth } = await setup({
            hooks: {
                onReuseDetected: async () => {
                    expect(adapter.getSessions().every(s => s.revokedAt !== null)).toBe(true);
                }
            }
        });

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });
        await auth.refresh(login.refreshToken);

        await expect(auth.refresh(login.refreshToken)).rejects.toBeDefined();
    });

    it("should not fire for a tolerated concurrent refresh", async () => {
        const onReuseDetected = vi.fn();
        const { auth } = await setup({ refreshTokenGracePeriod: "10s", hooks: { onReuseDetected } });

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });
        await auth.refresh(login.refreshToken);
        await auth.refresh(login.refreshToken);

        expect(onReuseDetected).not.toHaveBeenCalled();
    });

});

describe("beforeRefresh / afterRefresh", () => {

    it("should call both hooks with the user on a successful refresh", async () => {
        const beforeRefresh = vi.fn();
        const afterRefresh = vi.fn();
        const { auth, user } = await setup({ hooks: { beforeRefresh, afterRefresh } });

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });
        await auth.refresh(login.refreshToken);

        const expected = { id: user.id, email: "akash@gmail.com" };
        expect(beforeRefresh).toHaveBeenCalledWith(expected);
        expect(afterRefresh).toHaveBeenCalledWith(expected);
    });

    it("should abort the refresh without rotating when beforeRefresh throws", async () => {
        const { adapter, auth } = await setup({
            hooks: { beforeRefresh: () => { throw new Error("account locked"); } }
        });

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });

        await expect(auth.refresh(login.refreshToken)).rejects.toThrow("account locked");

        // Token was not rotated, so it is still usable once the hook allows it
        expect(adapter.getSessions()).toHaveLength(1);
        expect(adapter.getSessions()[0]!.revokedAt).toBeNull();
    });

    it("should not call beforeRefresh for an invalid token", async () => {
        const beforeRefresh = vi.fn();
        const { auth } = await setup({ hooks: { beforeRefresh } });

        await expect(auth.refresh("nope")).rejects.toBeDefined();

        expect(beforeRefresh).not.toHaveBeenCalled();
    });

    it("should still return the result when afterRefresh throws", async () => {
        const logger = silentLogger();
        const { auth } = await setup({
            logger,
            hooks: { afterRefresh: () => { throw new Error("boom"); } }
        });

        const login = await auth.login({ email: "akash@gmail.com", password: "akash" });
        const result = await auth.refresh(login.refreshToken);

        expect(result.token).toBeTypeOf("string");
        expect(logger.error).toHaveBeenCalledWith(expect.stringContaining("afterRefresh"), expect.any(Error));
    });

});

describe("logger", () => {

    it("should route hook failures to the configured logger instead of console", async () => {
        const logger = silentLogger();
        const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

        const { auth } = await setup({
            logger,
            hooks: { afterLogin: () => { throw new Error("boom"); } }
        });

        await auth.login({ email: "akash@gmail.com", password: "akash" });

        expect(logger.error).toHaveBeenCalledTimes(1);
        expect(consoleError).not.toHaveBeenCalled();

        consoleError.mockRestore();
    });

    it("should route the short-secret warning to the configured logger", async () => {
        const logger = silentLogger();
        const adapter = new MemoryAdapter();

        createAuth({ adapter, refreshTokenAdapter: adapter, secret: "short", logger });

        expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining("32 bytes"));
    });

});
