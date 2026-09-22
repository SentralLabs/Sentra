import { describe, it, expect, vi } from "vitest";
import { createAuth, createBcryptHasher, MemoryAdapter } from "../src/index.js";
import type { PasswordHasher } from "../src/index.js";
import bcrypt from "bcrypt";

const secret = "test-secret-that-is-at-least-32-bytes-long";

describe("bcryptCost", () => {

    it("should default to a cost of 10", async () => {
        const adapter = new MemoryAdapter();
        const auth = createAuth({ adapter, refreshTokenAdapter: adapter, secret });

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        expect(bcrypt.getRounds(adapter.getUsers()[0]!.passwordHash)).toBe(10);
    });

    it("should honour a custom cost", async () => {
        const adapter = new MemoryAdapter();
        const auth = createAuth({ adapter, refreshTokenAdapter: adapter, secret, bcryptCost: 4 });

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });

        expect(bcrypt.getRounds(adapter.getUsers()[0]!.passwordHash)).toBe(4);
    });

    it("should reject an out-of-range cost at startup", () => {
        const adapter = new MemoryAdapter();

        expect(() =>
            createAuth({ adapter, refreshTokenAdapter: adapter, secret, bcryptCost: 3 })
        ).toThrow(/bcryptCost/);
        expect(() =>
            createAuth({ adapter, refreshTokenAdapter: adapter, secret, bcryptCost: 10.5 })
        ).toThrow(/bcryptCost/);
    });

    it("createBcryptHasher should round-trip", async () => {
        const hasher = createBcryptHasher(4);
        const hash = await hasher.hash("pw");

        expect(await hasher.compare("pw", hash)).toBe(true);
        expect(await hasher.compare("nope", hash)).toBe(false);
    });

});

describe("passwordHasher", () => {

    function fakeHasher() {
        return {
            hash: vi.fn<PasswordHasher["hash"]>(async password => `fake:${password}`),
            compare: vi.fn<PasswordHasher["compare"]>(async (password, hash) => hash === `fake:${password}`)
        };
    }

    it("should be used for signup and login instead of bcrypt", async () => {
        const adapter = new MemoryAdapter();
        const hasher = fakeHasher();
        const auth = createAuth({ adapter, refreshTokenAdapter: adapter, secret, passwordHasher: hasher });

        await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        expect(adapter.getUsers()[0]!.passwordHash).toBe("fake:akash");

        const result = await auth.login({ email: "akash@gmail.com", password: "akash" });
        expect(result.user.email).toBe("akash@gmail.com");

        await expect(
            auth.login({ email: "akash@gmail.com", password: "wrong" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        expect(hasher.hash).toHaveBeenCalled();
        expect(hasher.compare).toHaveBeenCalled();
    });

    it("should be used for the unknown-user dummy comparison", async () => {
        const adapter = new MemoryAdapter();
        const hasher = fakeHasher();
        const auth = createAuth({ adapter, refreshTokenAdapter: adapter, secret, passwordHasher: hasher });

        await expect(
            auth.login({ email: "nobody@gmail.com", password: "x" })
        ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

        expect(hasher.compare).toHaveBeenCalledTimes(1);
    });

    it("should be used by changePassword", async () => {
        const adapter = new MemoryAdapter();
        const hasher = fakeHasher();
        const auth = createAuth({ adapter, refreshTokenAdapter: adapter, secret, passwordHasher: hasher });

        const user = await auth.signUp({ email: "akash@gmail.com", password: "akash" });
        await auth.changePassword(user.id, { currentPassword: "akash", newPassword: "next" });

        expect(adapter.getUsers()[0]!.passwordHash).toBe("fake:next");
    });

    it("should warn when bcryptCost is also given", () => {
        const adapter = new MemoryAdapter();
        const logger = { warn: vi.fn(), error: vi.fn() };

        createAuth({ adapter, refreshTokenAdapter: adapter, secret, passwordHasher: fakeHasher(), bcryptCost: 12, logger });

        expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining("bcryptCost"));
    });

});
