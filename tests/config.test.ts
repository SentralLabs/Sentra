import { describe, it, expect, vi, afterEach } from "vitest";
import { createAuth } from "../src/index.js";
import { MemoryAdapter } from "../src/adapters/memory.js";

const secret = "test-secret-that-is-at-least-32-bytes-long";

function base() {
    const adapter = new MemoryAdapter();
    return { adapter, refreshTokenAdapter: adapter, secret };
}

describe("createAuth config validation", () => {

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("should accept a valid config", () => {
        expect(() => createAuth(base())).not.toThrow();
    });

    it("should reject an empty secret", () => {
        expect(() => createAuth({ ...base(), secret: "" })).toThrow(/secret/);
    });

    it("should reject a missing secret", () => {
        expect(() =>
            createAuth({ ...base(), secret: undefined as unknown as string })
        ).toThrow(/secret/);
    });

    it("should warn on a secret shorter than 32 bytes", () => {
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

        createAuth({ ...base(), secret: "short" });

        expect(warn).toHaveBeenCalledTimes(1);
        expect(warn.mock.calls[0]![0]).toMatch(/32 bytes/);
    });

    it("should not warn on a secret of 32 bytes or more", () => {
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

        createAuth(base());

        expect(warn).not.toHaveBeenCalled();
    });

    it("should reject an invalid tokenExpiry at startup", () => {
        expect(() =>
            createAuth({ ...base(), tokenExpiry: "soon" })
        ).toThrow(/tokenExpiry/);
    });

    it("should reject an invalid refreshTokenExpiry at startup", () => {
        expect(() =>
            createAuth({ ...base(), refreshTokenExpiry: "30" })
        ).toThrow(/refreshTokenExpiry/);
    });

    it("should reject an invalid absoluteSessionExpiry at startup", () => {
        expect(() =>
            createAuth({ ...base(), absoluteSessionExpiry: "forever" })
        ).toThrow(/absoluteSessionExpiry/);
    });

    it("should reject an invalid refreshTokenGracePeriod at startup", () => {
        expect(() =>
            createAuth({ ...base(), refreshTokenGracePeriod: "10" })
        ).toThrow(/refreshTokenGracePeriod/);
    });

    it("should accept the same duration formats for access and refresh tokens", () => {
        expect(() =>
            createAuth({ ...base(), tokenExpiry: "30s", refreshTokenExpiry: "2 weeks" })
        ).not.toThrow();
    });

    it("should require findSessionsByFamilyId when a grace period is set", () => {
        const adapter = new MemoryAdapter();

        expect(() =>
            createAuth({
                adapter,
                refreshTokenAdapter: {
                    findSessionByTokenHash: adapter.findSessionByTokenHash.bind(adapter),
                    createSession: adapter.createSession.bind(adapter),
                    revokeSession: adapter.revokeSession.bind(adapter),
                    revokeFamily: adapter.revokeFamily.bind(adapter)
                },
                secret,
                refreshTokenGracePeriod: "10s"
            })
        ).toThrow(/findSessionsByFamilyId/);
    });

    it("should not require findSessionsByFamilyId when no grace period is set", () => {
        const adapter = new MemoryAdapter();

        expect(() =>
            createAuth({
                adapter,
                refreshTokenAdapter: {
                    findSessionByTokenHash: adapter.findSessionByTokenHash.bind(adapter),
                    createSession: adapter.createSession.bind(adapter),
                    revokeSession: adapter.revokeSession.bind(adapter),
                    revokeFamily: adapter.revokeFamily.bind(adapter)
                },
                secret
            })
        ).not.toThrow();
    });

});
