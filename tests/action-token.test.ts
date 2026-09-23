import { describe, it, expect } from "vitest";
import { SignJWT } from "jose";
import {
    ActionTokenError,
    createActionToken,
    deriveActionKey,
    peekActionToken,
    verifyActionToken
} from "../src/jwt/action-token.js";
import { createToken } from "../src/jwt/token.js";

const secret = "test-secret-that-is-at-least-32-bytes-long";
const userId = "user-1";

describe("Action tokens", () => {

    it("should round-trip with the same key", async () => {
        const key = deriveActionKey(secret, "password-reset", userId, "hash-v1");
        const { token, expiresAt } = await createActionToken(key, "password-reset", userId, "1h");

        const payload = await verifyActionToken(token, key, "password-reset", userId);

        expect(payload.userId).toBe(userId);
        expect(payload.purpose).toBe("password-reset");
        expect(payload.expiresAt.getTime()).toBe(expiresAt.getTime());
        expect(payload.expiresAt.getTime() - payload.issuedAt.getTime()).toBe(3_600_000);
    });

    it("should expose the subject without verifying", async () => {
        const key = deriveActionKey(secret, "password-reset", userId, "hash-v1");
        const { token } = await createActionToken(key, "password-reset", userId, "1h");

        expect(peekActionToken(token, "password-reset")).toBe(userId);
        expect(peekActionToken(token, "email-verification")).toBeNull();
        expect(peekActionToken("garbage", "password-reset")).toBeNull();
        expect(peekActionToken("", "password-reset")).toBeNull();
    });

    it("should reject a token once the bound state changes", async () => {
        const before = deriveActionKey(secret, "password-reset", userId, "hash-v1");
        const after = deriveActionKey(secret, "password-reset", userId, "hash-v2");
        const { token } = await createActionToken(before, "password-reset", userId, "1h");

        await expect(
            verifyActionToken(token, after, "password-reset", userId)
        ).rejects.toMatchObject({ failure: "invalid" });
    });

    it("should derive different keys per purpose, user and secret", () => {
        const base = deriveActionKey(secret, "password-reset", userId, "s");

        expect(deriveActionKey(secret, "email-verification", userId, "s")).not.toEqual(base);
        expect(deriveActionKey(secret, "password-reset", "user-2", "s")).not.toEqual(base);
        expect(deriveActionKey("other-secret-that-is-also-long-enough", "password-reset", userId, "s")).not.toEqual(base);
        expect(deriveActionKey(secret, "password-reset", userId, "s")).toEqual(base);
    });

    it("should reject a token presented for a different purpose", async () => {
        const key = deriveActionKey(secret, "password-reset", userId, "s");
        const { token } = await createActionToken(key, "password-reset", userId, "1h");

        // Same key, wrong purpose claim
        await expect(
            verifyActionToken(token, key, "email-verification", userId)
        ).rejects.toMatchObject({ failure: "invalid" });
    });

    it("should reject a token presented for a different user", async () => {
        const key = deriveActionKey(secret, "password-reset", userId, "s");
        const { token } = await createActionToken(key, "password-reset", userId, "1h");

        await expect(
            verifyActionToken(token, key, "password-reset", "user-2")
        ).rejects.toMatchObject({ failure: "invalid" });
    });

    it("should report expiry distinctly", async () => {
        const key = deriveActionKey(secret, "password-reset", userId, "s");
        const { token } = await createActionToken(key, "password-reset", userId, "0s");

        await expect(
            verifyActionToken(token, key, "password-reset", userId)
        ).rejects.toMatchObject({ failure: "expired" });
    });

    it("should reject a tampered token", async () => {
        const key = deriveActionKey(secret, "password-reset", userId, "s");
        const { token } = await createActionToken(key, "password-reset", userId, "1h");
        const parts = token.split(".");
        parts[1] = parts[1] + "x";

        await expect(
            verifyActionToken(parts.join("."), key, "password-reset", userId)
        ).rejects.toBeInstanceOf(ActionTokenError);
    });

    it("should not accept an access token as an action token", async () => {
        const accessToken = await createToken(userId, secret, "1h");
        const key = deriveActionKey(secret, "password-reset", userId, "s");

        expect(peekActionToken(accessToken, "password-reset")).toBeNull();
        await expect(
            verifyActionToken(accessToken, key, "password-reset", userId)
        ).rejects.toMatchObject({ failure: "invalid" });
    });

    it("should not accept a token forged with the raw secret", async () => {
        const rawKey = new TextEncoder().encode(secret);
        const forged = await new SignJWT({ sub: userId, purpose: "password-reset" })
            .setProtectedHeader({ alg: "HS256", typ: "sentra-action+jwt" })
            .setIssuedAt()
            .setExpirationTime("1h")
            .sign(rawKey);

        const key = deriveActionKey(secret, "password-reset", userId, "s");

        await expect(
            verifyActionToken(forged, key, "password-reset", userId)
        ).rejects.toMatchObject({ failure: "invalid" });
    });

    it("should require the action typ header", async () => {
        const key = deriveActionKey(secret, "password-reset", userId, "s");
        const noTyp = await new SignJWT({ sub: userId, purpose: "password-reset" })
            .setProtectedHeader({ alg: "HS256" })
            .setIssuedAt()
            .setExpirationTime("1h")
            .sign(key);

        await expect(
            verifyActionToken(noTyp, key, "password-reset", userId)
        ).rejects.toMatchObject({ failure: "invalid" });
    });

});
