import { describe, it, expect } from "vitest";
import { SignJWT } from "jose";
import { createToken, verifyToken } from "../src/jwt/token.js";
import { AuthError } from "../src/errors/auth-error.js";

const secret = "test-secret-that-is-at-least-32-bytes-long";
const userId = "123";

describe("JWT", () => {

    it("should create a token", async () => {
        const token = await createToken(
            userId,
            secret,
            "7d"
        );
        expect(token).toBeTypeOf("string");
        expect(token.split(".")).toHaveLength(3);
    });


    it("should verify a valid token", async () => {
        const token = await createToken(
            userId,
            secret,
            "7d"
        );

        const result = await verifyToken(token, secret);
        expect(result).toBe(userId);
    });


    it("should reject a token signed with the wrong secret", async () => {
        const token = await createToken(
            userId,
            secret,
            "7d"
        );

        await expect(
            verifyToken(token, "wrong-secret")
        ).rejects.toBeInstanceOf(AuthError);
    });


    it("should reject a tampered token", async () => {
        const token = await createToken(
            userId,
            secret,
            "7d"
        );

        const parts = token.split(".");

        parts[1] = parts[1] + "tampered";

        const tamperedToken = parts.join(".");

        await expect(
            verifyToken(tamperedToken, secret)
        ).rejects.toBeInstanceOf(AuthError);
    });


    it("should reject an expired token", async () => {
        const token = await createToken(
            userId,
            secret,
            "0s"
        );

        await expect(
            verifyToken(token, secret)
        ).rejects.toBeInstanceOf(AuthError);
    });


    it("should reject a valid token without a subject", async () => {
        const key = new TextEncoder().encode(secret);

        const token = await new SignJWT({})
            .setProtectedHeader({
                alg: "HS256",
                typ: "JWT"
            })
            .setIssuedAt()
            .setExpirationTime("7d")
            .sign(key);

        await expect(
            verifyToken(token, secret)
        ).rejects.toBeInstanceOf(AuthError);

        try {
            await verifyToken(token, secret);
        } catch (error) {
            expect((error as AuthError).code)
                .toBe("AUTHENTICATION_FAILED");
        }
    });

});