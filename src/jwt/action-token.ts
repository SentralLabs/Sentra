import { SignJWT, jwtVerify, decodeJwt, errors as joseErrors } from "jose";
import { createHmac, randomBytes } from "node:crypto";
import { parseDuration } from "../utils/duration.js";

export type ActionTokenPurpose = "password-reset" | "email-verification";

export interface ActionTokenPayload {
    userId: string;
    purpose: ActionTokenPurpose;
    issuedAt: Date;
    expiresAt: Date;
}

export type ActionTokenFailure = "invalid" | "expired";

export class ActionTokenError extends Error {
    constructor(public failure: ActionTokenFailure, cause?: unknown) {
        super(failure === "expired" ? "Action token has expired" : "Invalid action token", cause === undefined ? undefined : { cause });
        this.name = "ActionTokenError";
    }
}

/**
 * Derives the signing key for a single-use action token. The key mixes in
 * the piece of state the action changes (the password hash for a reset,
 * the email for verification), so once the action runs every outstanding
 * token for it stops verifying without anything having to be stored.
 */
export function deriveActionKey(secret: string, purpose: ActionTokenPurpose, userId: string, state: string): Uint8Array {
    return new Uint8Array(
        createHmac("sha256", secret)
            .update(`${purpose}:${userId}:${state}`)
            .digest()
    );
}

export async function createActionToken(
    key: Uint8Array,
    purpose: ActionTokenPurpose,
    userId: string,
    expiry: string
): Promise<{ token: string; expiresAt: Date }> {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + Math.floor(parseDuration(expiry) / 1000);

    const token = await new SignJWT({ sub: userId, purpose })
        .setProtectedHeader({ alg: "HS256", typ: "sentra-action+jwt" })
        .setJti(randomBytes(16).toString("hex"))
        .setIssuedAt(now)
        .setExpirationTime(exp)
        .sign(key);

    return { token, expiresAt: new Date(exp * 1000) };
}

/**
 * Reads the subject out of a token *without* verifying it, so the caller
 * can look up the user and derive the right key. Nothing returned here
 * may be trusted until `verifyActionToken` succeeds.
 */
export function peekActionToken(token: string, purpose: ActionTokenPurpose): string | null {
    let claims;
    try {
        claims = decodeJwt(token);
    } catch {
        return null;
    }

    if (claims.purpose !== purpose || typeof claims.sub !== "string" || claims.sub.length === 0) {
        return null;
    }

    return claims.sub;
}

export async function verifyActionToken(token: string, key: Uint8Array, purpose: ActionTokenPurpose, userId: string): Promise<ActionTokenPayload> {
    let payload;

    try {
        payload = (await jwtVerify(token, key, {
            algorithms: ["HS256"],
            typ: "sentra-action+jwt",
            subject: userId
        })).payload;
    } catch (error) {
        if (error instanceof joseErrors.JWTExpired) {
            throw new ActionTokenError("expired", error);
        }
        throw new ActionTokenError("invalid", error);
    }

    const { sub, iat, exp } = payload;
    if (payload.purpose !== purpose || typeof sub !== "string" || typeof iat !== "number" || typeof exp !== "number") {
        throw new ActionTokenError("invalid");
    }

    return {
        userId: sub,
        purpose,
        issuedAt: new Date(iat * 1000),
        expiresAt: new Date(exp * 1000)
    };
}
