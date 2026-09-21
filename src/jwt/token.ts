import { SignJWT, jwtVerify, errors as joseErrors } from "jose";
import { AuthError } from "../errors/auth-error.js";
import { parseDuration } from "../utils/duration.js";

export interface JwtOptions {
    /** `iss` claim to set and require. */
    issuer?: string;
    /** `aud` claim to set and require. */
    audience?: string;
}

export interface TokenPayload {
    userId: string;
    issuedAt: Date;
    expiresAt: Date;
}

export async function createToken(userId: string, secret: string, tokenExpiry: string, options: JwtOptions = {}): Promise<string> {

    const key = new TextEncoder().encode(secret);
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = Math.floor(parseDuration(tokenExpiry) / 1000);

    const jwt = new SignJWT({ sub: userId });
    jwt.setIssuedAt(now);
    jwt.setExpirationTime(now + expiresIn);
    jwt.setProtectedHeader({ alg: "HS256" });
    if (options.issuer !== undefined) jwt.setIssuer(options.issuer);
    if (options.audience !== undefined) jwt.setAudience(options.audience);

    const token = await jwt.sign(key);

    return token;
}

export async function verifyToken(token: string, secret: string, options: JwtOptions = {}): Promise<TokenPayload> {

    const key = new TextEncoder().encode(secret);
    let payload;

    try {
        payload = (await jwtVerify(token, key, {
            algorithms: ["HS256"],
            issuer: options.issuer,
            audience: options.audience
        })).payload;
    } catch (error) {
        if (error instanceof joseErrors.JWTExpired) {
            throw new AuthError("Token has expired", "AUTHENTICATION_FAILED", { reason: "TOKEN_EXPIRED", cause: error });
        }
        throw new AuthError("Invalid token", "AUTHENTICATION_FAILED", { reason: "TOKEN_INVALID", cause: error });
    }

    const { sub, iat, exp } = payload;
    if (typeof sub !== "string" || typeof iat !== "number" || typeof exp !== "number") {
        throw new AuthError("Invalid token", "AUTHENTICATION_FAILED", { reason: "TOKEN_INVALID" });
    }

    return {
        userId: sub,
        issuedAt: new Date(iat * 1000),
        expiresAt: new Date(exp * 1000)
    };

}
