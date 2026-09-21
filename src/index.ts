import type { AuthConfig } from "./types/auth.js";
import { Auth } from "./core/auth.js";
import { AuthError } from "./errors/auth-error.js";
import type { AuthErrorCode } from "./errors/auth-error.js";
import { parseDuration } from "./utils/duration.js";

const MIN_SECRET_BYTES = 32;

function parseDurationOption(name: string, value: string): number {
    try {
        return parseDuration(value);
    } catch (error) {
        throw new Error(`Sentra: invalid ${name} "${value}": ${(error as Error).message}`);
    }
}

function createAuth(config: AuthConfig): Auth {

    if (typeof config.secret !== "string" || config.secret.length === 0) {
        throw new Error("Sentra: secret must be a non-empty string");
    }
    if (Buffer.byteLength(config.secret, "utf8") < MIN_SECRET_BYTES) {
        console.warn(
            `Sentra: secret is shorter than ${MIN_SECRET_BYTES} bytes. HS256 keys should be at least 256 bits; ` +
            "generate one with `openssl rand -base64 32`."
        );
    }

    const tokenExpiry = config.tokenExpiry ?? "7d";
    parseDurationOption("tokenExpiry", tokenExpiry);

    const refreshTokenExpiryMs = parseDurationOption("refreshTokenExpiry", config.refreshTokenExpiry ?? "30d");
    const absoluteSessionExpiryMs = config.absoluteSessionExpiry === undefined
        ? null
        : parseDurationOption("absoluteSessionExpiry", config.absoluteSessionExpiry);
    const refreshTokenGracePeriodMs = config.refreshTokenGracePeriod === undefined
        ? 0
        : parseDurationOption("refreshTokenGracePeriod", config.refreshTokenGracePeriod);

    if (refreshTokenGracePeriodMs > 0 && typeof config.refreshTokenAdapter.findSessionsByFamilyId !== "function") {
        throw new Error("Sentra: refreshTokenGracePeriod requires refreshTokenAdapter.findSessionsByFamilyId");
    }

    return new Auth({
        adapter: config.adapter,
        refreshTokenAdapter: config.refreshTokenAdapter,
        secret: config.secret,
        tokenExpiry,
        refreshTokenExpiryMs,
        absoluteSessionExpiryMs,
        refreshTokenGracePeriodMs,
        normalizeEmail: config.normalizeEmail ?? true,
        hooks: config.hooks
    });

}

export { createAuth, AuthError };
export type { AuthErrorCode };
export type { AuthConfig, SignUpData, LoginData, AuthResult } from "./types/auth.js";
export type { User, UserRecord, CreateUser, UserAdapter, RefreshTokenAdapter } from "./types/adapter.js";
export type { RefreshSession } from "./types/session.js";
export type { AuthHooks, SignUpHookData } from "./types/hooks.js";
