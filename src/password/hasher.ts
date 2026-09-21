import bcrypt from "bcrypt";

/**
 * Pluggable password hashing. Implement this to swap bcrypt for
 * argon2, scrypt, or a hosted KMS.
 */
export interface PasswordHasher {
    hash(password: string): Promise<string>;
    compare(password: string, hash: string): Promise<boolean>;
}

export const DEFAULT_BCRYPT_COST = 10;

export function createBcryptHasher(cost: number = DEFAULT_BCRYPT_COST): PasswordHasher {
    if (!Number.isInteger(cost) || cost < 4 || cost > 31) {
        throw new Error(`Sentra: bcryptCost must be an integer between 4 and 31, got ${String(cost)}`);
    }

    return {
        hash: password => bcrypt.hash(password, cost),
        compare: (password, hash) => bcrypt.compare(password, hash)
    };
}
