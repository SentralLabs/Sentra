export interface RefreshSession{
    sessionId: string;
    familyId: string;
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
    revokedAt: Date|null;
    /**
     * Hard upper bound on the lifetime of the whole refresh-token family.
     * Only present when `absoluteSessionExpiry` is configured; adapters
     * that do not persist it simply lose the absolute limit.
     */
    absoluteExpiresAt?: Date;
}
