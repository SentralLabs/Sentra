import { randomBytes } from "node:crypto";
import type { UserAdapter, UserRecord, CreateUser, RefreshTokenAdapter } from "../types/adapter.js";
import type { RefreshSession } from "../types/session.js";

/**
 * In-memory adapter implementing every optional method. Intended for
 * tests, examples and prototypes; nothing survives a restart.
 */
export class MemoryAdapter implements UserAdapter, RefreshTokenAdapter {

    private db: UserRecord[] = [];
    private sessions: RefreshSession[] = [];

    getSessions(): RefreshSession[] {
        return this.sessions;
    }

    getUsers(): UserRecord[] {
        return this.db;
    }

    deleteUser(userId: string): void {
        this.db = this.db.filter(user => user.id !== userId);
    }

    clear(): void {
        this.db = [];
        this.sessions = [];
    }

    // --- UserAdapter ---

    async findUserByEmail(email: string): Promise<UserRecord | null> {
        return this.db.find(user => user.email === email) ?? null;
    }

    async findUserById(userId: string): Promise<UserRecord | null> {
        return this.db.find(user => user.id === userId) ?? null;
    }

    async createUser(data: CreateUser): Promise<UserRecord> {
        const user: UserRecord = {
            id: randomBytes(8).toString("hex"),
            email: data.email,
            passwordHash: data.passwordHash,
            emailVerifiedAt: null
        };
        this.db.push(user);
        return user;
    }

    async updatePassword(userId: string, passwordHash: string): Promise<void> {
        const user = this.db.find(user => user.id === userId);
        if (user) user.passwordHash = passwordHash;
    }

    async setEmailVerified(userId: string, verifiedAt: Date): Promise<void> {
        const user = this.db.find(user => user.id === userId);
        if (user) user.emailVerifiedAt = verifiedAt;
    }

    /** Test helper: change a user's email directly. */
    setEmail(userId: string, email: string): void {
        const user = this.db.find(user => user.id === userId);
        if (user) user.email = email;
    }

    // --- RefreshTokenAdapter ---

    async findSessionByTokenHash(refreshTokenHash: string): Promise<RefreshSession | null> {
        return this.sessions.find(session => session.refreshTokenHash === refreshTokenHash) ?? null;
    }

    async createSession(session: RefreshSession): Promise<RefreshSession> {
        this.sessions.push(session);
        return session;
    }

    async revokeSession(sessionId: string): Promise<void> {
        const session = this.sessions.find(session => session.sessionId === sessionId);
        if (session) session.revokedAt = new Date();
    }

    async revokeFamily(familyId: string): Promise<void> {
        const now = new Date();
        for (const session of this.sessions) {
            if (session.familyId === familyId && session.revokedAt === null) session.revokedAt = now;
        }
    }

    async findSessionsByFamilyId(familyId: string): Promise<RefreshSession[]> {
        return this.sessions.filter(session => session.familyId === familyId);
    }

    async revokeUserSessions(userId: string): Promise<void> {
        const now = new Date();
        for (const session of this.sessions) {
            if (session.userId === userId && session.revokedAt === null) session.revokedAt = now;
        }
    }

}
