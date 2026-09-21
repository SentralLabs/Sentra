import type { UserAdapter, UserRecord, CreateUser, RefreshTokenAdapter } from "../src/types/adapter.js";
import type { RefreshSession } from "../src/types/session.js";

export class MemoryAdapter implements UserAdapter, RefreshTokenAdapter {

    private db: UserRecord[] = [];
    private sessions: RefreshSession[] = [];

    getSessions(): RefreshSession[] {
        return this.sessions;
    }
    deleteUser(userId: string) {
        this.db = this.db.filter((user) => {
            return user.id != userId;
        })
    }
    getUsers(): UserRecord[] {
        return this.db;
    }

    async findUserByEmail(email: string): Promise<UserRecord | null> {
        return this.db.find((user) => user.email === email) ?? null;
    }

    async findUserById(userId: string): Promise<UserRecord | null> {
        return this.db.find((user) => user.id === userId) ?? null;
    }

    async createUser(data: CreateUser): Promise<UserRecord> {
        const user: UserRecord = { id: Math.random().toString(), email: data.email, passwordHash: data.passwordHash };
        this.db.push(user);
        return user;
    }

    async findSessionByTokenHash(refreshTokenHash: string): Promise<RefreshSession | null> {
        return this.sessions.find((session) => session.refreshTokenHash === refreshTokenHash) ?? null;
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
        this.sessions.forEach(session => {
            if (session.familyId === familyId) session.revokedAt = new Date();
        });
    }

    async findSessionsByFamilyId(familyId: string): Promise<RefreshSession[]> {
        return this.sessions.filter(session => session.familyId === familyId);
    }

}