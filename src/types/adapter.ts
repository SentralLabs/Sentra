import { RefreshSession } from "./session.js";

export interface User {
    id: string;
    email: string;
}
export interface UserRecord extends User {
    passwordHash: string;
}
export interface CreateUser {
    email: string;
    passwordHash: string;
}

export interface UserAdapter {
    findUserByEmail(email: string): Promise<UserRecord | null>;
    createUser(data: CreateUser): Promise<UserRecord>;
    findUserById(userId: string): Promise<UserRecord | null>;
}

export interface RefreshTokenAdapter {
    findSessionByTokenHash(refreshTokenHash: string): Promise<RefreshSession | null>;
    revokeSession(sessionId: string): Promise<void>;
    createSession(session: RefreshSession): Promise<RefreshSession>;
    revokeFamily(familyId: string): Promise<void>;
    /**
     * Required when `refreshTokenGracePeriod` is configured. Used to confirm
     * that a family is still healthy before tolerating a concurrent refresh.
     */
    findSessionsByFamilyId?(familyId: string): Promise<RefreshSession[]>;
}
