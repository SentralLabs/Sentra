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
    /** Required for `auth.changePassword`. */
    updatePassword?(userId: string, passwordHash: string): Promise<void>;
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
    /**
     * Required for `auth.logoutAll`; also used by `auth.changePassword`
     * to sign the user out everywhere when available.
     */
    revokeUserSessions?(userId: string): Promise<void>;
}
