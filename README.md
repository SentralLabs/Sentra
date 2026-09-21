# Sentra v1.0.0
[![npm version](https://img.shields.io/npm/v/@_bisht_akash/sentra.svg)](https://www.npmjs.com/package/@_bisht_akash/sentra)
[![CI](https://github.com/akashbisht004/Sentra/actions/workflows/ci.yml/badge.svg)](https://github.com/akashbisht004/Sentra/actions/workflows/ci.yml)
[![npm downloads](https://img.shields.io/npm/dm/@_bisht_akash/sentra.svg)](https://www.npmjs.com/package/@_bisht_akash/sentra)
[![License](https://img.shields.io/npm/l/@_bisht_akash/sentra.svg)](https://github.com/akashbisht004/Sentra/blob/main/LICENSE)

Sentra is a lightweight, database-agnostic authentication and authorization mechanics engine for TypeScript and JavaScript applications. Sentra handles secure password hashing, JWT creation and validation, and advanced refresh token rotation (RTR) with automatic reuse detection—allowing you to focus purely on your application's business rules.

```
       Frontend (Next.js, React, Mobile, etc.)
                          │
                          │ credentials (email + password)
                          ▼
                  Developer's Backend
                          │
                          ▼
                       SENTRA
                          │
     ┌────────────────────┼────────────────────┐
     ▼                    ▼                    ▼
Password Hashing   JWT Token Mgmt     Session & Token Rotation
(bcrypt HS256)      (jose HS256)      (Reuse Detection / Hooks)
     ▲                    ▲                    ▲
     └────────────────────┼────────────────────┘
                          │
                          ▼
             Adapters (User & Session)
                          │
                          ▼
                Developer's Database
```

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Adapter Documentation](#adapter-documentation)
  - [UserAdapter](#useradapter)
  - [RefreshTokenAdapter](#refreshtokenadapter)
  - [Concrete Prisma Example](#concrete-prisma-example)
- [Refresh-Token Architecture](#refresh-token-architecture)
  - [How Token Rotation Works](#how-token-rotation-works)
  - [Automatic Reuse Detection](#automatic-reuse-detection)
- [Hooks](#hooks)
- [Errors](#errors)
- [API Reference](#api-reference)
  - [createAuth](#createauth)
  - [Auth Class](#auth-class)

---

## Installation

Install Sentra via npm, yarn, or pnpm:

```bash
# npm
npm install @_bisht_akash/sentra

# yarn
yarn add @_bisht_akash/sentra

# pnpm
pnpm add @_bisht_akash/sentra
```

---

## Quick Start

Initialize Sentra by providing your custom database adapters and configuration secret:

```typescript
import { createAuth } from '@_bisht_akash/sentra';
import { MyDatabaseAdapter } from './my-database-adapter'; // Custom implementation

// 1. Initialize Auth Engine
const dbAdapter = new MyDatabaseAdapter();
export const auth = createAuth({
  adapter: dbAdapter,
  refreshTokenAdapter: dbAdapter,
  secret: process.env.JWT_SECRET || 'your-super-secret-key',
  tokenExpiry: '15m',        // Access token expiry (e.g. 15m, 1h, 7d)
  refreshTokenExpiry: '30d', // Refresh token expiry
});

// 2. Sign Up a User
const newUser = await auth.signUp({
  email: 'user@example.com',
  password: 'securepassword123',
});

// 3. Log In a User
const { user, token, refreshToken } = await auth.login({
  email: 'user@example.com',
  password: 'securepassword123',
});
// Sentra returns:
// - `user`: The user's metadata (id, email)
// - `token`: A short-lived JWT access token
// - `refreshToken`: A secure, single-use refresh token string

// 4. Authenticate a Request
const authenticatedUser = await auth.authenticate(token);

// 5. Refresh Tokens
const tokens = await auth.refresh(refreshToken);
// Returns a new access token and a rotated refresh token
```

---

## Adapter Documentation

Sentra is completely database-agnostic. To wire it up with your database (PostgreSQL, MongoDB, MySQL, Redis, etc.), you implement two TypeScript interfaces: `UserAdapter` and `RefreshTokenAdapter`.

### UserAdapter

Handles operations related to the user accounts.

```typescript
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
  findUserById(userId: string): Promise<UserRecord | null>;
  createUser(data: CreateUser): Promise<UserRecord>;
}
```

### RefreshTokenAdapter

Handles storage and state tracking for refresh token sessions to power the Refresh Token Rotation (RTR) mechanics.

```typescript
export interface RefreshSession {
  sessionId: string;
  familyId: string;
  userId: string;
  refreshTokenHash: string;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface RefreshTokenAdapter {
  findSessionByTokenHash(refreshTokenHash: string): Promise<RefreshSession | null>;
  createSession(session: RefreshSession): Promise<RefreshSession>;
  revokeSession(sessionId: string): Promise<void>;
  revokeFamily(familyId: string): Promise<void>;
}
```

### Concrete Prisma Example

Here is a full example of implementing both interfaces using **Prisma ORM**:

#### Prisma Schema

```prisma
model User {
  id           String           @id @default(uuid())
  email        String           @unique
  passwordHash String
  sessions     RefreshSession[]
}

model RefreshSession {
  sessionId        String    @id
  familyId         String
  userId           String
  refreshTokenHash String    @unique
  expiresAt        DateTime
  revokedAt        DateTime?
  user             User      @relation(fields: [userId], references: [id], onDelete: Cascade)
}
```

#### Adapter Class

```typescript
import { PrismaClient } from '@prisma/client';
import type { 
  UserAdapter, 
  RefreshTokenAdapter, 
  UserRecord, 
  CreateUser, 
  RefreshSession 
} from '@_bisht_akash/sentra';

const prisma = new PrismaClient();

export class SentraDbAdapter implements UserAdapter, RefreshTokenAdapter {
  // --- UserAdapter Implementation ---

  async findUserByEmail(email: string): Promise<UserRecord | null> {
    return prisma.user.findUnique({ where: { email } });
  }

  async findUserById(userId: string): Promise<UserRecord | null> {
    return prisma.user.findUnique({ where: { id: userId } });
  }

  async createUser(data: CreateUser): Promise<UserRecord> {
    return prisma.user.create({
      data: {
        email: data.email,
        passwordHash: data.passwordHash,
      },
    });
  }

  // --- RefreshTokenAdapter Implementation ---

  async findSessionByTokenHash(refreshTokenHash: string): Promise<RefreshSession | null> {
    return prisma.refreshSession.findUnique({ where: { refreshTokenHash } });
  }

  async createSession(session: RefreshSession): Promise<RefreshSession> {
    return prisma.refreshSession.create({ data: session });
  }

  async revokeSession(sessionId: string): Promise<void> {
    await prisma.refreshSession.update({
      where: { sessionId },
      data: { revokedAt: new Date() },
    });
  }

  async revokeFamily(familyId: string): Promise<void> {
    await prisma.refreshSession.updateMany({
      where: { familyId },
      data: { revokedAt: new Date() },
    });
  }
}
```

---

## Refresh-Token Architecture

Sentra implements a highly secure refresh-token structure utilizing **Refresh Token Rotation (RTR)** to protect against token hijacking.

```
🔑 LOGIN  ──> Generates Token + Refresh Token (R1) (belongs to Family F1)
                │
🔄 REFRESH ──> Presents R1 ──> Sentra revokes R1 ──> Generates Token + R2 (Family F1)
                │
⚠️ REUSE   ──> Thief presents revoked R1 ──> Sentra detects breach ──> Revokes ENTIRE Family F1
```

### How Token Rotation Works

1. When a user logs in, a refresh token is generated along with a unique `sessionId` and a `familyId` (representing the chain of refreshes in this login session).
2. The refresh token string is cryptographically hashed (SHA-256) before storing it in the database to prevent database-compromise token extraction.
3. Upon refreshing, the old refresh token is marked as `revokedAt = new Date()`, and a brand new refresh token is issued to the client under the same `familyId`.

### Automatic Reuse Detection

If an attacker steals a refresh token and uses it:
- Either the **victim** or the **attacker** will attempt to refresh the token first, causing the token to be marked as revoked.
- When the second party attempts to use that same (already revoked) refresh token, Sentra's reuse detection triggers.
- Sentra automatically calls `revokeFamily(familyId)`, instantly invalidating **every single refresh token** in that family chain.
- The next time the user or attacker makes an authenticated request with an expired access token, they will be blocked and forced to re-authenticate completely.

---

## Hooks

You can define optional lifecycle hooks to execute side effects during key events:

```typescript
export interface AuthHooks {
  beforeSignUp?: (data: { email: string }) => Promise<void>;
  afterSignUp?: (user: User) => Promise<void>;
  beforeLogin?: (user: User) => Promise<void>;
  afterLogin?: (user: User) => Promise<void>;
}
```

### Example Usage

```typescript
const auth = createAuth({
  adapter,
  refreshTokenAdapter,
  secret: 'my-secret',
  hooks: {
    beforeSignUp: async ({ email }) => {
      if (email.endsWith('@disallowed.com')) {
        throw new Error('Disallowed email domain.');
      }
    },
    afterSignUp: async (user) => {
      await sendWelcomeEmail(user.email);
    },
    beforeLogin: async (user) => {
      // Implement account suspension or verification check
      const isSuspended = await checkSuspensionStatus(user.id);
      if (isSuspended) throw new Error('Account is suspended.');
    },
    afterLogin: async (user) => {
      await logAuditActivity(user.id, 'user_login_success');
    }
  }
});
```

> [!NOTE]
> Errors thrown inside `beforeSignUp` and `beforeLogin` hooks will abort the operation. If hooks like `afterSignUp` or `afterLogin` throw, they are caught and logged automatically to prevent breaking the core user response flow.

---

## Errors

Sentra throws a custom `AuthError` containing a descriptive error message and an error code to make error handling clean.

### Error Codes

- `USER_ALREADY_EXISTS`: Thrown during signup if a user record with the same email already exists.
- `INVALID_CREDENTIALS`: Thrown during login if the email is not found or the password comparison fails.
- `AUTHENTICATION_FAILED`: Thrown during token validation or refresh flow (e.g. invalid tokens, expired tokens, or token reuse detection).

### Example Error Handling

```typescript
import { AuthError } from '@_bisht_akash/sentra';

try {
  const result = await auth.login({ email, password });
} catch (error) {
  if (error instanceof AuthError) {
    switch (error.code) {
      case 'INVALID_CREDENTIALS':
        res.status(401).json({ error: 'Invalid email or password' });
        break;
      case 'AUTHENTICATION_FAILED':
        res.status(403).json({ error: 'Session expired or invalidated' });
        break;
      default:
        res.status(500).json({ error: error.message });
    }
  } else {
    res.status(500).json({ error: 'Internal server error' });
  }
}
```

---

## API Reference

### `createAuth(config)`

Factory function to create a new `Auth` instance.

#### Parameters

- `config: AuthConfig`
  - `adapter: UserAdapter` (Required) - Database adapter for user operations.
  - `refreshTokenAdapter: RefreshTokenAdapter` (Required) - Database adapter for refresh token sessions.
  - `secret: string` (Required) - HMAC secret key for signing JWTs.
  - `tokenExpiry?: string` (Optional) - Expiration duration for access tokens (e.g., `"15m"`, `"1h"`, `"7d"`). Defaults to `"7d"`.
  - `refreshTokenExpiry?: string` (Optional) - Expiration duration for refresh tokens (e.g., `"30d"`, `"90d"`). Defaults to `"30d"`.
  - `hooks?: AuthHooks` (Optional) - Lifecycle hooks object.

#### Returns

An instance of the `Auth` class.

---

### `Auth` Class

#### `signUp(data)`

Creates a new user record. Hashes the password with bcrypt (cost factor of 10) before saving.

- **Parameters**: `data: SignUpData` (`{ email, password }`)
- **Returns**: `Promise<User>` (`{ id, email }`)
- **Throws**: `AuthError` (code: `USER_ALREADY_EXISTS`)

#### `login(data)`

Validates credentials, creates a refresh token family/session, and returns JWT tokens.

- **Parameters**: `data: LoginData` (`{ email, password }`)
- **Returns**: `Promise<AuthResult>` (`{ user: { id, email }, token, refreshToken }`)
- **Throws**: `AuthError` (code: `INVALID_CREDENTIALS`)

#### `authenticate(token)`

Verifies a short-lived access token and retrieves the associated user.

- **Parameters**: `token: string` - The access token JWT.
- **Returns**: `Promise<User>` (`{ id, email }`)
- **Throws**: `AuthError` (code: `AUTHENTICATION_FAILED`)

#### `refresh(refreshToken)`

Validates the refresh token, executes rotation, generates a new token/refresh token pair, and checks for reuse.

- **Parameters**: `refreshToken: string` - The single-use refresh token.
- **Returns**: `Promise<AuthResult>` (`{ user: { id, email }, token, refreshToken }`)
- **Throws**: `AuthError` (code: `AUTHENTICATION_FAILED`)

## Development

Sentra uses GitHub Actions for continuous integration.