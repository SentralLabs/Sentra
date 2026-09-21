// src/errors/auth-error.ts
var AuthError = class extends Error {
  code;
  constructor(message, code) {
    super(message);
    this.name = "AuthError";
    this.code = code;
  }
};

// src/jwt/refresh-token.ts
import { randomBytes, createHash } from "crypto";
function generateRefreshToken() {
  return randomBytes(32).toString("hex");
}
function hashRefreshToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

// src/jwt/token.ts
import { SignJWT, jwtVerify } from "jose";

// src/utils/duration.ts
var UNIT_MS = {
  s: 1e3,
  sec: 1e3,
  secs: 1e3,
  second: 1e3,
  seconds: 1e3,
  m: 6e4,
  min: 6e4,
  mins: 6e4,
  minute: 6e4,
  minutes: 6e4,
  h: 36e5,
  hr: 36e5,
  hrs: 36e5,
  hour: 36e5,
  hours: 36e5,
  d: 864e5,
  day: 864e5,
  days: 864e5,
  w: 6048e5,
  week: 6048e5,
  weeks: 6048e5
};
function parseDuration(duration) {
  if (typeof duration !== "string") {
    throw new Error(`Invalid duration: ${String(duration)}`);
  }
  const match = duration.trim().match(/^(\d+)\s*([a-z]+)$/i);
  if (!match) {
    throw new Error(`Invalid duration: "${duration}"`);
  }
  const value = Number(match[1]);
  const unit = UNIT_MS[match[2].toLowerCase()];
  if (unit === void 0) {
    throw new Error(`Invalid duration unit in "${duration}"`);
  }
  return value * unit;
}

// src/jwt/token.ts
async function createToken(userId, secret, tokenExpiry) {
  const key = new TextEncoder().encode(secret);
  const now = Math.floor(Date.now() / 1e3);
  const expiresIn = Math.floor(parseDuration(tokenExpiry) / 1e3);
  const jwt = new SignJWT({ sub: userId });
  jwt.setIssuedAt(now);
  jwt.setExpirationTime(now + expiresIn);
  jwt.setProtectedHeader({ alg: "HS256" });
  const token = await jwt.sign(key);
  return token;
}
async function verifyToken(token, secret) {
  const key = new TextEncoder().encode(secret);
  let payload;
  try {
    payload = (await jwtVerify(token, key)).payload;
  } catch (error) {
    throw new AuthError("Invalid token", "AUTHENTICATION_FAILED");
  }
  const sub = payload.sub;
  if (typeof sub !== "string") {
    throw new AuthError("Invalid token", "AUTHENTICATION_FAILED");
  }
  return sub;
}

// src/core/auth.ts
import bcrypt from "bcrypt";
import { randomBytes as randomBytes2 } from "crypto";
var BCRYPT_COST = 10;
var Auth = class {
  adapter;
  secret;
  expiry;
  refreshTokenAdapter;
  refreshTokenExpiryMs;
  absoluteSessionExpiryMs;
  refreshTokenGracePeriodMs;
  emailNormalizer;
  hooks;
  dummyHash;
  constructor(options) {
    this.adapter = options.adapter;
    this.secret = options.secret;
    this.expiry = options.tokenExpiry;
    this.refreshTokenAdapter = options.refreshTokenAdapter;
    this.refreshTokenExpiryMs = options.refreshTokenExpiryMs;
    this.absoluteSessionExpiryMs = options.absoluteSessionExpiryMs;
    this.refreshTokenGracePeriodMs = options.refreshTokenGracePeriodMs;
    this.emailNormalizer = options.normalizeEmail;
    this.hooks = options.hooks;
  }
  async signUp(data) {
    const email = this.normalizeEmail(data.email);
    if (this.hooks?.beforeSignUp) {
      await this.hooks.beforeSignUp({ email });
    }
    const user = await this.adapter.findUserByEmail(email);
    if (user != null) {
      throw new AuthError("User already exists with same mail", "USER_ALREADY_EXISTS");
    }
    const passwordHash = await bcrypt.hash(data.password, BCRYPT_COST);
    const newUser = await this.adapter.createUser({
      email,
      passwordHash
    });
    const result = {
      id: newUser.id,
      email: newUser.email
    };
    if (this.hooks?.afterSignUp) {
      try {
        await this.hooks.afterSignUp(result);
      } catch (error) {
        console.error("after signup hook failed", error);
      }
    }
    return result;
  }
  async login(data) {
    const email = this.normalizeEmail(data.email);
    const user = await this.adapter.findUserByEmail(email);
    if (user == null) {
      await bcrypt.compare(data.password, await this.getDummyHash());
      throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");
    }
    if (this.hooks?.beforeLogin) await this.hooks.beforeLogin({ id: user.id, email: user.email });
    const valid = await bcrypt.compare(data.password, user.passwordHash);
    if (!valid) throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");
    const now = Date.now();
    const familyId = randomBytes2(16).toString("hex");
    const absoluteExpiresAt = this.absoluteSessionExpiryMs === null ? void 0 : new Date(now + this.absoluteSessionExpiryMs);
    const refreshToken = await this.issueSession(user.id, familyId, absoluteExpiresAt, now);
    const token = await createToken(user.id, this.secret, this.expiry);
    const result = {
      user: {
        id: user.id,
        email: user.email
      },
      token,
      refreshToken
    };
    if (this.hooks?.afterLogin) {
      try {
        await this.hooks.afterLogin(result.user);
      } catch (error) {
        console.error("After login hook failed", error);
      }
    }
    return result;
  }
  async authenticate(token) {
    const userId = await verifyToken(token, this.secret);
    const user = await this.adapter.findUserById(userId);
    if (user == null) throw new AuthError("Authorization failed", "AUTHENTICATION_FAILED");
    return {
      id: user.id,
      email: user.email
    };
  }
  async refresh(refreshToken) {
    const refreshTokenHash = hashRefreshToken(refreshToken);
    const session = await this.refreshTokenAdapter.findSessionByTokenHash(refreshTokenHash);
    if (session == null) {
      throw new AuthError("Invalid refresh token", "AUTHENTICATION_FAILED");
    }
    const now = Date.now();
    if (session.revokedAt !== null) {
      const concurrent = await this.isConcurrentRefresh(session, now);
      if (!concurrent) {
        await this.refreshTokenAdapter.revokeFamily(
          session.familyId
        );
        throw new AuthError(
          "Refresh token reuse detected",
          "AUTHENTICATION_FAILED"
        );
      }
    }
    if (session.expiresAt.getTime() <= now) {
      throw new AuthError("Refresh token has expired", "AUTHENTICATION_FAILED");
    }
    if (session.absoluteExpiresAt !== void 0 && session.absoluteExpiresAt.getTime() <= now) {
      throw new AuthError("Session has reached its maximum lifetime", "AUTHENTICATION_FAILED");
    }
    const user = await this.adapter.findUserById(session.userId);
    if (user == null) {
      throw new AuthError("User no longer exists", "AUTHENTICATION_FAILED");
    }
    if (session.revokedAt === null) {
      await this.refreshTokenAdapter.revokeSession(session.sessionId);
    }
    const newRefreshToken = await this.issueSession(user.id, session.familyId, session.absoluteExpiresAt, now);
    const token = await createToken(
      user.id,
      this.secret,
      this.expiry
    );
    return {
      user: {
        id: user.id,
        email: user.email
      },
      token,
      refreshToken: newRefreshToken
    };
  }
  /**
   * Creates and stores a new refresh session in `familyId` and returns the
   * raw refresh token. `expiresAt` is capped by `absoluteExpiresAt`.
   */
  async issueSession(userId, familyId, absoluteExpiresAt, now) {
    const refreshToken = generateRefreshToken();
    let expiresAt = new Date(now + this.refreshTokenExpiryMs);
    if (absoluteExpiresAt !== void 0 && absoluteExpiresAt.getTime() < expiresAt.getTime()) {
      expiresAt = absoluteExpiresAt;
    }
    const session = {
      sessionId: randomBytes2(16).toString("hex"),
      familyId,
      userId,
      refreshTokenHash: hashRefreshToken(refreshToken),
      expiresAt,
      revokedAt: null
    };
    if (absoluteExpiresAt !== void 0) {
      session.absoluteExpiresAt = absoluteExpiresAt;
    }
    await this.refreshTokenAdapter.createSession(session);
    return refreshToken;
  }
  /**
   * A revoked session presented within the grace period counts as a
   * concurrent refresh (two clients racing with the same token) rather
   * than reuse, but only while the family still has a live session. A
   * family that was revoked outright has none, so its tokens stay dead.
   */
  async isConcurrentRefresh(session, now) {
    if (this.refreshTokenGracePeriodMs === 0 || session.revokedAt === null) return false;
    if (now - session.revokedAt.getTime() > this.refreshTokenGracePeriodMs) return false;
    const family = await this.refreshTokenAdapter.findSessionsByFamilyId(session.familyId);
    return family.some(
      (member) => member.revokedAt === null && member.expiresAt.getTime() > now
    );
  }
  normalizeEmail(email) {
    if (this.emailNormalizer === false) return email;
    if (typeof this.emailNormalizer === "function") return this.emailNormalizer(email);
    return email.trim().toLowerCase();
  }
  async getDummyHash() {
    this.dummyHash ??= await bcrypt.hash("sentra-dummy-password", BCRYPT_COST);
    return this.dummyHash;
  }
};

// src/index.ts
var MIN_SECRET_BYTES = 32;
function parseDurationOption(name, value) {
  try {
    return parseDuration(value);
  } catch (error) {
    throw new Error(`Sentra: invalid ${name} "${value}": ${error.message}`);
  }
}
function createAuth(config) {
  if (typeof config.secret !== "string" || config.secret.length === 0) {
    throw new Error("Sentra: secret must be a non-empty string");
  }
  if (Buffer.byteLength(config.secret, "utf8") < MIN_SECRET_BYTES) {
    console.warn(
      `Sentra: secret is shorter than ${MIN_SECRET_BYTES} bytes. HS256 keys should be at least 256 bits; generate one with \`openssl rand -base64 32\`.`
    );
  }
  const tokenExpiry = config.tokenExpiry ?? "7d";
  parseDurationOption("tokenExpiry", tokenExpiry);
  const refreshTokenExpiryMs = parseDurationOption("refreshTokenExpiry", config.refreshTokenExpiry ?? "30d");
  const absoluteSessionExpiryMs = config.absoluteSessionExpiry === void 0 ? null : parseDurationOption("absoluteSessionExpiry", config.absoluteSessionExpiry);
  const refreshTokenGracePeriodMs = config.refreshTokenGracePeriod === void 0 ? 0 : parseDurationOption("refreshTokenGracePeriod", config.refreshTokenGracePeriod);
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
export {
  AuthError,
  createAuth
};
//# sourceMappingURL=index.js.map