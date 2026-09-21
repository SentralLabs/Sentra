# Changelog

All notable changes to Sentra will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Sentra follows [Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-09-22

### Fixed

* Unknown emails and wrong passwords now take the same time to reject; previously an unknown email returned before running bcrypt, leaking whether an account exists.
* `tokenExpiry` and `refreshTokenExpiry` now share one duration parser and are validated when `createAuth` is called, instead of failing at first login.
* Emails are trimmed and lowercased before lookup and storage, so `Akash@x.com` and `akash@x.com` are one account. Disable or customise with `normalizeEmail`.
* Hooks may now be synchronous; the `AuthHooks` types accept `void | Promise<void>`.
* `AuthConfig`, `UserAdapter`, `RefreshTokenAdapter`, `RefreshSession`, `User` and related types are now exported from the package entry point, as the README already showed.
* Fixed the refresh-token expiry error message.

### Added

* `refreshTokenGracePeriod` option: tolerate two clients racing to refresh with the same token instead of revoking the whole family. Opt-in; requires `findSessionsByFamilyId` on the refresh-token adapter.
* `absoluteSessionExpiry` option: hard cap on how long a session can be kept alive by refreshing. Opt-in; adds `absoluteExpiresAt` to stored sessions.
* `createAuth` throws on an empty secret and warns when the secret is shorter than 32 bytes.
* Durations accept seconds and weeks and long unit names (`"2 hours"`, `"30 days"`).
* `repository`, `homepage`, `bugs` and `engines` metadata in `package.json`.

### Migration notes

* If you already have users with mixed-case emails, lowercase the stored values (`UPDATE users SET email = lower(email)`) or set `normalizeEmail: false` to keep the previous behaviour.

## [1.0.0] - 2026-08-20

### Added

* User signup and login
* JWT access-token authentication
* Refresh-token sessions
* Secure refresh-token hashing
* Refresh-token rotation
* Refresh-token reuse detection
* Refresh-token family revocation
* Session expiration
* Authentication hooks
* Custom user adapters
* Custom refresh-session adapters
* TypeScript type declarations
* ESM package build
* Comprehensive automated test suite
* GitHub Actions CI

### Security

* Raw refresh tokens are never persisted.
* Refresh tokens are hashed before storage.
* Reuse of revoked refresh tokens is detected.
* Refresh-token families can be revoked after token reuse detection.

[1.0.1]: https://github.com/akashbisht004/Sentra/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/akashbisht004/Sentra/releases/tag/v1.0.0
