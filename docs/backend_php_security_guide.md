# Backend Password Security Guide — PHP

> **For:** PHP Backend Developers  
> **Context:** This guide accompanies the Flutter [`password_guard`](https://pub.dev/packages/password_guard) library.  
> The Flutter app enforces password strength and policy on the client side.  
> **Your job** is to hash passwords securely on the server — never trust the client to do it.

---

## 📌 Golden Rules

> ❌ **NEVER store plain text passwords**  
> ❌ **NEVER use MD5, SHA-1, or SHA-256 alone for passwords**  
> ❌ **NEVER use a single global salt (that's just a constant, not a salt)**  
> ✅ **ALWAYS hash on the server side, regardless of what the client sends**  
> ✅ **ALWAYS use a slow, purpose-built password hashing algorithm**  
> ✅ **ALWAYS use a unique per-user salt (automatic in PHP)**  
> ✅ **ALWAYS add a server-side pepper stored separately from the database**

---

## 🗂️ Table of Contents

1. [Why Not MD5 / SHA?](#1-why-not-md5--sha)
2. [Algorithm Comparison](#2-algorithm-comparison)
3. [PHP Built-in: password_hash()](#3-php-built-in-password_hash)
4. [Recommended: Argon2id (OWASP 2024)](#4-recommended-argon2id-owasp-2024)
5. [bcrypt (Fallback)](#5-bcrypt-fallback)
6. [Adding a Pepper](#6-adding-a-pepper)
7. [Full Production Class](#7-full-production-class)
8. [Database Schema](#8-database-schema)
9. [Password Migration](#9-password-migration)
10. [API Endpoint Examples](#10-api-endpoint-examples)
11. [Security Checklist](#11-security-checklist)

---

## 1. Why Not MD5 / SHA?

```php
// ❌ NEVER DO THIS
$hash = md5($password);
$hash = sha1($password);
$hash = hash('sha256', $password);
```

**Why these fail:**

| Problem | MD5 / SHA | Argon2id |
|---------|-----------|----------|
| Speed (attack) | ~10 billion/sec on GPU | ~1/sec intentionally |
| Rainbow table | Cracked in seconds | Impossible with unique salt |
| Purpose | Data integrity, checksums | Password storage |
| OWASP recommended | ❌ Explicitly forbidden | ✅ Recommended |

A modern GPU can crack a 7-character MD5 password in **under 1 minute**.
The same GPU would take **thousands of years** against Argon2id.

---

## 2. Algorithm Comparison

| Algorithm | PHP Support | Speed | Memory-Hard | OWASP 2024 |
|-----------|:-----------:|:-----:|:-----------:|:----------:|
| **Argon2id** | PHP 7.3+ | Slow ✅ | ✅ | ✅ Recommended |
| **bcrypt** | PHP 5.5+ | Slow ✅ | ❌ | ✅ Acceptable |
| **PBKDF2** | PHP 5.5+ | Configurable | ❌ | ✅ with 600K iterations |
| SHA-256 | All | 🚨 Fast | ❌ | ❌ Forbidden |
| MD5 | All | 🚨 Very Fast | ❌ | ❌ Forbidden |

**Use Argon2id** unless you're on PHP < 7.3, in which case use bcrypt.

---

## 3. PHP Built-in: `password_hash()`

PHP has a **built-in, OWASP-compliant** password hashing API.
It automatically handles salt generation — you never manage salt manually.

```php
<?php

// Hash
$hash = password_hash($password, PASSWORD_ARGON2ID);
// Returns: $argon2id$v=19$m=65536,t=4,p=1$...

// Verify
$isValid = password_verify($password, $hash);
// Returns: true or false

// Check if rehash needed
$needsRehash = password_needs_rehash($hash, PASSWORD_ARGON2ID, $options);
// Returns: true if hash uses weak params or different algorithm
```

**Salt is automatic** — `password_hash()` generates a unique cryptographic
salt for every call. You do NOT need to generate or store it separately.

---

## 4. Recommended: Argon2id (OWASP 2024)

### Minimum Requirements (OWASP 2024)

| Parameter | OWASP Minimum | Recommended |
|-----------|:-------------:|:-----------:|
| Memory (`memory_cost`) | 64 MB (65536 KB) | 64–128 MB |
| Iterations (`time_cost`) | 3 | 3–4 |
| Parallelism (`threads`) | 4 | 4 |

```php
<?php

// ✅ OWASP-compliant Argon2id configuration
$options = [
    'memory_cost' => 65536,  // 64 MB in KB
    'time_cost'   => 3,      // iterations (time factor)
    'threads'     => 4,      // parallelism
];

$hash = password_hash($password, PASSWORD_ARGON2ID, $options);
```

### Check Argon2id availability

```php
<?php

if (!defined('PASSWORD_ARGON2ID')) {
    throw new RuntimeException(
        'Argon2id not available. Requires PHP 7.3+ compiled with libargon2. ' .
        'Install: apt-get install php-cli php7.x-fpm (Ubuntu) or use bcrypt.'
    );
}
```

---

## 5. bcrypt (Fallback)

Use bcrypt if your server runs PHP < 7.3 or does not have libargon2.

```php
<?php

// bcrypt — cost 12 is OWASP minimum (each +1 doubles the time)
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
// Returns: $2y$12$...

$isValid = password_verify($password, $hash);
```

> ⚠️ bcrypt **silently truncates passwords at 72 bytes**.
> If your users may enter very long passwords, pre-hash with SHA-256:

```php
<?php

// Safe bcrypt for long passwords
function hashPasswordBcrypt(string $password, int $cost = 12): string {
    // Prevents 72-byte truncation — safe with binary-safe base64
    $prehashed = base64_encode(hash('sha256', $password, true));
    return password_hash($prehashed, PASSWORD_BCRYPT, ['cost' => $cost]);
}

function verifyPasswordBcrypt(string $password, string $hash): bool {
    $prehashed = base64_encode(hash('sha256', $password, true));
    return password_verify($prehashed, $hash);
}
```

---

## 6. Adding a Pepper

A **pepper** is a secret string mixed into the password **before hashing**.
Unlike salt (stored in the hash), pepper is stored **separately** — in an
environment variable or secrets manager. Even if your database leaks,
hashes cannot be cracked without the pepper.

### Store the pepper in `.env` (never in the database)

```ini
# .env
PASSWORD_PEPPER=your-random-64-char-secret-pepper-value-change-in-production
```

Generate a strong pepper:
```bash
# Generate a 64-character secure random pepper
openssl rand -base64 48
# or
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"
```

### Apply pepper before hashing

```php
<?php

class PepperService
{
    private string $pepper;

    public function __construct()
    {
        $this->pepper = $_ENV['PASSWORD_PEPPER']
            ?? getenv('PASSWORD_PEPPER')
            ?: throw new RuntimeException(
                'PASSWORD_PEPPER environment variable is not set. ' .
                'Add it to your .env file and never commit it to git.'
            );
    }

    /**
     * Apply HMAC-SHA256 pepper to password before hashing.
     * Using HMAC instead of concatenation prevents length-extension attacks.
     */
    public function applyPepper(string $password): string
    {
        return hash_hmac('sha256', $password, $this->pepper);
    }
}
```

### Hash with pepper (Argon2id)

```php
<?php

function hashPassword(string $password): string
{
    $pepperService = new PepperService();
    $pepperedPassword = $pepperService->applyPepper($password);

    return password_hash($pepperedPassword, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost'   => 3,
        'threads'     => 4,
    ]);
}

function verifyPassword(string $enteredPassword, string $storedHash): bool
{
    $pepperService = new PepperService();
    $pepperedPassword = $pepperService->applyPepper($enteredPassword);

    return password_verify($pepperedPassword, $storedHash);
}
```

> **Note:** `password_hash()` automatically generates and embeds a unique salt per user.
> You do **not** manage salt separately — PHP handles it.
> You only manage the **pepper** (the server-side secret).

---

## 7. Full Production Class

Copy this class into your project:

```php
<?php

namespace App\Services;

/**
 * PasswordService — Secure password hashing with Argon2id + pepper.
 *
 * OWASP Password Storage Cheat Sheet compliant.
 * Compatible with Flutter password_guard library.
 *
 * Usage:
 *   $service = new PasswordService();
 *   $hash = $service->hash('userPassword123!');
 *   $valid = $service->verify('userPassword123!', $hash);
 */
class PasswordService
{
    /** Argon2id memory cost in KB (64 MB = OWASP minimum) */
    private const MEMORY_COST = 65536;

    /** Argon2id time cost (iterations) */
    private const TIME_COST = 3;

    /** Argon2id parallelism (threads) */
    private const THREADS = 4;

    /** Minimum bcrypt cost if falling back */
    private const BCRYPT_COST = 12;

    private string $pepper;
    private bool $useArgon2id;

    public function __construct()
    {
        $this->pepper = $this->loadPepper();
        $this->useArgon2id = defined('PASSWORD_ARGON2ID');
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Public API
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Hash a password securely.
     *
     * @param  string  $plainPassword  Raw password from the user
     * @return string  The complete hash string — store this in the database
     * @throws \InvalidArgumentException  if password is empty
     */
    public function hash(string $plainPassword): string
    {
        if (empty(trim($plainPassword))) {
            throw new \InvalidArgumentException('Password must not be empty.');
        }

        $prepared = $this->prepare($plainPassword);

        if ($this->useArgon2id) {
            return password_hash($prepared, PASSWORD_ARGON2ID, [
                'memory_cost' => self::MEMORY_COST,
                'time_cost'   => self::TIME_COST,
                'threads'     => self::THREADS,
            ]);
        }

        // Fallback: bcrypt with SHA-256 pre-hash (avoids 72-byte truncation)
        $prepared = base64_encode(hash('sha256', $prepared, true));
        return password_hash($prepared, PASSWORD_BCRYPT, ['cost' => self::BCRYPT_COST]);
    }

    /**
     * Verify a password against a stored hash.
     *
     * @param  string  $plainPassword  Raw password entered by the user
     * @param  string  $storedHash     Hash retrieved from the database
     * @return bool    true if password matches
     */
    public function verify(string $plainPassword, string $storedHash): bool
    {
        if (empty($plainPassword) || empty($storedHash)) {
            return false;
        }

        $prepared = $this->prepare($plainPassword);

        // Detect bcrypt hash — it was pre-hashed with SHA-256
        if (str_starts_with($storedHash, '$2y$') || str_starts_with($storedHash, '$2b$')) {
            $prepared = base64_encode(hash('sha256', $prepared, true));
        }

        return password_verify($prepared, $storedHash);
    }

    /**
     * Check if a stored hash needs to be upgraded.
     *
     * Call this after every successful login and silently re-hash if true.
     *
     * @param  string  $storedHash  Hash from the database
     * @return bool    true if the hash should be re-hashed
     */
    public function needsRehash(string $storedHash): bool
    {
        $algorithm = $this->useArgon2id ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        $options   = $this->useArgon2id
            ? ['memory_cost' => self::MEMORY_COST, 'time_cost' => self::TIME_COST, 'threads' => self::THREADS]
            : ['cost' => self::BCRYPT_COST];

        return password_needs_rehash($storedHash, $algorithm, $options);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Private Helpers
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Prepare password: apply HMAC-SHA256 pepper.
     * HMAC prevents length-extension attacks vs plain concatenation.
     */
    private function prepare(string $password): string
    {
        return hash_hmac('sha256', $password, $this->pepper);
    }

    /**
     * Load pepper from environment. Throws if not configured.
     */
    private function loadPepper(): string
    {
        $pepper = $_ENV['PASSWORD_PEPPER'] ?? getenv('PASSWORD_PEPPER') ?? '';

        if (empty($pepper)) {
            throw new \RuntimeException(
                'PASSWORD_PEPPER environment variable is not set. ' .
                'Generate one with: php -r "echo bin2hex(random_bytes(32));" ' .
                'and add it to your .env file.'
            );
        }

        if (strlen($pepper) < 32) {
            throw new \RuntimeException(
                'PASSWORD_PEPPER is too short. Minimum 32 characters required. ' .
                'Generate: php -r "echo bin2hex(random_bytes(32));"'
            );
        }

        return $pepper;
    }
}
```

---

## 8. Database Schema

```sql
-- Users table — only one column needed for the password
CREATE TABLE users (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email         VARCHAR(255)    NOT NULL UNIQUE,
    password_hash VARCHAR(255)    NOT NULL,  -- stores the complete hash string
    created_at    TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP       DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_email (email)
);

-- Notes:
-- VARCHAR(255) is enough for Argon2id and bcrypt hashes
-- Do NOT store salt separately — it's embedded inside the hash string
-- Do NOT store the pepper here — it lives in your .env / secrets manager
-- Do NOT add a column for the raw password — ever
```

### What the hash string looks like in the DB

```
-- Argon2id (recommended):
$argon2id$v=19$m=65536,t=3,p=4$<base64_salt>$<base64_hash>

-- bcrypt (fallback):
$2y$12$<22_char_salt><31_char_hash>
```

---

## 9. Password Migration

Upgrade legacy MD5/SHA hashes **without forcing password resets**.
On every successful login:

```php
<?php

class AuthService
{
    public function __construct(
        private PasswordService $passwordService,
        private UserRepository  $userRepository,
    ) {}

    public function login(string $email, string $enteredPassword): ?User
    {
        $user = $this->userRepository->findByEmail($email);
        if (!$user) {
            // Always run a dummy comparison to prevent timing-based user enumeration
            $this->passwordService->verify('dummy', '$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy');
            return null;
        }

        // Handle legacy MD5 hashes (migration path)
        if ($this->isLegacyMd5($user->password_hash)) {
            return $this->migrateLegacyMd5($user, $enteredPassword);
        }

        // Handle legacy SHA-256 hashes
        if ($this->isLegacySha($user->password_hash)) {
            return $this->migrateLegacySha($user, $enteredPassword);
        }

        // Standard Argon2id / bcrypt verify
        if (!$this->passwordService->verify($enteredPassword, $user->password_hash)) {
            return null;
        }

        // ✅ Silent upgrade — if parameters are outdated, re-hash transparently
        if ($this->passwordService->needsRehash($user->password_hash)) {
            $newHash = $this->passwordService->hash($enteredPassword);
            $this->userRepository->updatePasswordHash($user->id, $newHash);
        }

        return $user;
    }

    // ── Legacy migration helpers ──────────────────────────────────────────────

    private function isLegacyMd5(string $hash): bool
    {
        return strlen($hash) === 32 && ctype_xdigit($hash);
    }

    private function isLegacySha(string $hash): bool
    {
        return strlen($hash) === 64 && ctype_xdigit($hash);
    }

    private function migrateLegacyMd5(User $user, string $enteredPassword): ?User
    {
        // Compare using the old method (MD5 without pepper)
        if (!hash_equals($user->password_hash, md5($enteredPassword))) {
            return null;
        }
        // Password correct — silently upgrade to Argon2id + pepper
        $newHash = $this->passwordService->hash($enteredPassword);
        $this->userRepository->updatePasswordHash($user->id, $newHash);
        return $user;
    }

    private function migrateLegacySha(User $user, string $enteredPassword): ?User
    {
        if (!hash_equals($user->password_hash, hash('sha256', $enteredPassword))) {
            return null;
        }
        $newHash = $this->passwordService->hash($enteredPassword);
        $this->userRepository->updatePasswordHash($user->id, $newHash);
        return $user;
    }
}
```

---

## 10. API Endpoint Examples

### Registration

```php
<?php

// POST /api/auth/register
public function register(Request $request): JsonResponse
{
    // 1. Validate input
    $validated = $request->validate([
        'name'     => 'required|string|max:255',
        'email'    => 'required|email|unique:users,email',
        'password' => 'required|string|min:6|max:128',
    ]);

    // 2. Hash the password on the server (NEVER trust client-side hashing)
    $passwordHash = $this->passwordService->hash($validated['password']);

    // 3. Store user
    $user = User::create([
        'name'          => $validated['name'],
        'email'         => $validated['email'],
        'password_hash' => $passwordHash,  // store ONLY the hash
    ]);

    return response()->json([
        'message' => 'Account created successfully.',
        'user'    => ['id' => $user->id, 'email' => $user->email],
    ], 201);
}
```

### Login

```php
<?php

// POST /api/auth/login
public function login(Request $request): JsonResponse
{
    $validated = $request->validate([
        'email'    => 'required|email',
        'password' => 'required|string',
    ]);

    // Find user
    $user = User::where('email', $validated['email'])->first();

    // Always verify — even if user not found — to prevent timing attacks
    $storedHash = $user?->password_hash ?? '$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy';
    $isValid    = $this->passwordService->verify($validated['password'], $storedHash);

    if (!$user || !$isValid) {
        // Same error message regardless of whether email or password is wrong
        return response()->json(['message' => 'Invalid email or password.'], 401);
    }

    // Silent hash upgrade if parameters are outdated
    if ($this->passwordService->needsRehash($user->password_hash)) {
        $user->password_hash = $this->passwordService->hash($validated['password']);
        $user->save();
    }

    // Issue token (Laravel Sanctum / Passport / JWT)
    $token = $user->createToken('auth_token')->plainTextToken;

    return response()->json([
        'message'      => 'Login successful.',
        'access_token' => $token,
        'token_type'   => 'Bearer',
    ]);
}
```

### Change Password

```php
<?php

// POST /api/auth/change-password
public function changePassword(Request $request): JsonResponse
{
    $validated = $request->validate([
        'current_password' => 'required|string',
        'new_password'     => 'required|string|min:6|max:128|different:current_password',
    ]);

    $user = $request->user();

    // Verify current password before allowing change
    if (!$this->passwordService->verify($validated['current_password'], $user->password_hash)) {
        return response()->json(['message' => 'Current password is incorrect.'], 422);
    }

    // Hash and save the new password
    $user->password_hash = $this->passwordService->hash($validated['new_password']);
    $user->save();

    // Revoke all other tokens (force re-login on other devices)
    $user->tokens()->where('id', '!=', $request->user()->currentAccessToken()->id)->delete();

    return response()->json(['message' => 'Password changed successfully.']);
}
```

---

## 11. Security Checklist

Run through this before going to production:

### Password Storage
- [ ] Using `password_hash()` with `PASSWORD_ARGON2ID` or `PASSWORD_BCRYPT`
- [ ] `memory_cost` ≥ 65536 (Argon2id)
- [ ] `time_cost` ≥ 3 (Argon2id) or `cost` ≥ 12 (bcrypt)
- [ ] Pepper applied via `hash_hmac()` before `password_hash()`
- [ ] Pepper stored in environment variable, NOT in database or code
- [ ] Pepper is at least 32 random characters
- [ ] Database column is `VARCHAR(255)` — never shorter

### API Security
- [ ] Password validation on server side (min 6 chars, max 128 chars)
- [ ] Same error message for wrong email AND wrong password (prevents enumeration)
- [ ] `password_verify()` always runs even when user is not found (prevents timing leak)
- [ ] HTTPS enforced on all auth endpoints
- [ ] Rate limiting on login endpoint (e.g., 5 attempts per minute per IP)
- [ ] Account lockout after N failed attempts (e.g., lock for 15 minutes after 10 failures)

### Secrets Management
- [ ] `PASSWORD_PEPPER` is in `.env`, never committed to git
- [ ] `.env` is in `.gitignore`
- [ ] Production pepper is different from development pepper
- [ ] Pepper rotation plan exists (see note below)

### Database
- [ ] Column named `password_hash` (not `password`) — naming clarity
- [ ] No plain text password stored anywhere (logs, cache, API responses)
- [ ] Password hash never returned in API responses

### Migration
- [ ] `password_needs_rehash()` called on every successful login
- [ ] Legacy MD5/SHA migration logic in place if upgrading old system
- [ ] Migration tracked (e.g., count of remaining legacy hashes in monitoring)

---

## Pepper Rotation (Advanced)

If your pepper is compromised, you need to rotate it without locking out users:

```php
<?php

// Store pepper version in the hash column prefix
// e.g.:  v2:$argon2id$v=19$...

class PepperRotationService
{
    private array $peppers = [
        1 => 'old-pepper-value',   // keep old peppers for reading only
        2 => 'new-pepper-value',   // current pepper for writing
    ];

    private int $currentVersion = 2;

    public function hash(string $password): string
    {
        $pepper   = $this->peppers[$this->currentVersion];
        $prepared = hash_hmac('sha256', $password, $pepper);
        $hash     = password_hash($prepared, PASSWORD_ARGON2ID);
        return "v{$this->currentVersion}:{$hash}";
    }

    public function verify(string $password, string $storedHash): bool
    {
        [$version, $hash] = explode(':', $storedHash, 2);
        $pepper           = $this->peppers[(int)ltrim($version, 'v')] ?? '';
        $prepared         = hash_hmac('sha256', $password, $pepper);
        return password_verify($prepared, $hash);
    }
}
```

---

## Quick Reference

```php
<?php

// ── Install (Composer) ────────────────────────────────────────
// No extra packages needed — PHP built-in functions only

// ── Generate pepper (run once, save to .env) ─────────────────
echo bin2hex(random_bytes(32)); // 64-char hex pepper

// ── Hash ──────────────────────────────────────────────────────
$peppered = hash_hmac('sha256', $plainPassword, $_ENV['PASSWORD_PEPPER']);
$hash     = password_hash($peppered, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,
    'time_cost'   => 3,
    'threads'     => 4,
]);

// ── Verify ────────────────────────────────────────────────────
$peppered = hash_hmac('sha256', $enteredPassword, $_ENV['PASSWORD_PEPPER']);
$isValid  = password_verify($peppered, $storedHash);

// ── Check for upgrade ─────────────────────────────────────────
$needsUpgrade = password_needs_rehash($storedHash, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536, 'time_cost' => 3, 'threads' => 4,
]);
```

---

## Related Resources

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [PHP password_hash() docs](https://www.php.net/manual/en/function.password-hash.php)
- [PHP password_verify() docs](https://www.php.net/manual/en/function.password-verify.php)
- [PHP password_needs_rehash() docs](https://www.php.net/manual/en/function.password-needs-rehash.php)
- [Flutter password_guard package](https://pub.dev/packages/password_guard)
- [Argon2 — Password Hashing Competition winner](https://github.com/P-H-C/phc-winner-argon2)

---

*Document maintained by: Backend Security Team*  
*Last updated: June 2025*  
*Applies to: PHP 7.3+, Laravel 9+, Lumen, Slim, custom PHP APIs*
