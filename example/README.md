# password_guard — Examples

This folder contains a complete working example demonstrating every feature
of the [`password_guard`](https://pub.dev/packages/password_guard) library.

## Run the Example

```bash
# From the package root:
dart run example/password_guard_example.dart
```

---

## What the Example Covers

The example file [`password_guard_example.dart`](password_guard_example.dart)
walks through **8 demos**, each showing real-world usage patterns.

---

### Demo 1 — Basic Hashing & Verification

The simplest usage — hash a password and verify it on login.

```dart
import 'package:password_guard/password_guard.dart';

// Hash (returns a self-contained encoded string)
final result = await PasswordGuard.hash(password: 'myPassword123!');

// Store ONLY this one string in your database:
final storedHash = result.hash;
// Example: $pg$argon2id$v1$m=65536,t=3,p=4,l=32$<salt>$<hash>

// Verify on login
final isValid = await PasswordGuard.verify(
  password: 'myPassword123!',
  hash: storedHash,
);
// → true

final isWrong = await PasswordGuard.verify(
  password: 'wrongPassword!',
  hash: storedHash,
);
// → false
```

**Key point:** Each call to `hash()` produces a different output even for the
same password — a unique cryptographic salt is generated automatically.

---

### Demo 2 — Choosing an Algorithm

Three algorithms are supported, each suited to different platforms and needs:

```dart
// Argon2id — OWASP recommended default (all platforms)
final result = await PasswordGuard.hash(
  password: 'myPassword',
  algorithm: PasswordAlgorithm.argon2id,
  config: Argon2Config(
    memory: 65536,   // 64 MB — OWASP minimum
    iterations: 3,
    parallelism: 4,
  ),
);

// bcrypt — widely supported, proven (Android, iOS, Desktop)
final result = await PasswordGuard.hash(
  password: 'myPassword',
  algorithm: PasswordAlgorithm.bcrypt,
  config: BcryptConfig(cost: 12),
);

// PBKDF2 — pure Dart, works on Web too
final result = await PasswordGuard.hash(
  password: 'myPassword',
  algorithm: PasswordAlgorithm.pbkdf2,
  config: PBKDF2Config(iterations: 600000),
);
```

| Algorithm | Best For | Web | Speed |
|-----------|----------|:---:|-------|
| `argon2id` | All apps (default) | ✅ | Fast native |
| `bcrypt` | Traditional apps | ⚠️ slow | Fast native |
| `pbkdf2` | Web-first apps | ✅ | Fast everywhere |

---

### Demo 3 — Pepper Support

A **pepper** is a secret value mixed in before hashing — stored separately
from the database (env var, secrets manager). Even a leaked database cannot
be brute-forced without the pepper.

```dart
// Inline pepper
final result = await PasswordGuard.hash(
  password: 'myPassword',
  pepper: 'my-app-secret-pepper',
);

final valid = await PasswordGuard.verify(
  password: 'myPassword',
  hash: result.hash,
  pepper: 'my-app-secret-pepper', // must match
);

// With MemoryPepperProvider — great for DI (Provider, GetIt, etc.)
final provider = MemoryPepperProvider(env['APP_PEPPER']!);

final result = await PasswordGuard.hash(
  password: 'myPassword',
  pepperProvider: provider,
);

// With EnvPepperProvider — reads env var (native platforms only)
import 'package:password_guard/src/pepper/env_pepper_provider.dart';

final result = await PasswordGuard.hash(
  password: 'myPassword',
  pepperProvider: EnvPepperProvider(key: 'PASSWORD_GUARD_PEPPER'),
);
```

---

### Demo 4 — Password Migration (`needsRehash`)

Transparently upgrade weak or legacy hashes after a successful login —
no forced password resets, no user disruption.

```dart
Future<void> login(String userId, String enteredPassword) async {
  final user = await db.getUser(userId);

  // Verify with current stored hash
  final isValid = await PasswordGuard.verify(
    password: enteredPassword,
    hash: user.passwordHash,
  );

  if (!isValid) throw AuthException('Invalid credentials');

  // Silently upgrade on successful login
  if (PasswordGuard.needsRehash(user.passwordHash)) {
    final upgraded = await PasswordGuard.hash(password: enteredPassword);
    await db.updatePasswordHash(userId, upgraded.hash);
    // User never notices — it happens in the background
  }
}
```

`needsRehash` returns `true` when:
- Hash is not in `$pg$` format (legacy MD5, SHA, old bcrypt, etc.)
- Argon2id memory is below 65,536 KB
- Argon2id iterations are below 3
- bcrypt cost is below 12
- PBKDF2 iterations are below 600,000

---

### Demo 5 — Password Strength Checker

Synchronous — safe to call on every keystroke.
Returns a score (0–100), a `StrengthLevel`, and improvement suggestions.

```dart
final result = PasswordStrength.check('MyPass1!');

print(result.score);           // e.g., 58
print(result.level);           // StrengthLevel.medium
print(result.level.label);     // 'Medium'
print(result.level.isAcceptable); // true (medium and above)
print(result.suggestions);     // ['Consider using 12 or more characters.']
```

**StrengthLevel enum:**

| Level | Score Range | `isAcceptable` |
|-------|:-----------:|:--------------:|
| `veryWeak` | 0–19 | ❌ |
| `weak` | 20–39 | ❌ |
| `medium` | 40–59 | ✅ |
| `strong` | 60–79 | ✅ |
| `veryStrong` | 80–100 | ✅ |

**With Flutter TextField:**

```dart
TextField(
  onChanged: (value) {
    setState(() {
      _strength = PasswordStrength.check(value);
    });
  },
  decoration: InputDecoration(
    helperText: _strength?.level.label ?? '',
    helperStyle: TextStyle(
      color: _strength?.score ?? 0 > 60 ? Colors.green : Colors.orange,
    ),
  ),
)
```

---

### Demo 6 — Password Policy Validation

Enforce your app's password rules. Returns all violations at once,
or throws on failure — your choice:

```dart
const policy = PasswordPolicy(
  minLength: 6,                    // minimum 6 chars (default)
  maxLength: 128,                  // optional
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSpecialCharacter: true,
  bannedPasswords: ['password', 'company123!'],
);

// Form validation — collect all errors at once
final result = policy.validate(enteredPassword);
if (!result.isValid) {
  for (final error in result.violations) {
    showSnackBar(error);
  }
}

// Server-side — throw on failure
try {
  policy.validateOrThrow(enteredPassword);
} on PasswordPolicyException catch (e) {
  return Response.badRequest(body: jsonEncode({'errors': e.violations}));
}
```

---

### Demo 7 — Secure Random Utilities

Generate cryptographically secure random values for tokens, salts, and IDs:

```dart
// Raw bytes — for binary operations
final bytes = SecureRandom.bytes(32); // Uint8List(32)

// Base64 string — for session tokens, API keys
final sessionToken = SecureRandom.base64(32);
// e.g.: "dGhpcyBpcyBhIHNlY3VyZSB0b2tlbg=="

// Hex string — for reset tokens, confirmation codes
final resetToken = SecureRandom.hex(16);
// e.g.: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

// Pre-validated salt (always ≥ 16 bytes)
final salt = SaltGenerator.generate();          // 16 bytes default
final salt = SaltGenerator.generate(length: 32); // 32 bytes
```

---

### Demo 8 — Exception Handling

All exceptions extend `PasswordGuardException`. Handle specifically or catch all:

```dart
try {
  await PasswordGuard.verify(password: input, hash: storedHash);
} on InvalidHashException catch (e) {
  // Malformed, corrupted, or unsupported hash format
  logger.warn('Bad hash: ${e.message}');
} on InvalidConfigurationException catch (e) {
  // Empty password, conflicting pepper options, bad config
  logger.error('Config error: ${e.message}');
} on PepperException catch (e) {
  // Env var not set, empty provider
  logger.critical('Pepper not configured: ${e.message}');
} on PasswordPolicyException catch (e) {
  // Policy validation failed
  return apiError(400, e.violations);
} on PasswordGuardException catch (e) {
  // Catch-all for any password_guard error
  logger.error('Unexpected auth error: ${e.runtimeType} — ${e.message}');
}
```

---

## Full API Reference

See the [main README](../README.md) for the full API reference, OWASP compliance
table, framework integration examples (Shelf, Dart Frog, Serverpod), and the roadmap.

## pub.dev

[`password_guard` on pub.dev](https://pub.dev/packages/password_guard)

---

*password_guard — secure password hashing for Dart and Flutter*
