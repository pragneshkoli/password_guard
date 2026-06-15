# password_guard

[![pub package](https://img.shields.io/pub/v/password_guard.svg)](https://pub.dev/packages/password_guard)
[![pub points](https://img.shields.io/pub/points/password_guard)](https://pub.dev/packages/password_guard/score)
[![popularity](https://img.shields.io/pub/popularity/password_guard)](https://pub.dev/packages/password_guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/pragneshkoli/password_guard/blob/main/LICENSE)
[![Dart SDK](https://img.shields.io/badge/dart-%3E%3D3.0.0-blue)](https://dart.dev)
[![Flutter Compatible](https://img.shields.io/badge/Flutter-compatible-54C5F8)](https://flutter.dev)

**A modern, secure, and developer-friendly password hashing library for Dart and Flutter.**

Secure password storage made effortless — with Argon2id, bcrypt, and PBKDF2 hashing, automatic
salt generation, pepper support, password migration, strength checking, and policy validation —
all behind a clean, framework-agnostic API.

> Follows the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
> Uses **Argon2id by default** — the winner of the Password Hashing Competition (PHC 2015).

---

## Why password_guard?

Most apps store passwords incorrectly — using MD5, SHA-256, or even plain text.
**password_guard** makes the secure approach the *only* approach:

```dart
import 'package:password_guard/password_guard.dart';

// Register — one line to hash
final result = await PasswordGuard.hash(password: 'myPassword123!');
await db.save(userId: user.id, passwordHash: result.hash);

// Login — one line to verify
final isValid = await PasswordGuard.verify(
  password: enteredPassword,
  hash: storedHash,
);
```

You never need to think about salts, iterations, memory factors, or timing attacks.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **Argon2id** | OWASP-recommended default — memory-hard, GPU-resistant |
| 🔏 **bcrypt** | Battle-tested, widely supported |
| 🔑 **PBKDF2-SHA256** | Pure Dart — works on Web, Android, iOS, Desktop, CLI |
| 🧂 **Auto Salt** | Cryptographically secure, 16-byte salt per hash |
| 🌶️ **Pepper Support** | Env var, in-memory, or custom `PepperProvider` |
| 📦 **Self-Contained Hash** | Store one string — no external salt column needed |
| 🔄 **Migration** | Silently upgrade weak or legacy hashes on login |
| 💪 **Strength Checker** | Score 0–100, `StrengthLevel` enum, improvement tips |
| 📋 **Policy Validation** | Min/max length, charset rules, banned passwords |
| ⏱️ **Timing Attack Safe** | Constant-time comparison in every `verify()` call |
| 🎯 **Zero Flutter Dep** | Pure Dart core — use in Flutter, Shelf, Dart Frog, CLI |
| 🧩 **Framework Agnostic** | Works with Provider, Riverpod, BLoC, GetX, MobX, Cubit |

---

## 📱 Platform Support

| Platform | Argon2id | bcrypt | PBKDF2 |
|----------|:--------:|:------:|:------:|
| Android  | ✅ | ✅ | ✅ |
| iOS      | ✅ | ✅ | ✅ |
| Web      | ✅ | ⚠️ slow | ✅ |
| macOS    | ✅ | ✅ | ✅ |
| Linux    | ✅ | ✅ | ✅ |
| Windows  | ✅ | ✅ | ✅ |
| Dart CLI | ✅ | ✅ | ✅ |

> ⚠️ On **Web**, prefer **PBKDF2** or **Argon2id** for best performance.
> bcrypt is pure Dart but significantly slower in browser environments.

---

## 🚀 Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  password_guard: ^1.0.0
```

Then run:

```bash
dart pub get
# or
flutter pub get
```

---

## 🔰 Quick Start

### Hash a password

```dart
import 'package:password_guard/password_guard.dart';

final result = await PasswordGuard.hash(password: 'myPassword123!');

// Store ONLY result.hash in your database:
// $pg$argon2id$v1$m=65536,t=3,p=4,l=32$<salt>$<hash>
print(result.hash);
```

### Verify on login

```dart
final isValid = await PasswordGuard.verify(
  password: enteredPassword,
  hash: storedHash, // from your database
);

if (!isValid) {
  throw AuthException('Invalid email or password.');
}
```

### Full login flow with migration

```dart
Future<void> login(String userId, String enteredPassword) async {
  final user = await db.getUser(userId);

  final isValid = await PasswordGuard.verify(
    password: enteredPassword,
    hash: user.passwordHash,
  );

  if (!isValid) throw AuthException('Invalid credentials');

  // Silently upgrade weak/old hashes on every successful login
  if (PasswordGuard.needsRehash(user.passwordHash)) {
    final upgraded = await PasswordGuard.hash(password: enteredPassword);
    await db.updatePasswordHash(userId, upgraded.hash);
  }
}
```

---

## 🔐 Algorithms

### Argon2id — Default (OWASP 2024 Recommended)

Memory-hard and resistant to GPU/ASIC attacks. Combines Argon2i
(side-channel resistance) and Argon2d (GPU resistance).

```dart
// Default OWASP settings — no config needed
final result = await PasswordGuard.hash(password: 'myPassword');

// Custom config
final result = await PasswordGuard.hash(
  password: 'myPassword',
  algorithm: PasswordAlgorithm.argon2id,
  config: Argon2Config(
    memory: 65536,    // 64 MB (OWASP minimum)
    iterations: 3,    // time cost
    parallelism: 4,   // thread count
    hashLength: 32,   // output bytes
  ),
);
```

### bcrypt

A proven, widely deployed algorithm. Uses Blowfish cipher with
a configurable cost factor (work factor doubles per +1 cost).

```dart
final result = await PasswordGuard.hash(
  password: 'myPassword',
  algorithm: PasswordAlgorithm.bcrypt,
  config: BcryptConfig(cost: 12), // OWASP: minimum 10, recommended 12
);
```

### PBKDF2-HMAC-SHA256

Pure Dart — runs everywhere including Web. Ideal for
cross-platform apps where bcrypt performance is a concern.

```dart
final result = await PasswordGuard.hash(
  password: 'myPassword',
  algorithm: PasswordAlgorithm.pbkdf2,
  config: PBKDF2Config(
    iterations: 600000, // OWASP minimum for SHA-256
    keyLength: 32,      // output bytes
  ),
);
```

---

## 🌶️ Pepper Support

A **pepper** is a secret value mixed into every password before hashing.
Unlike salt, pepper is **never stored in the database** — it lives in your
environment/secrets manager. Even if your database leaks, hashes are
uncrackable without the pepper.

### Inline string

```dart
final result = await PasswordGuard.hash(
  password: 'myPassword',
  pepper: 'my-secret-pepper', // store in env var or secrets manager
);

final valid = await PasswordGuard.verify(
  password: enteredPassword,
  hash: storedHash,
  pepper: 'my-secret-pepper',
);
```

### Environment variable provider

```dart
// Reads from PASSWORD_GUARD_PEPPER env var (dart:io only — not Web)
import 'package:password_guard/password_guard_io.dart';

final result = await PasswordGuard.hash(
  password: 'myPassword',
  pepperProvider: EnvPepperProvider(key: 'PASSWORD_GUARD_PEPPER'),
);
```

### Custom provider (DI-friendly)

```dart
class VaultPepperProvider implements PepperProvider {
  @override
  Future<String> getPepper() => vaultClient.getSecret('password-pepper');
}

final result = await PasswordGuard.hash(
  password: 'myPassword',
  pepperProvider: VaultPepperProvider(),
);
```

### With DI containers (GetIt, Injectable, etc.)

```dart
// Register once at startup
getIt.registerSingleton<PepperProvider>(
  MemoryPepperProvider(env['APP_PEPPER']!),
);

// Use anywhere in the app
final pepper = getIt<PepperProvider>();
final result = await PasswordGuard.hash(
  password: password,
  pepperProvider: pepper,
);
```

---

## 🔄 Password Migration

Upgrade hashes from old algorithms or weak parameters **without forcing
users to reset passwords**. Just check `needsRehash` after a successful login:

```dart
// Works for:
// - bcrypt cost < 12 → upgrade to Argon2id
// - Argon2id memory < 65536 → re-hash with OWASP defaults
// - Legacy MD5/SHA hashes → any $pg$ format
// - Plain text passwords (if you know the condition)

if (PasswordGuard.needsRehash(user.passwordHash)) {
  final upgraded = await PasswordGuard.hash(password: enteredPassword);
  await db.updatePasswordHash(userId, upgraded.hash);
}
```

---

## 💪 Password Strength Checker

Call synchronously — safe to use on every keystroke in a text field:

```dart
final result = PasswordStrength.check('MyPassword123!');

print(result.score);          // 0–100
print(result.level);          // StrengthLevel.strong
print(result.level.label);    // 'Strong'
print(result.suggestions);    // ['Add special characters']

// Check in UI
if (!result.level.isAcceptable) {
  showWarning('Please choose a stronger password.');
}
```

**StrengthLevel values:** `veryWeak` · `weak` · `medium` · `strong` · `veryStrong`

### With state management

```dart
// Riverpod
final strengthProvider = StateProvider((ref) => PasswordStrength.check(''));
ref.read(strengthProvider.notifier).state = PasswordStrength.check(input);

// BLoC
on<PasswordChanged>((event, emit) {
  emit(state.copyWith(strength: PasswordStrength.check(event.password)));
});

// GetX
final strength = Rx<PasswordStrengthResult?>(null);
strength.value = PasswordStrength.check(controller.text);
```

---

## 📋 Password Policy

```dart
final policy = PasswordPolicy(
  minLength: 6,                    // minimum — default is 6 (user-friendly)
  maxLength: 128,                  // optional max
  requireUppercase: true,          // A–Z
  requireLowercase: true,          // a–z
  requireNumber: true,             // 0–9
  requireSpecialCharacter: true,   // !@#$% etc.
  bannedPasswords: [               // custom blocklist
    'password', 'company123!',
  ],
);

// Form validation — returns all violations at once
final result = policy.validate(enteredPassword);
if (!result.isValid) {
  showErrors(result.violations); // List<String>
}

// Server-side — throws PasswordPolicyException on failure
policy.validateOrThrow(enteredPassword);
```

---

## 🔒 Hash Format

All hashes are self-contained — no separate salt column needed:

```
$pg$argon2id$v1$m=65536,t=3,p=4,l=32$<base64_salt>$<base64_hash>
$pg$bcrypt$v1$cost=12$<base64_salt>$<bcrypt_encoded>
$pg$pbkdf2$v1$iter=600000,kl=32$<base64_salt>$<base64_hash>
```

Just create a **single `password_hash TEXT` column** in your database. Done.

---

## 🎲 Secure Random Utilities

```dart
// Cryptographically secure random bytes
final bytes = SecureRandom.bytes(32); // Uint8List

// Random token — Base64-encoded
final sessionToken = SecureRandom.base64(32);

// Random ID — hex-encoded
final resetToken = SecureRandom.hex(32);

// Password salt — Base64, 16+ bytes, validated
final salt = SaltGenerator.generate();        // 16 bytes (default)
final salt = SaltGenerator.generate(length: 32); // 32 bytes
```

---

## 🛠️ Password & Passphrase Generators

Generate highly secure random passwords or readable, human-friendly passphrases using cryptographically secure values.

### Password Generator

```dart
// Generate standard 16-char password (lowercase, uppercase, numbers, special characters)
// Guarantees at least one character from each enabled set.
final password = PasswordGenerator.generate();

// Custom length and enabled pools
final custom = PasswordGenerator.generate(
  length: 24,
  includeSpecial: false,
);
```

### Passphrase Generator

Generates readable, easy-to-remember passphrases from a curated, high-quality list of 512 words. Since the default wordlist size is exactly 512 ($2^9$), each word adds exactly 9 bits of entropy to the passphrase.

```dart
// Generates standard 4-word passphrase separated by dashes: e.g. "apple-beach-cloud-flute"
final phrase = PassphraseGenerator.generate();

// Custom word count and separator
final securePhrase = PassphraseGenerator.generate(
  wordCount: 6,
  separator: '_',
);

// Calculate entropy in bits
final bits = PassphraseGenerator.calculateEntropy(wordCount: 6); // 54.0 bits
```

---

## ⚠️ Exception Handling

All exceptions extend `PasswordGuardException` for easy catch-all handling:

```dart
try {
  await PasswordGuard.verify(password: input, hash: storedHash);
} on InvalidHashException catch (e) {
  // Hash is malformed, corrupted, or from an unsupported format
  logger.error(e.message);
} on InvalidConfigurationException catch (e) {
  // Empty password, conflicting options, or bad config values
  logger.error(e.message);
} on PepperException catch (e) {
  // Pepper env var not set or empty
  logger.error(e.message);
} on PasswordPolicyException catch (e) {
  // Policy validation failed
  showErrors(e.violations); // List<String>
} on PasswordGuardException catch (e) {
  // Catch-all — any password_guard error
  logger.error('Auth error: ${e.message}');
}
```

---

## 📐 OWASP Compliance

| Setting | OWASP Minimum | `password_guard` Default |
|---------|:------------:|:------------------------:|
| Argon2id memory | 64 MB | ✅ 64 MB (65536 KB) |
| Argon2id iterations (t) | 3 | ✅ 3 |
| Argon2id parallelism (p) | 4 | ✅ 4 |
| bcrypt cost | 10 | ✅ 12 |
| PBKDF2 iterations | 600,000 | ✅ 600,000 |
| Salt length | 16 bytes | ✅ 16 bytes |
| Hash comparison | Constant-time | ✅ Always |

---

## 🧩 Framework & Library Examples

### Shelf (server-side Dart)

```dart
import 'package:shelf/shelf.dart';
import 'package:password_guard/password_guard.dart';

Handler registerHandler = (Request request) async {
  final body = await request.readAsString();
  final data = jsonDecode(body);

  final hash = await PasswordGuard.hash(password: data['password']);
  await db.createUser(email: data['email'], passwordHash: hash.hash);

  return Response.ok('{"status":"created"}');
};
```

### Dart Frog

```dart
import 'package:dart_frog/dart_frog.dart';
import 'package:password_guard/password_guard.dart';

Future<Response> onRequest(RequestContext context) async {
  final body = await context.request.json() as Map<String, dynamic>;

  final isValid = await PasswordGuard.verify(
    password: body['password'] as String,
    hash: await db.getPasswordHash(body['email'] as String),
  );

  if (!isValid) return Response.json(statusCode: 401, body: {'error': 'Unauthorized'});
  return Response.json(body: {'token': generateJwt(body['email'] as String)});
}
```

### Serverpod

```dart
Future<String> register(Session session, String email, String password) async {
  final result = await PasswordGuard.hash(password: password);
  final user = User(email: email, passwordHash: result.hash);
  await User.insert(session, user);
  return 'User created successfully';
}
```

---

## 🗺️ Roadmap

| Version | Features |
|---------|----------|
| **v1.0.0** ✅ | Argon2id, bcrypt, PBKDF2, Salt, Pepper, Verify, Migration, Strength, Policy |
| **v1.1.0** ✅ | Password generator, passphrase generator |
| **v1.2.0** | Cloud secret providers: AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Security Audit |
| **v2.0.0** | `password_guard_flutter` — ready-made UI widgets, strength indicator widget |

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create your branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a pull request

---

## 📜 License

[MIT License](LICENSE) — free for personal and commercial use.

---

## 🔗 Related Packages

- [`crypto`](https://pub.dev/packages/crypto) — SHA/HMAC primitives (used internally)
- [`hashlib`](https://pub.dev/packages/hashlib) — Low-level hash functions (used internally)
- [`dart_frog`](https://pub.dev/packages/dart_frog) — Dart server-side framework
- [`shelf`](https://pub.dev/packages/shelf) — Dart HTTP middleware framework

---

*Keywords: password hashing, argon2id, bcrypt, pbkdf2, dart security, flutter security,
password strength, OWASP, password policy, secure hashing, dart cryptography,
flutter authentication, password validation, salt, pepper, key derivation*
