/// password_guard — Comprehensive Example
///
/// This file demonstrates all major features of the password_guard library.
///
/// Run with:
///   dart run example/password_guard_example.dart
library;

import 'dart:math';
import 'package:password_guard/password_guard_io.dart';

Future<void> main() async {
  _printHeader('password_guard — Feature Demo');

  await _demo1BasicHashing();
  await _demo2AllAlgorithms();
  await _demo3PepperSupport();
  await _demo4MigrationDetection();
  await _demo5StrengthChecker();
  _demo6PolicyValidation();
  _demo7SecureRandom();
  await _demo8ExceptionHandling();
  _demo9Generators();

  _printHeader('All demos completed ✅');
}

// ──────────────────────────────────────────────────────────────────────────────
// Demo 1 — Basic Hashing & Verification
// ──────────────────────────────────────────────────────────────────────────────

Future<void> _demo1BasicHashing() async {
  _printSection('1. Basic Hashing & Verification (Argon2id default)');

  const password = 'MySecurePassword123!';

  // Hash the password — Argon2id is the default (OWASP recommended)
  final result = await PasswordGuard.hash(password: password);

  print('  Password  : $password');
  print('  Algorithm : ${result.algorithm.identifier}');
  print('  Salt      : ${result.salt}');
  print('  Hash      : ${result.hash}');
  print('  Created   : ${result.createdAt}');
  print('');

  // Only store result.hash in your database — everything is embedded
  final storedHash = result.hash;

  // Verify — correct password
  final isValid = await PasswordGuard.verify(
    password: password,
    hash: storedHash,
  );
  print('  Verify correct password  : $isValid ✅');

  // Verify — wrong password
  final isWrong = await PasswordGuard.verify(
    password: 'WrongPassword999!',
    hash: storedHash,
  );
  print('  Verify incorrect password: $isWrong ❌');

  // Unique salt — same password, different hash every time
  final result2 = await PasswordGuard.hash(password: password);
  print('  Same password → different hash: ${result.hash != result2.hash} ✅');
}

// ──────────────────────────────────────────────────────────────────────────────
// Demo 2 — All Three Algorithms
// ──────────────────────────────────────────────────────────────────────────────

Future<void> _demo2AllAlgorithms() async {
  _printSection('2. All Three Algorithms');

  const password = 'TestPassword!99';

  // ── Argon2id (default, OWASP recommended) ──────────────────────────────────
  final argon2Result = await PasswordGuard.hash(
    password: password,
    algorithm: PasswordAlgorithm.argon2id,
    // Custom config (using low values here for demo speed)
    config: Argon2Config(
      memory: 8192,    // 8 MB (production: 65536 = 64 MB)
      iterations: 1,   // production: 3
      parallelism: 1,  // production: 4
    ),
  );
  print('  Argon2id hash : ${_truncate(argon2Result.hash)}');

  final argon2Valid = await PasswordGuard.verify(
    password: password,
    hash: argon2Result.hash,
  );
  print('  Argon2id verify: $argon2Valid ✅');
  print('');

  // ── bcrypt ─────────────────────────────────────────────────────────────────
  final bcryptResult = await PasswordGuard.hash(
    password: password,
    algorithm: PasswordAlgorithm.bcrypt,
    config: BcryptConfig(cost: 4), // production: cost 12
  );
  print('  bcrypt hash   : ${_truncate(bcryptResult.hash)}');

  final bcryptValid = await PasswordGuard.verify(
    password: password,
    hash: bcryptResult.hash,
  );
  print('  bcrypt verify : $bcryptValid ✅');
  print('');

  // ── PBKDF2 (pure Dart, works on Web too) ───────────────────────────────────
  final pbkdf2Result = await PasswordGuard.hash(
    password: password,
    algorithm: PasswordAlgorithm.pbkdf2,
    config: PBKDF2Config(
      iterations: 100000, // production: 600000
      keyLength: 32,
    ),
  );
  print('  PBKDF2 hash   : ${_truncate(pbkdf2Result.hash)}');

  final pbkdf2Valid = await PasswordGuard.verify(
    password: password,
    hash: pbkdf2Result.hash,
  );
  print('  PBKDF2 verify : $pbkdf2Valid ✅');
}

// ──────────────────────────────────────────────────────────────────────────────
// Demo 3 — Pepper Support
// ──────────────────────────────────────────────────────────────────────────────

Future<void> _demo3PepperSupport() async {
  _printSection('3. Pepper Support');

  const password = 'PasswordWithPepper!';
  const pepper = 'my-app-secret-pepper-from-env';

  // Hash with inline pepper string
  final result = await PasswordGuard.hash(
    password: password,
    pepper: pepper,
    config: Argon2Config(memory: 8192, iterations: 1, parallelism: 1),
  );
  print('  Hash with pepper: ${_truncate(result.hash)}');

  // Verify with correct pepper → true
  final correct = await PasswordGuard.verify(
    password: password,
    hash: result.hash,
    pepper: pepper,
  );
  print('  Correct pepper  : $correct ✅');

  // Verify with wrong pepper → false (even with correct password!)
  final wrongPepper = await PasswordGuard.verify(
    password: password,
    hash: result.hash,
    pepper: 'wrong-pepper-value',
  );
  print('  Wrong pepper    : $wrongPepper ❌');

  print('');

  // MemoryPepperProvider — useful with DI containers (Provider, GetIt, etc.)
  final provider = MemoryPepperProvider('provider-pepper-value');
  final resultWithProvider = await PasswordGuard.hash(
    password: password,
    pepperProvider: provider,
    config: Argon2Config(memory: 8192, iterations: 1, parallelism: 1),
  );

  final validWithProvider = await PasswordGuard.verify(
    password: password,
    hash: resultWithProvider.hash,
    pepperProvider: provider,
  );
  print('  MemoryPepperProvider verify: $validWithProvider ✅');

  // EnvPepperProvider example (reads from env var PASSWORD_GUARD_PEPPER)
  // Commented out — requires the env variable to be set:
  //
  // final envProvider = EnvPepperProvider(key: 'PASSWORD_GUARD_PEPPER');
  // final envResult = await PasswordGuard.hash(
  //   password: password,
  //   pepperProvider: envProvider,
  // );
  print('  EnvPepperProvider: reads from PASSWORD_GUARD_PEPPER env var 🌶️');
}

// ──────────────────────────────────────────────────────────────────────────────
// Demo 4 — Password Migration (needsRehash)
// ──────────────────────────────────────────────────────────────────────────────

Future<void> _demo4MigrationDetection() async {
  _printSection('4. Password Migration (needsRehash)');

  // Simulate a stored hash with weak Argon2 parameters
  final weakHash = await PasswordGuard.hash(
    password: 'OldPassword1!',
    config: Argon2Config(
      memory: 8192,   // below OWASP recommendation of 65536
      iterations: 1,  // below OWASP recommendation of 3
      parallelism: 1,
    ),
  );

  // Check if it needs upgrading
  final needsUpgrade = PasswordGuard.needsRehash(weakHash.hash);
  print('  Weak config hash needs rehash   : $needsUpgrade ✅');

  // Hash with OWASP defaults
  final strongHash = await PasswordGuard.hash(
    password: 'OldPassword1!',
    // No config = OWASP defaults (m=65536, t=3, p=4)
    config: Argon2Config(memory: 65536, iterations: 3, parallelism: 4),
  );

  final needsUpgrade2 = PasswordGuard.needsRehash(strongHash.hash);
  print('  Strong config hash needs rehash : $needsUpgrade2 ✅');

  // Legacy hash (not in $pg$ format) always needs rehash
  const legacyBcrypt = r'$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW';
  final legacyNeedsRehash = PasswordGuard.needsRehash(legacyBcrypt);
  print('  Legacy bcrypt hash needs rehash : $legacyNeedsRehash ✅');

  print('');
  print('  // Typical login flow:');
  print('  // 1. Verify password against stored hash');
  print('  // 2. If valid AND needsRehash → create new hash silently');
  print('  // 3. Update database — user never sees this happen');
}

// ──────────────────────────────────────────────────────────────────────────────
// Demo 5 — Password Strength Checker
// ──────────────────────────────────────────────────────────────────────────────

Future<void> _demo5StrengthChecker() async {
  _printSection('5. Password Strength Checker');

  final passwords = [
    '123456',
    'password',
    'Hello1',
    'MyPass1!',
    'Correct!Horse2Battery',
    'X9#mK\$2nPq@wL7vZ',
  ];

  for (final pw in passwords) {
    final result = PasswordStrength.check(pw);
    final bar = _scoreBar(result.score);
    final padded = pw.padRight(22);
    print(
      '  $padded $bar '
      '${result.score.toString().padLeft(3)}/100  '
      '${result.level.label}',
    );
    if (result.suggestions.isNotEmpty) {
      for (final suggestion in result.suggestions) {
        print('    ↳ Suggestion: $suggestion');
      }
    }
  }

  print('');
  print('  -- Asynchronous Breach Check (HIBP / Breached Passwords Callback) --');
  final resultAsync = await PasswordStrength.checkAsync(
    'password123',
    isBreached: (password) async {
      // Simulation: assume 'password123' is found in leaked list
      return password == 'password123';
    },
  );
  print('  Checking "password123" with custom breached check:');
  print('    Score : ${resultAsync.score}/100');
  print('    Level : ${resultAsync.level.label}');
  for (final suggestion in resultAsync.suggestions) {
    print('    ↳ $suggestion');
  }

  print('');
  // Works synchronously — safe to call on every keystroke
  print('  PasswordStrength.check() is synchronous — call on every keystroke!');
  print('  Compatible with Provider, Riverpod, BLoC, GetX, MobX...');
}

// ──────────────────────────────────────────────────────────────────────────────
// Demo 6 — Password Policy Validation
// ──────────────────────────────────────────────────────────────────────────────

void _demo6PolicyValidation() {
  _printSection('6. Password Policy Validation');

  // Define your app's policy once
  const policy = PasswordPolicy(
    minLength: 6,   // default — users can still remember a 6-char password
    requireUppercase: true,
    requireLowercase: true,
    requireNumber: true,
    requireSpecialCharacter: true,
    bannedPasswords: ['CompanyName123!', 'Welcome1!'],
  );

  print('  Policy: min 6 chars, upper+lower+number+special required');
  print('');

  final testPasswords = [
    'weak',
    'NoSpecial123',
    'no_upper_1!',
    'MyStrongPass1!',
    'CompanyName123!',  // banned
  ];

  for (final pw in testPasswords) {
    final result = policy.validate(pw);
    final icon = result.isValid ? '✅' : '❌';
    print('  "$pw" $icon');
    if (!result.isValid) {
      for (final v in result.violations) {
        print('    • $v');
      }
    }
  }

  print('');
  // validateOrThrow — great for server-side validation
  try {
    policy.validateOrThrow('weakpass');
  } on PasswordPolicyException catch (e) {
    print('  validateOrThrow caught: ${e.violations.length} violation(s)');
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Demo 7 — Secure Random Utilities
// ──────────────────────────────────────────────────────────────────────────────

void _demo7SecureRandom() {
  _printSection('7. Secure Random Utilities');

  // Random bytes
  final bytes = SecureRandom.bytes(16);
  print('  bytes(16) length : ${bytes.length} bytes');

  // Base64-encoded token
  final token = SecureRandom.base64(32);
  print('  base64(32)       : $token');

  // Hex-encoded string
  final hex = SecureRandom.hex(16);
  print('  hex(16)          : $hex');

  // Salt generator
  final salt = SaltGenerator.generate();
  print('  SaltGenerator    : $salt');

  final salt32 = SaltGenerator.generate(length: 32);
  print('  SaltGenerator×32 : $salt32');
}

// ──────────────────────────────────────────────────────────────────────────────
// Demo 8 — Exception Handling
// ──────────────────────────────────────────────────────────────────────────────

Future<void> _demo8ExceptionHandling() async {
  _printSection('8. Exception Handling');

  // InvalidHashException — malformed hash
  try {
    await PasswordGuard.verify(
      password: 'test',
      hash: 'not-a-valid-pg-hash',
    );
  } on InvalidHashException catch (e) {
    print('  InvalidHashException      : ${e.message}');
  }

  // InvalidConfigurationException — empty password
  try {
    await PasswordGuard.hash(password: '');
  } on InvalidConfigurationException catch (e) {
    print('  InvalidConfigurationException: ${e.message}');
  }

  // InvalidConfigurationException — both pepper and pepperProvider
  try {
    await PasswordGuard.hash(
      password: 'test',
      pepper: 'raw',
      pepperProvider: MemoryPepperProvider('also-raw'),
    );
  } on InvalidConfigurationException catch (e) {
    print('  Dual pepper conflict      : ${e.message}');
  }

  // PepperException — empty pepper
  try {
    await MemoryPepperProvider('').getPepper();
  } on PepperException catch (e) {
    print('  PepperException           : ${e.message}');
  }

  // PasswordPolicyException — validateOrThrow
  try {
    const PasswordPolicy(minLength: 20).validateOrThrow('short');
  } on PasswordPolicyException catch (e) {
    print('  PasswordPolicyException   : ${e.message}');
    for (final v in e.violations) {
      print('    • Violation: $v');
    }
  }

  // Catch-all using base class
  try {
    await PasswordGuard.verify(password: 'x', hash: 'bad');
  } on PasswordGuardException catch (e) {
    print('  PasswordGuardException    : ${e.runtimeType} — ${e.message}');
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Demo 9 — Password & Passphrase Generators
// ──────────────────────────────────────────────────────────────────────────────

void _demo9Generators() {
  _printSection('9. Password & Passphrase Generators');

  // Generate a standard password
  final password = PasswordGenerator.generate();
  print('  Generated Password (default 16 chars): $password');

  // Custom password
  final customPassword = PasswordGenerator.generate(
    length: 24,
    includeSpecial: false,
  );
  print('  Custom Password (24 chars, no special): $customPassword');

  // Generate a standard passphrase
  final passphrase = PassphraseGenerator.generate();
  final entropy = PassphraseGenerator.calculateEntropy(wordCount: 4);
  print('  Generated Passphrase (default 4 words): $passphrase');
  print('  ↳ Entropy: ${entropy.toStringAsFixed(1)} bits (9.0 bits per word from 512-word list)');

  // Custom passphrase
  final customPassphrase = PassphraseGenerator.generate(
    wordCount: 6,
    separator: '_',
  );
  final customEntropy = PassphraseGenerator.calculateEntropy(wordCount: 6);
  print('  Custom Passphrase (6 words, underscore): $customPassphrase');
  print('  ↳ Entropy: ${customEntropy.toStringAsFixed(1)} bits');

  // Custom wordlist passphrase
  final customList = ['alpha', 'beta', 'gamma', 'delta', 'epsilon'];
  final customListPassphrase = PassphraseGenerator.generate(
    wordCount: 3,
    customWordList: customList,
    separator: '.',
  );
  final customListEntropy = PassphraseGenerator.calculateEntropy(
    wordCount: 3,
    customWordList: customList,
  );
  print('  Passphrase with custom list: $customListPassphrase');
  print('  ↳ List size: ${customList.length} words');
  print('  ↳ Entropy  : ${customListEntropy.toStringAsFixed(2)} bits (log2(${customList.length}) = ${(log(customList.length) / ln2).toStringAsFixed(2)} bits per word)');
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

void _printHeader(String title) {
  final line = '═' * 60;
  print('');
  print('╔$line╗');
  print('║  $title${' ' * (58 - title.length)}║');
  print('╚$line╝');
  print('');
}

void _printSection(String title) {
  print('');
  print('  ┌─ $title');
  print('  │');
}

String _truncate(String s) {
  if (s.length <= 60) return s;
  return '${s.substring(0, 57)}...';
}

String _scoreBar(int score) {
  final filled = (score / 10).round().clamp(0, 10);
  final empty = 10 - filled;
  return '[${'█' * filled}${'░' * empty}]';
}
