/// Password Guard — A modern, secure, developer-friendly password hashing
/// library for Dart and Flutter.
///
/// ## Quick Start
///
/// ```dart
/// import 'package:password_guard/password_guard.dart';
///
/// // Hash
/// final result = await PasswordGuard.hash(password: 'myPassword');
///
/// // Verify
/// final valid = await PasswordGuard.verify(
///   password: 'myPassword',
///   hash: result.hash,
/// );
///
/// // Check strength
/// final strength = PasswordStrength.check('myPassword');
///
/// // Policy validation
/// final policy = PasswordPolicy(minLength: 12, requireUppercase: true);
/// final policyResult = policy.validate('myPassword');
/// ```
///
/// ## Framework Support
///
/// Works with ANY Dart/Flutter stack — no Flutter dependency in core.
/// Compatible with: Provider, Riverpod, BLoC, GetX, MobX, Cubit,
/// Shelf, Dart Frog, Serverpod, Dart CLI.
library password_guard;

// ── Main API ───────────────────────────────────────────────────────────────
export 'src/password_guard_base.dart' show PasswordGuard;

// ── Algorithms ─────────────────────────────────────────────────────────────
export 'src/models/password_algorithm.dart'
    show PasswordAlgorithm, PasswordAlgorithmExtension;

// ── Algorithm Configs ──────────────────────────────────────────────────────
export 'src/algorithms/configs/algorithm_config.dart'
    show AlgorithmConfig, Argon2Config, BcryptConfig, PBKDF2Config;

// ── Models ─────────────────────────────────────────────────────────────────
export 'src/models/password_hash_result.dart' show PasswordHashResult;
export 'src/models/password_strength_result.dart'
    show PasswordStrengthResult, StrengthLevel, StrengthLevelExtension;

// ── Validators ─────────────────────────────────────────────────────────────
export 'src/validators/password_strength_checker.dart' show PasswordStrength;
export 'src/validators/password_policy.dart'
    show PasswordPolicy, PasswordValidationResult;

// ── Pepper Providers ───────────────────────────────────────────────────────
export 'src/pepper/pepper_provider.dart'
    show PepperProvider, MemoryPepperProvider;
// Note: EnvPepperProvider requires dart:io (not available on Web).
// Import package:password_guard/password_guard_io.dart when needed on native platforms.

// ── Utilities ──────────────────────────────────────────────────────────────
export 'src/generators/secure_random.dart' show SecureRandom;
export 'src/generators/salt_generator.dart' show SaltGenerator;
export 'src/generators/password_generator.dart' show PasswordGenerator;
export 'src/generators/passphrase_generator.dart' show PassphraseGenerator;

// ── Exceptions ─────────────────────────────────────────────────────────────
export 'src/exceptions/exceptions.dart'
    show
        PasswordGuardException,
        InvalidHashException,
        UnsupportedAlgorithmException,
        InvalidConfigurationException,
        PepperException,
        PasswordPolicyException;
