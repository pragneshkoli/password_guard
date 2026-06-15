import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:password_guard/src/algorithms/algorithm_base.dart';
import 'package:password_guard/src/algorithms/argon2id_hasher.dart';
import 'package:password_guard/src/algorithms/bcrypt_hasher.dart';
import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';
import 'package:password_guard/src/algorithms/pbkdf2_hasher.dart';
import 'package:password_guard/src/exceptions/exceptions.dart';
import 'package:password_guard/src/generators/salt_generator.dart';
import 'package:password_guard/src/migration/hash_parser.dart';
import 'package:password_guard/src/migration/rehash_detector.dart';
import 'package:password_guard/src/models/password_algorithm.dart';
import 'package:password_guard/src/models/password_hash_result.dart';
import 'package:password_guard/src/pepper/pepper_provider.dart';

/// The main entry point for password_guard.
///
/// ## Quick Start
///
/// ```dart
/// // Hash a password (Argon2id by default)
/// final result = await PasswordGuard.hash(password: 'myPassword123!');
///
/// // Store result.hash in your database — that's all you need
/// await db.save(userId, result.hash);
///
/// // Verify on login
/// final isValid = await PasswordGuard.verify(
///   password: enteredPassword,
///   hash: storedHash,
/// );
/// ```
///
/// ## Works with Any State Management
///
/// The API is pure async functions — no streams, no ChangeNotifier,
/// no reactive primitives. Wire it into whatever you use:
///
/// ```dart
/// // Riverpod
/// final hashFuture = ref.watch(
///   FutureProvider((ref) => PasswordGuard.hash(password: password)),
/// );
///
/// // BLoC
/// on<RegisterSubmitted>((event, emit) async {
///   final result = await PasswordGuard.hash(password: event.password);
///   emit(RegisterSuccess(hash: result.hash));
/// });
///
/// // GetX
/// Future<void> register(String password) async {
///   final result = await PasswordGuard.hash(password: password);
///   await authRepo.register(passwordHash: result.hash);
/// }
///
/// // Shelf / Dart Frog / Serverpod — exact same API
/// ```
///
/// ## Framework Support
///
/// This package has ZERO dependency on Flutter.
/// It works identically in:
/// - Flutter (Android, iOS, Web, Desktop)
/// - Shelf HTTP servers
/// - Dart Frog
/// - Serverpod
/// - Dart CLI tools
/// - Any Dart runtime ≥ 3.0.0
class PasswordGuard {
  PasswordGuard._();

  // ── Hasher registry ────────────────────────────────────────────────────────

  static const Map<PasswordAlgorithm, PasswordHasher> _hashers = {
    PasswordAlgorithm.argon2id: Argon2IdHasher(),
    PasswordAlgorithm.bcrypt: BcryptHasher(),
    PasswordAlgorithm.pbkdf2: PBKDF2Hasher(),
  };

  // ── hash ───────────────────────────────────────────────────────────────────

  /// Hashes [password] and returns a [PasswordHashResult].
  ///
  /// ## Parameters
  ///
  /// - [password]: The plaintext password to hash. Must not be empty.
  /// - [algorithm]: Hashing algorithm. Defaults to [PasswordAlgorithm.argon2id].
  /// - [saltLength]: Salt length in bytes. Must be ≥ 16. Defaults to 16.
  /// - [config]: Algorithm-specific configuration. Uses OWASP defaults if omitted.
  /// - [pepper]: A raw pepper string to mix in. Mutually exclusive with [pepperProvider].
  /// - [pepperProvider]: A [PepperProvider] to fetch the pepper from.
  ///
  /// ## Returns
  ///
  /// A [PasswordHashResult] containing the self-contained encoded [hash] string.
  /// **Only store [PasswordHashResult.hash] in your database.**
  ///
  /// ## Example
  ///
  /// ```dart
  /// // Simple usage
  /// final result = await PasswordGuard.hash(password: 'hunter2');
  ///
  /// // With pepper from environment
  /// final result = await PasswordGuard.hash(
  ///   password: 'hunter2',
  ///   pepperProvider: EnvPepperProvider(key: 'APP_PEPPER'),
  /// );
  ///
  /// // Custom config
  /// final result = await PasswordGuard.hash(
  ///   password: 'hunter2',
  ///   config: Argon2Config(memory: 131072, iterations: 4),
  /// );
  /// ```
  ///
  /// Throws [InvalidConfigurationException] if config is invalid.
  /// Throws [PepperException] if pepper provider fails.
  static Future<PasswordHashResult> hash({
    required String password,
    PasswordAlgorithm algorithm = PasswordAlgorithm.argon2id,
    int saltLength = SaltGenerator.minimumLength,
    AlgorithmConfig? config,
    String? pepper,
    PepperProvider? pepperProvider,
  }) async {
    if (password.isEmpty) {
      throw const InvalidConfigurationException('Password must not be empty.');
    }

    if (pepper != null && pepperProvider != null) {
      throw const InvalidConfigurationException(
        'Provide either "pepper" or "pepperProvider", not both.',
      );
    }

    final resolvedConfig = config ?? algorithm.defaultConfig;
    resolvedConfig.validate();

    final salt = SaltGenerator.generate(length: saltLength);

    // Resolve pepper
    final String? resolvedPepper;
    if (pepperProvider != null) {
      resolvedPepper = await pepperProvider.getPepper();
    } else {
      resolvedPepper = pepper;
    }

    // Apply pepper to password if provided
    final effectivePassword = resolvedPepper != null
        ? _applyPepper(password, resolvedPepper)
        : password;

    final hasher = _hashers[algorithm]!;
    final rawHash = await hasher.hashRaw(
      password: effectivePassword,
      salt: salt,
      config: resolvedConfig,
    );

    final encodedHash = HashParser.encode(
      algorithm: algorithm,
      config: resolvedConfig,
      salt: salt,
      hashValue: rawHash,
    );

    return PasswordHashResult(
      hash: encodedHash,
      salt: salt,
      algorithm: algorithm,
      createdAt: DateTime.now().toUtc(),
    );
  }

  // ── verify ─────────────────────────────────────────────────────────────────

  /// Verifies [password] against a stored [hash].
  ///
  /// The hash must be in the `$pg$` encoded format produced by [PasswordGuard.hash].
  ///
  /// Uses constant-time comparison internally to prevent timing attacks.
  ///
  /// ## Parameters
  ///
  /// - [password]: The plaintext password to check.
  /// - [hash]: The encoded hash string from [PasswordHashResult.hash].
  /// - [pepper]: Must match the pepper used during [hash] (if any).
  /// - [pepperProvider]: Provider to fetch the pepper used during [hash].
  ///
  /// ## Returns
  ///
  /// `true` if the password matches, `false` otherwise.
  ///
  /// ## Example
  ///
  /// ```dart
  /// final isValid = await PasswordGuard.verify(
  ///   password: enteredPassword,
  ///   hash: storedHash,
  /// );
  ///
  /// if (!isValid) throw AuthenticationException('Invalid credentials');
  /// ```
  ///
  /// Throws [InvalidHashException] if the hash is malformed.
  /// Throws [PepperException] if the pepper provider fails.
  static Future<bool> verify({
    required String password,
    required String hash,
    String? pepper,
    PepperProvider? pepperProvider,
  }) async {
    if (password.isEmpty) return false;

    if (pepper != null && pepperProvider != null) {
      throw const InvalidConfigurationException(
        'Provide either "pepper" or "pepperProvider", not both.',
      );
    }

    // Parse the encoded hash to extract metadata
    final metadata = HashParser.parse(hash);

    // Resolve pepper
    final String? resolvedPepper;
    if (pepperProvider != null) {
      resolvedPepper = await pepperProvider.getPepper();
    } else {
      resolvedPepper = pepper;
    }

    final effectivePassword = resolvedPepper != null
        ? _applyPepper(password, resolvedPepper)
        : password;

    final hasher = _hashers[metadata.algorithm]!;
    return hasher.verify(
      password: effectivePassword,
      salt: metadata.salt,
      hashValue: metadata.hashValue,
      config: metadata.config,
    );
  }

  // ── needsRehash ────────────────────────────────────────────────────────────

  /// Returns `true` if [hash] should be rehashed.
  ///
  /// Call this after a successful login to transparently upgrade
  /// weak/legacy hashes to current recommendations.
  ///
  /// ## Example
  ///
  /// ```dart
  /// final isValid = await PasswordGuard.verify(
  ///   password: password,
  ///   hash: storedHash,
  /// );
  ///
  /// if (isValid && PasswordGuard.needsRehash(storedHash)) {
  ///   final newHash = await PasswordGuard.hash(password: password);
  ///   await db.updateHash(userId, newHash.hash);
  /// }
  /// ```
  ///
  /// Returns `true` if:
  /// - The hash is not in the `$pg$` format (legacy hash)
  /// - The algorithm differs from [targetAlgorithm]
  /// - The parameters are weaker than [targetConfig]
  static bool needsRehash(
    String hash, {
    PasswordAlgorithm targetAlgorithm = PasswordAlgorithm.argon2id,
    AlgorithmConfig? targetConfig,
  }) {
    return RehashDetector.needsRehash(
      hash,
      targetAlgorithm: targetAlgorithm,
      targetConfig: targetConfig,
    );
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  /// Mixes the pepper into the password using HMAC-SHA256.
  ///
  /// The pepper is never stored.
  static String _applyPepper(String password, String pepper) {
    final key = utf8.encode(pepper);
    final msg = utf8.encode(password);
    final hmac = Hmac(sha256, key);
    return base64Encode(hmac.convert(msg).bytes);
  }
}
