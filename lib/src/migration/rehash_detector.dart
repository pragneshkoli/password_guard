import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';
import 'package:password_guard/src/migration/hash_parser.dart';
import 'package:password_guard/src/models/hash_metadata.dart';
import 'package:password_guard/src/models/password_algorithm.dart';

/// Detects whether a stored password hash should be rehashed.
///
/// Use this after a successful login to transparently upgrade hashes
/// to newer/stronger parameters without forcing a password reset.
///
/// ## Example
///
/// ```dart
/// // After successful login:
/// if (PasswordGuard.needsRehash(storedHash)) {
///   final newHash = await PasswordGuard.hash(password: enteredPassword);
///   await db.updatePasswordHash(userId, newHash.hash);
/// }
/// ```
class RehashDetector {
  RehashDetector._();

  /// Returns `true` if the given hash should be rehashed.
  ///
  /// This returns true when any of the following is true:
  /// - The hash is not in `$pg$` format (legacy hash)
  /// - The algorithm differs from [targetAlgorithm]
  /// - The algorithm parameters are weaker than [targetConfig]
  ///
  /// [targetAlgorithm] defaults to [PasswordAlgorithm.argon2id].
  /// [targetConfig] defaults to the OWASP-recommended defaults.
  static bool needsRehash(
    String hash, {
    PasswordAlgorithm targetAlgorithm = PasswordAlgorithm.argon2id,
    AlgorithmConfig? targetConfig,
  }) {
    // If not a password_guard hash, definitely needs rehash
    if (!HashParser.isPasswordGuardHash(hash)) {
      return true;
    }

    final HashMetadata metadata;
    try {
      metadata = HashParser.parse(hash);
    } catch (_) {
      // Can't parse → definitely needs rehash
      return true;
    }

    // Different algorithm
    if (metadata.algorithm != targetAlgorithm) {
      return true;
    }

    final target = targetConfig ?? targetAlgorithm.defaultConfig;

    // Check algorithm-specific parameter weaknesses
    return _isWeakerThan(metadata.config, target, metadata.algorithm);
  }

  static bool _isWeakerThan(
    AlgorithmConfig current,
    AlgorithmConfig target,
    PasswordAlgorithm algorithm,
  ) {
    switch (algorithm) {
      case PasswordAlgorithm.argon2id:
        if (current is! Argon2Config || target is! Argon2Config) return true;
        return current.memory < target.memory ||
            current.iterations < target.iterations ||
            current.hashLength < target.hashLength;

      case PasswordAlgorithm.bcrypt:
        if (current is! BcryptConfig || target is! BcryptConfig) return true;
        return current.cost < target.cost;

      case PasswordAlgorithm.pbkdf2:
        if (current is! PBKDF2Config || target is! PBKDF2Config) return true;
        return current.iterations < target.iterations ||
            current.keyLength < target.keyLength;
    }
  }
}
