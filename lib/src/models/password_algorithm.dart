import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';

/// Supported password hashing algorithms.
///
/// The default and OWASP-recommended choice is [argon2id].
///
/// ```dart
/// await PasswordGuard.hash(
///   password: 'myPassword',
///   algorithm: PasswordAlgorithm.argon2id,
/// );
/// ```
enum PasswordAlgorithm {
  /// Argon2id — OWASP recommended as of 2024.
  ///
  /// Memory-hard, resistant to GPU/ASIC attacks.
  /// Works on all platforms (pure Dart).
  argon2id,

  /// bcrypt — battle-tested, widely supported.
  ///
  /// Note: NOT available on web platforms.
  /// Use [argon2id] or [pbkdf2] for web.
  bcrypt,

  /// PBKDF2 with HMAC-SHA256.
  ///
  /// Pure Dart — works on all platforms including web.
  /// Use when Argon2 is unavailable.
  pbkdf2,
}

/// Returns the [AlgorithmConfig] identifier string for a given algorithm.
extension PasswordAlgorithmExtension on PasswordAlgorithm {
  /// Short identifier stored in the encoded hash string.
  String get identifier {
    switch (this) {
      case PasswordAlgorithm.argon2id:
        return 'argon2id';
      case PasswordAlgorithm.bcrypt:
        return 'bcrypt';
      case PasswordAlgorithm.pbkdf2:
        return 'pbkdf2';
    }
  }

  /// Parses an identifier string back to [PasswordAlgorithm].
  static PasswordAlgorithm fromIdentifier(String id) {
    switch (id) {
      case 'argon2id':
        return PasswordAlgorithm.argon2id;
      case 'bcrypt':
        return PasswordAlgorithm.bcrypt;
      case 'pbkdf2':
        return PasswordAlgorithm.pbkdf2;
      default:
        throw ArgumentError('Unknown algorithm identifier: $id');
    }
  }

  /// Returns the OWASP-recommended default config for this algorithm.
  AlgorithmConfig get defaultConfig {
    switch (this) {
      case PasswordAlgorithm.argon2id:
        return const Argon2Config();
      case PasswordAlgorithm.bcrypt:
        return const BcryptConfig();
      case PasswordAlgorithm.pbkdf2:
        return const PBKDF2Config();
    }
  }
}
