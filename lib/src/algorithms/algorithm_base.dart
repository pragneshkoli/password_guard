import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';

/// Abstract interface for all password hashers.
///
/// Each algorithm (Argon2id, bcrypt, PBKDF2) implements this interface.
/// The [PasswordGuard] class delegates to the appropriate hasher based on
/// the requested [PasswordAlgorithm].
abstract class PasswordHasher {
  const PasswordHasher();

  /// Hashes [password] with [salt] using this algorithm.
  ///
  /// [config] must be the appropriate type for this hasher.
  /// Returns only the raw hash bytes as a Base64 string.
  Future<String> hashRaw({
    required String password,
    required String salt,
    required AlgorithmConfig config,
  });

  /// Verifies [password] against a previously hashed value.
  ///
  /// Uses constant-time comparison to prevent timing attacks.
  ///
  /// Returns `true` if the password matches, `false` otherwise.
  Future<bool> verify({
    required String password,
    required String salt,
    required String hashValue,
    required AlgorithmConfig config,
  });
}
