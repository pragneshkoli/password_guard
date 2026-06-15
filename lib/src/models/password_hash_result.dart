import 'package:password_guard/src/models/password_algorithm.dart';

/// The result returned from [PasswordGuard.hash].
///
/// Contains all data needed to verify the password later.
/// The [hash] field is a self-contained encoded string that includes
/// the algorithm, parameters, salt, and hash — so only [hash] needs
/// to be stored in the database.
///
/// Example:
/// ```dart
/// final result = await PasswordGuard.hash(password: 'myPassword');
/// // Store only result.hash in your database
/// await db.save(userId: user.id, passwordHash: result.hash);
/// ```
class PasswordHashResult {
  /// The full encoded hash string.
  ///
  /// Format: `$pg$<algorithm>$v1$<params>$<salt>$<hash>`
  ///
  /// This is the ONLY value you need to persist.
  /// Everything else (salt, algorithm, parameters) is embedded.
  final String hash;

  /// The Base64-encoded salt that was used.
  ///
  /// Already embedded inside [hash]. Exposed here for inspection/logging.
  /// Do NOT store this separately — it's not needed for verification.
  final String salt;

  /// The algorithm that was used to produce this hash.
  final PasswordAlgorithm algorithm;

  /// When this hash was created.
  final DateTime createdAt;

  const PasswordHashResult({
    required this.hash,
    required this.salt,
    required this.algorithm,
    required this.createdAt,
  });

  @override
  String toString() =>
      'PasswordHashResult(algorithm: ${algorithm.identifier}, '
      'createdAt: $createdAt)';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PasswordHashResult &&
          runtimeType == other.runtimeType &&
          hash == other.hash &&
          salt == other.salt &&
          algorithm == other.algorithm;

  @override
  int get hashCode => Object.hash(hash, salt, algorithm);
}
