import 'package:password_guard/src/generators/secure_random.dart';

/// Generates cryptographically secure random salts.
///
/// This is used internally by [PasswordGuard.hash] to produce a unique
/// salt for every hash operation. You do not need to call this directly.
///
/// Example:
/// ```dart
/// // 16-byte salt (default)
/// final salt = SaltGenerator.generate();
///
/// // Custom 32-byte salt
/// final salt = SaltGenerator.generate(length: 32);
/// ```
class SaltGenerator {
  SaltGenerator._();

  /// Minimum salt length in bytes per OWASP recommendation.
  static const int minimumLength = 16;

  /// Generates a Base64-encoded random salt of [length] bytes.
  ///
  /// [length] must be at least [minimumLength] (16 bytes).
  /// Defaults to 16 bytes.
  ///
  /// Throws [ArgumentError] if [length] < [minimumLength].
  static String generate({int length = minimumLength}) {
    if (length < minimumLength) {
      throw ArgumentError(
        'Salt length must be at least $minimumLength bytes. '
        'Got: $length. OWASP recommends at least 16 bytes.',
      );
    }
    return SecureRandom.base64(length);
  }
}
