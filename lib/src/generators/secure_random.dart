import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/// Provides cryptographically secure random values.
///
/// Uses [Random.secure()] under the hood — backed by the OS CSPRNG
/// on all platforms (Android, iOS, macOS, Linux, Windows, Web).
///
/// Example:
/// ```dart
/// // 32 random bytes
/// final bytes = SecureRandom.bytes(32);
///
/// // Base64-encoded random string
/// final token = SecureRandom.base64(32);
///
/// // Hex-encoded random string
/// final hex = SecureRandom.hex(32);
/// ```
class SecureRandom {
  SecureRandom._();

  static final Random _random = Random.secure();

  /// Generates [length] cryptographically secure random bytes.
  ///
  /// ```dart
  /// final bytes = SecureRandom.bytes(32);
  /// ```
  static Uint8List bytes(int length) {
    assert(length > 0, 'length must be positive');
    return Uint8List.fromList(
      List<int>.generate(length, (_) => _random.nextInt(256)),
    );
  }

  /// Generates [length] random bytes and returns them as a Base64 string.
  ///
  /// Uses standard Base64 encoding (RFC 4648).
  ///
  /// ```dart
  /// final token = SecureRandom.base64(32); // 44 chars
  /// ```
  static String base64(int length) {
    assert(length > 0, 'length must be positive');
    return base64Encode(bytes(length));
  }

  /// Generates [length] random bytes and returns them as a hex string.
  ///
  /// The returned string is [length * 2] characters long.
  ///
  /// ```dart
  /// final hex = SecureRandom.hex(16); // 32 hex chars
  /// ```
  static String hex(int length) {
    assert(length > 0, 'length must be positive');
    return bytes(length)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  /// Generates a random integer in [0, max).
  static int nextInt(int max) => _random.nextInt(max);
}
