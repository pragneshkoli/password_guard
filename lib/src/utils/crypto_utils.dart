import 'dart:convert';

/// Cryptographic utility helper methods.
class CryptoUtils {
  CryptoUtils._();

  /// Performs a constant-time comparison on two strings to prevent timing attacks.
  ///
  /// Evaluates all characters regardless of mismatches to ensure the operation
  /// runtime does not leak information about match length.
  static bool constantTimeEquals(String a, String b) {
    final aBytes = utf8.encode(a);
    final bBytes = utf8.encode(b);
    if (aBytes.length != bBytes.length) {
      // Iterate to prevent length timing leak
      int diff = 0;
      final maxLen =
          aBytes.length > bBytes.length ? aBytes.length : bBytes.length;
      for (int i = 0; i < maxLen; i++) {
        final aVal = i < aBytes.length ? aBytes[i] : 0;
        final bVal = i < bBytes.length ? bBytes[i] : 0;
        diff |= aVal ^ bVal;
      }
      return diff == 0 && aBytes.length == bBytes.length;
    }
    int diff = 0;
    for (int i = 0; i < aBytes.length; i++) {
      diff |= aBytes[i] ^ bBytes[i];
    }
    return diff == 0;
  }
}
