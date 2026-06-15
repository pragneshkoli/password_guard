import 'dart:convert';

import 'package:hashlib/hashlib.dart';
import 'package:password_guard/src/algorithms/algorithm_base.dart';
import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';
import 'package:password_guard/src/exceptions/exceptions.dart';

/// Implements PBKDF2-HMAC-SHA256 password hashing using [hashlib].
///
/// PBKDF2 is a pure-Dart implementation that works on ALL platforms
/// including Web, Android, iOS, Desktop, and CLI.
///
/// OWASP recommends 600,000+ iterations with SHA-256.
///
/// Platform support:
/// - Android ✅, iOS ✅, Web ✅, macOS ✅, Linux ✅, Windows ✅
class PBKDF2Hasher implements PasswordHasher {
  const PBKDF2Hasher();

  @override
  Future<String> hashRaw({
    required String password,
    required String salt,
    required AlgorithmConfig config,
  }) async {
    if (config is! PBKDF2Config) {
      throw InvalidConfigurationException(
        'Expected PBKDF2Config but got ${config.runtimeType}.',
      );
    }
    config.validate();

    final passwordBytes = utf8.encode(password);
    final saltBytes = base64Decode(salt);

    // hashlib's pbkdf2 uses HMAC-SHA256 by default
    final digest = pbkdf2(
      passwordBytes,
      saltBytes,
      config.iterations,
      config.keyLength,
    );

    return base64Encode(digest.bytes);
  }

  @override
  Future<bool> verify({
    required String password,
    required String salt,
    required String hashValue,
    required AlgorithmConfig config,
  }) async {
    final computed = await hashRaw(
      password: password,
      salt: salt,
      config: config,
    );
    return _constantTimeEquals(computed, hashValue);
  }

  /// Constant-time comparison to prevent timing attacks.
  bool _constantTimeEquals(String a, String b) {
    final aBytes = utf8.encode(a);
    final bBytes = utf8.encode(b);
    if (aBytes.length != bBytes.length) {
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
