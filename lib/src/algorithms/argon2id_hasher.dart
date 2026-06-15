import 'dart:convert';

import 'package:hashlib/hashlib.dart';
import 'package:password_guard/src/algorithms/algorithm_base.dart';
import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';
import 'package:password_guard/src/exceptions/exceptions.dart';

/// Implements Argon2id password hashing using [hashlib].
///
/// Argon2id is the OWASP-recommended algorithm as of 2024.
/// It is memory-hard and resistant to GPU/ASIC brute-force attacks.
///
/// Uses `package:hashlib` — pure Dart, works on
/// Android, iOS, Web, macOS, Linux, Windows, and Dart CLI.
class Argon2IdHasher implements PasswordHasher {
  const Argon2IdHasher();

  @override
  Future<String> hashRaw({
    required String password,
    required String salt,
    required AlgorithmConfig config,
  }) async {
    if (config is! Argon2Config) {
      throw InvalidConfigurationException(
        'Expected Argon2Config but got ${config.runtimeType}.',
      );
    }
    config.validate();

    final passwordBytes = utf8.encode(password);
    final saltBytes = base64Decode(salt);

    final digest = Argon2(
      salt: saltBytes,
      memorySizeKB: config.memory,
      iterations: config.iterations,
      parallelism: config.parallelism,
      hashLength: config.hashLength,
    ).convert(passwordBytes);

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

  /// Constant-time string comparison to prevent timing attacks.
  bool _constantTimeEquals(String a, String b) {
    final aBytes = utf8.encode(a);
    final bBytes = utf8.encode(b);
    if (aBytes.length != bBytes.length) {
      // Still iterate to prevent length-based timing leak
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
