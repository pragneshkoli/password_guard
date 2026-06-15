import 'dart:convert';
import 'package:password_guard/src/utils/isolate_runner.dart';

import 'package:hashlib/hashlib.dart';
import 'package:password_guard/src/algorithms/algorithm_base.dart';
import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';
import 'package:password_guard/src/exceptions/exceptions.dart';
import 'package:password_guard/src/utils/crypto_utils.dart';

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

    final digestBytes = await runInIsolate(() {
      return Argon2(
        salt: saltBytes,
        memorySizeKB: config.memory,
        iterations: config.iterations,
        parallelism: config.parallelism,
        hashLength: config.hashLength,
      ).convert(passwordBytes).bytes;
    });

    return base64Encode(digestBytes);
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
    return CryptoUtils.constantTimeEquals(computed, hashValue);
  }
}
