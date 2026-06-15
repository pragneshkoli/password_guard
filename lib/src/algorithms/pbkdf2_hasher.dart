import 'dart:convert';
import 'dart:isolate';

import 'package:hashlib/hashlib.dart';
import 'package:password_guard/src/algorithms/algorithm_base.dart';
import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';
import 'package:password_guard/src/exceptions/exceptions.dart';
import 'package:password_guard/src/utils/crypto_utils.dart';

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

    // Run in isolate to prevent blocking the main thread
    final digestBytes = await Isolate.run(() {
      return pbkdf2(
        passwordBytes,
        saltBytes,
        config.iterations,
        config.keyLength,
      ).bytes;
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
