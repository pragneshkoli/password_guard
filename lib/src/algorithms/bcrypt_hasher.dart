import 'dart:convert';
import 'dart:isolate';

import 'package:crypto/crypto.dart' as crypto;
import 'package:hashlib/hashlib.dart';
import 'package:password_guard/src/algorithms/algorithm_base.dart';
import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';
import 'package:password_guard/src/exceptions/exceptions.dart';

/// Implements bcrypt password hashing using [hashlib].
///
/// bcrypt is a battle-tested algorithm, widely supported across platforms.
///
/// Note: The managed [salt] is mixed with the password and pre-hashed using SHA-256,
/// producing a fixed-size Base64 string before passing it to bcrypt. This resolves
/// the 72-byte password truncation limit inherent to bcrypt, making it safe for
/// long passwords/passphrases.
///
/// Platform support:
/// - Android ✅, iOS ✅, macOS ✅, Linux ✅, Windows ✅, Web ✅ (pure Dart)
class BcryptHasher implements PasswordHasher {
  const BcryptHasher();

  @override
  Future<String> hashRaw({
    required String password,
    required String salt,
    required AlgorithmConfig config,
  }) async {
    if (config is! BcryptConfig) {
      throw InvalidConfigurationException(
        'Expected BcryptConfig but got ${config.runtimeType}.',
      );
    }
    config.validate();

    // Pre-hash password and salt using SHA-256 to prevent bcrypt's 72-byte truncation
    final saltedPassword = utf8.encode('$salt:$password');
    final prehash = base64Encode(crypto.sha256.convert(saltedPassword).bytes);
    final prehashBytes = utf8.encode(prehash);

    // Run in isolate to prevent blocking the main thread
    final digestEncoded = await Isolate.run(() {
      // Use hashlib's bcrypt — generates its own 16-byte internal salt
      final digest = bcryptDigest(prehashBytes, nb: config.cost);
      return digest.encoded();
    });

    // Return the full bcrypt encoded string as the hash value
    return base64Encode(utf8.encode(digestEncoded));
  }

  @override
  Future<bool> verify({
    required String password,
    required String salt,
    required String hashValue,
    required AlgorithmConfig config,
  }) async {
    if (config is! BcryptConfig) {
      throw InvalidConfigurationException(
        'Expected BcryptConfig but got ${config.runtimeType}.',
      );
    }

    final saltedPassword = utf8.encode('$salt:$password');
    final prehash = base64Encode(crypto.sha256.convert(saltedPassword).bytes);
    final prehashBytes = utf8.encode(prehash);

    try {
      final encodedHash = utf8.decode(base64Decode(hashValue));
      // Run in isolate to prevent blocking the main thread
      return await Isolate.run(() {
        return bcryptVerify(encodedHash, prehashBytes);
      });
    } catch (e) {
      throw InvalidHashException.withCause(
        'bcrypt hash is malformed or corrupted.',
        cause: e,
      );
    }
  }
}
