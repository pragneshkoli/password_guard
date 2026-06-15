import 'dart:convert';

import 'package:hashlib/hashlib.dart';
import 'package:password_guard/src/algorithms/algorithm_base.dart';
import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';
import 'package:password_guard/src/exceptions/exceptions.dart';

/// Implements bcrypt password hashing using [hashlib].
///
/// bcrypt is a battle-tested algorithm, widely supported across platforms.
///
/// Note: The managed [salt] is mixed into the password string before bcrypt
/// processes it, so bcrypt uses its own internal 16-byte salt as well.
/// The combined approach gives us consistent salt management while leveraging
/// bcrypt's self-contained format.
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

    // Mix our managed salt with the password for consistent salt management
    final saltedPassword = utf8.encode('$salt:$password');

    // Use hashlib's bcrypt — generates its own 16-byte internal salt
    final digest = bcryptDigest(saltedPassword, nb: config.cost);
    // Return the full bcrypt encoded string as the hash value
    return base64Encode(utf8.encode(digest.encoded()));
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

    try {
      final encodedHash = utf8.decode(base64Decode(hashValue));
      return bcryptVerify(encodedHash, saltedPassword);
    } catch (e) {
      throw InvalidHashException.withCause(
        'bcrypt hash is malformed or corrupted.',
        cause: e,
      );
    }
  }
}
