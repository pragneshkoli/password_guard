import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';
import 'package:password_guard/src/exceptions/exceptions.dart';
import 'package:password_guard/src/models/hash_metadata.dart';
import 'package:password_guard/src/models/password_algorithm.dart';

/// The prefix that identifies all password_guard encoded hash strings.
const String _kHashPrefix = r'$pg$';

/// Current hash format version.
const int _kFormatVersion = 1;

/// Parses and encodes the `$pg$` hash format.
///
/// ## Encoded Format
///
/// ```
/// $pg$<algorithm>$v<version>$<params>$<salt>$<hash>
/// ```
///
/// ### Examples
///
/// Argon2id:
/// ```
/// $pg$argon2id$v1$m=65536,t=3,p=4,l=32$<base64salt>$<base64hash>
/// ```
///
/// bcrypt:
/// ```
/// $pg$bcrypt$v1$cost=12$<base64salt>$<base64hash>
/// ```
///
/// PBKDF2:
/// ```
/// $pg$pbkdf2$v1$iter=600000,kl=32$<base64salt>$<base64hash>
/// ```
class HashParser {
  HashParser._();

  /// Encodes hash components into the `$pg$` format string.
  static String encode({
    required PasswordAlgorithm algorithm,
    required AlgorithmConfig config,
    required String salt,
    required String hashValue,
  }) {
    final params = _encodeParams(algorithm, config);
    return '$_kHashPrefix${algorithm.identifier}\$v$_kFormatVersion'
        '\$$params\$$salt\$$hashValue';
  }

  /// Parses an encoded hash string into [HashMetadata].
  ///
  /// Throws [InvalidHashException] if the string is malformed.
  static HashMetadata parse(String encodedHash) {
    if (!encodedHash.startsWith(_kHashPrefix)) {
      throw InvalidHashException(
        'Hash does not start with the password_guard prefix "$_kHashPrefix". '
        'This may be a legacy hash or from another library.',
      );
    }

    // Remove the leading '$pg$' and split
    final withoutPrefix = encodedHash.substring(_kHashPrefix.length);
    final parts = withoutPrefix.split('\$');

    // Expected parts: [algorithm, version, params, salt, hash]
    if (parts.length != 5) {
      throw InvalidHashException(
        'Hash has ${parts.length} segments but expected 5. '
        'The hash may be corrupted.',
      );
    }

    final algorithmStr = parts[0];
    final versionStr = parts[1];
    final paramsStr = parts[2];
    final salt = parts[3];
    final hashValue = parts[4];

    // Parse algorithm
    final PasswordAlgorithm algorithm;
    try {
      algorithm = PasswordAlgorithmExtension.fromIdentifier(algorithmStr);
    } catch (_) {
      throw InvalidHashException(
          'Unknown algorithm identifier: "$algorithmStr".');
    }

    // Parse version
    if (!versionStr.startsWith('v')) {
      throw InvalidHashException('Invalid version segment: "$versionStr".');
    }
    final int formatVersion;
    try {
      formatVersion = int.parse(versionStr.substring(1));
    } catch (_) {
      throw InvalidHashException(
        'Could not parse version number from: "$versionStr".',
      );
    }
    if (formatVersion > _kFormatVersion) {
      throw InvalidHashException(
        'Unsupported hash format version: "v$formatVersion". '
        'This library supports up to version "v$_kFormatVersion".',
      );
    }

    // Parse params
    final config = _parseParams(algorithm, paramsStr);

    // Validate salt and hash are not empty
    if (salt.isEmpty) {
      throw InvalidHashException('Hash contains an empty salt segment.');
    }
    if (hashValue.isEmpty) {
      throw InvalidHashException('Hash contains an empty hash segment.');
    }

    return HashMetadata(
      algorithm: algorithm,
      formatVersion: formatVersion,
      salt: salt,
      hashValue: hashValue,
      config: config,
    );
  }

  /// Returns true if [encodedHash] starts with the `$pg$` prefix.
  static bool isPasswordGuardHash(String encodedHash) =>
      encodedHash.startsWith(_kHashPrefix);

  // ──────────────────────────────────────────────────────────
  // Private helpers
  // ──────────────────────────────────────────────────────────

  static String _encodeParams(
    PasswordAlgorithm algorithm,
    AlgorithmConfig config,
  ) {
    switch (algorithm) {
      case PasswordAlgorithm.argon2id:
        final c = config as Argon2Config;
        return 'm=${c.memory},t=${c.iterations},p=${c.parallelism},l=${c.hashLength}';

      case PasswordAlgorithm.bcrypt:
        final c = config as BcryptConfig;
        return 'cost=${c.cost}';

      case PasswordAlgorithm.pbkdf2:
        final c = config as PBKDF2Config;
        return 'iter=${c.iterations},kl=${c.keyLength}';
    }
  }

  static AlgorithmConfig _parseParams(
    PasswordAlgorithm algorithm,
    String paramsStr,
  ) {
    final params = _splitParams(paramsStr);

    switch (algorithm) {
      case PasswordAlgorithm.argon2id:
        return Argon2Config(
          memory: _requireInt(params, 'm', paramsStr),
          iterations: _requireInt(params, 't', paramsStr),
          parallelism: _requireInt(params, 'p', paramsStr),
          hashLength: _requireInt(params, 'l', paramsStr),
        );

      case PasswordAlgorithm.bcrypt:
        return BcryptConfig(
          cost: _requireInt(params, 'cost', paramsStr),
        );

      case PasswordAlgorithm.pbkdf2:
        return PBKDF2Config(
          iterations: _requireInt(params, 'iter', paramsStr),
          keyLength: _requireInt(params, 'kl', paramsStr),
        );
    }
  }

  static Map<String, String> _splitParams(String paramsStr) {
    final result = <String, String>{};
    for (final pair in paramsStr.split(',')) {
      final idx = pair.indexOf('=');
      if (idx == -1) {
        throw InvalidHashException('Malformed param segment: "$pair".');
      }
      result[pair.substring(0, idx)] = pair.substring(idx + 1);
    }
    return result;
  }

  static int _requireInt(
    Map<String, String> params,
    String key,
    String fullParams,
  ) {
    final value = params[key];
    if (value == null) {
      throw InvalidHashException(
        'Missing required parameter "$key" in params: "$fullParams".',
      );
    }
    final parsed = int.tryParse(value);
    if (parsed == null) {
      throw InvalidHashException(
        'Parameter "$key" has non-integer value "$value".',
      );
    }
    return parsed;
  }
}
