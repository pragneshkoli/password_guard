import 'package:password_guard/src/algorithms/configs/algorithm_config.dart';
import 'package:password_guard/src/models/password_algorithm.dart';

/// Internal model representing the parsed components of an encoded hash.
///
/// This is used internally by [HashParser] and [RehashDetector].
/// Not part of the public API.
class HashMetadata {
  /// The hashing algorithm used.
  final PasswordAlgorithm algorithm;

  /// The hash format version (e.g., 1 for 'v1').
  final int formatVersion;

  /// The Base64-encoded salt.
  final String salt;

  /// The Base64-encoded raw hash bytes.
  final String hashValue;

  /// The algorithm-specific configuration extracted from the hash.
  final AlgorithmConfig config;

  const HashMetadata({
    required this.algorithm,
    required this.formatVersion,
    required this.salt,
    required this.hashValue,
    required this.config,
  });

  @override
  String toString() =>
      'HashMetadata(algorithm: ${algorithm.identifier}, '
      'version: v$formatVersion)';
}
