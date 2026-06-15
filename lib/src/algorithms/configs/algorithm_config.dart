/// Base class for all algorithm configuration objects.
///
/// Extend this to create algorithm-specific configs:
/// - [Argon2Config]
/// - [BcryptConfig]
/// - [PBKDF2Config]
abstract class AlgorithmConfig {
  const AlgorithmConfig();

  /// Validates the configuration values.
  ///
  /// Throws [InvalidConfigurationException] if any value is unsafe.
  void validate();
}

/// Configuration for Argon2id hashing.
///
/// OWASP recommended defaults (2024):
/// - memory: 64 MB (65536 KB)
/// - iterations: 3
/// - parallelism: 4
/// - hashLength: 32 bytes
///
/// Example:
/// ```dart
/// const config = Argon2Config(
///   memory: 65536,
///   iterations: 3,
///   parallelism: 4,
/// );
/// await PasswordGuard.hash(password: 'pass', config: config);
/// ```
class Argon2Config extends AlgorithmConfig {
  /// Memory cost in KB. Minimum 64 MB (65536 KB) recommended.
  final int memory;

  /// Number of iterations (time cost). Minimum 3 recommended.
  final int iterations;

  /// Degree of parallelism (threads). Minimum 1.
  final int parallelism;

  /// Output hash length in bytes. Minimum 16, recommended 32.
  final int hashLength;

  const Argon2Config({
    this.memory = 65536,
    this.iterations = 3,
    this.parallelism = 4,
    this.hashLength = 32,
  });

  @override
  void validate() {
    if (memory < 8192) {
      throw ArgumentError(
        'Argon2Config.memory must be at least 8192 KB (8 MB). '
        'OWASP recommends 65536 KB (64 MB). Got: $memory',
      );
    }
    if (iterations < 1) {
      throw ArgumentError(
        'Argon2Config.iterations must be at least 1. Got: $iterations',
      );
    }
    if (parallelism < 1) {
      throw ArgumentError(
        'Argon2Config.parallelism must be at least 1. Got: $parallelism',
      );
    }
    if (hashLength < 16) {
      throw ArgumentError(
        'Argon2Config.hashLength must be at least 16 bytes. Got: $hashLength',
      );
    }
  }

  @override
  String toString() =>
      'Argon2Config(memory: $memory, iterations: $iterations, '
      'parallelism: $parallelism, hashLength: $hashLength)';
}

/// Configuration for bcrypt hashing.
///
/// OWASP recommended defaults (2024):
/// - cost: 10 minimum, 12 recommended
///
/// Example:
/// ```dart
/// const config = BcryptConfig(cost: 12);
/// await PasswordGuard.hash(
///   password: 'pass',
///   algorithm: PasswordAlgorithm.bcrypt,
///   config: config,
/// );
/// ```
class BcryptConfig extends AlgorithmConfig {
  /// Work factor (cost). Each increment doubles the work.
  /// Minimum 10, recommended 12.
  final int cost;

  const BcryptConfig({this.cost = 12});

  @override
  void validate() {
    if (cost < 4) {
      throw ArgumentError(
        'BcryptConfig.cost must be at least 4. '
        'OWASP recommends 10-12. Got: $cost',
      );
    }
    if (cost > 31) {
      throw ArgumentError(
        'BcryptConfig.cost must be 31 or less. Got: $cost',
      );
    }
  }

  @override
  String toString() => 'BcryptConfig(cost: $cost)';
}

/// Configuration for PBKDF2-HMAC-SHA256 hashing.
///
/// OWASP recommended defaults (2024):
/// - iterations: 600,000 minimum
/// - keyLength: 32 bytes
///
/// Example:
/// ```dart
/// const config = PBKDF2Config(iterations: 600000);
/// await PasswordGuard.hash(
///   password: 'pass',
///   algorithm: PasswordAlgorithm.pbkdf2,
///   config: config,
/// );
/// ```
class PBKDF2Config extends AlgorithmConfig {
  /// Number of iterations. OWASP recommends 600,000 minimum.
  final int iterations;

  /// Output key length in bytes. Recommended 32.
  final int keyLength;

  const PBKDF2Config({
    this.iterations = 600000,
    this.keyLength = 32,
  });

  @override
  void validate() {
    if (iterations < 100000) {
      throw ArgumentError(
        'PBKDF2Config.iterations must be at least 100,000. '
        'OWASP recommends 600,000. Got: $iterations',
      );
    }
    if (keyLength < 16) {
      throw ArgumentError(
        'PBKDF2Config.keyLength must be at least 16 bytes. Got: $keyLength',
      );
    }
  }

  @override
  String toString() =>
      'PBKDF2Config(iterations: $iterations, keyLength: $keyLength)';
}
