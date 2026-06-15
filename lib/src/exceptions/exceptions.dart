/// Exception hierarchy for password_guard.
///
/// All exceptions extend [PasswordGuardException] so callers
/// can catch the base type or be specific.
library;

/// Base exception for all password_guard errors.
class PasswordGuardException implements Exception {
  /// A human-readable message describing what went wrong.
  final String message;

  /// Optional underlying cause.
  final Object? cause;

  const PasswordGuardException(this.message, {this.cause});

  @override
  String toString() => 'PasswordGuardException: $message'
      '${cause != null ? '\nCaused by: $cause' : ''}';
}

/// Thrown when a hash string cannot be parsed or is malformed.
///
/// Example:
/// ```dart
/// try {
///   await PasswordGuard.verify(password: 'pass', hash: 'invalid');
/// } on InvalidHashException catch (e) {
///   print(e.message);
/// }
/// ```
class InvalidHashException extends PasswordGuardException {
  const InvalidHashException([
    super.message = 'Hash format is unrecognized or corrupted.',
  ]);

  /// Creates an [InvalidHashException] with a [cause].
  const InvalidHashException.withCause(super.message,
      {required Object super.cause});

  @override
  String toString() => 'InvalidHashException: $message'
      '${cause != null ? '\nCaused by: $cause' : ''}';
}

/// Thrown when an algorithm is not supported on the current platform.
///
/// For example, bcrypt is not available in a browser environment.
class UnsupportedAlgorithmException extends PasswordGuardException {
  /// The algorithm that is not supported.
  final String algorithm;

  const UnsupportedAlgorithmException(
    this.algorithm, [
    String message = '',
  ]) : super(
          message,
        );

  @override
  String toString() {
    final msg = message.isNotEmpty
        ? message
        : 'Algorithm "$algorithm" is not supported on this platform.';
    return 'UnsupportedAlgorithmException: $msg';
  }
}

/// Thrown when algorithm configuration values are invalid or unsafe.
class InvalidConfigurationException extends PasswordGuardException {
  const InvalidConfigurationException(
    super.message, {
    super.cause,
  });

  @override
  String toString() => 'InvalidConfigurationException: $message'
      '${cause != null ? '\nCaused by: $cause' : ''}';
}

/// Thrown when pepper retrieval fails.
class PepperException extends PasswordGuardException {
  const PepperException(
    super.message, {
    super.cause,
  });

  @override
  String toString() => 'PepperException: $message'
      '${cause != null ? '\nCaused by: $cause' : ''}';
}

/// Thrown when a password policy validation fails.
///
/// Example:
/// ```dart
/// try {
///   policy.validateOrThrow('weak');
/// } on PasswordPolicyException catch (e) {
///   print(e.violations); // ['Too short', 'Missing uppercase']
/// }
/// ```
class PasswordPolicyException extends PasswordGuardException {
  /// List of rule violations.
  final List<String> violations;

  const PasswordPolicyException(this.violations)
      : super('Password does not meet policy requirements.');

  @override
  String toString() => 'PasswordPolicyException: $message\nViolations:\n'
      '${violations.map((v) => '  - $v').join('\n')}';
}
