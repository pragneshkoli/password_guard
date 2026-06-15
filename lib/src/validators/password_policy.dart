import 'package:password_guard/src/exceptions/exceptions.dart';

/// Result of a [PasswordPolicy.validate] call.
class PasswordValidationResult {
  /// Whether all policy rules passed.
  final bool isValid;

  /// List of violated rule messages. Empty when [isValid] is true.
  final List<String> violations;

  const PasswordValidationResult({
    required this.isValid,
    required this.violations,
  });

  @override
  String toString() => isValid
      ? 'PasswordValidationResult(valid)'
      : 'PasswordValidationResult(violations: $violations)';
}

/// Defines and enforces password rules.
///
/// Create a policy and call [validate] or [validateOrThrow] on any password.
///
/// ## Usage with state management
///
/// ```dart
/// // Define once (e.g., in a constants file or DI container)
/// final policy = PasswordPolicy(
///   minLength: 12,
///   requireUppercase: true,
///   requireLowercase: true,
///   requireNumber: true,
///   requireSpecialCharacter: true,
/// );
///
/// // BLoC
/// on<PasswordSubmitted>((event, emit) {
///   final result = policy.validate(event.password);
///   if (!result.isValid) emit(PasswordError(result.violations));
/// });
///
/// // Provider / Riverpod
/// final policyProvider = Provider((_) => PasswordPolicy(minLength: 10));
///
/// // GetX / MobX — just call policy.validate() in your controller
/// ```
class PasswordPolicy {
  /// Minimum number of characters required.
  final int minLength;

  /// Maximum number of characters allowed. Null means no limit.
  final int? maxLength;

  /// Whether at least one uppercase letter is required (A–Z).
  final bool requireUppercase;

  /// Whether at least one lowercase letter is required (a–z).
  final bool requireLowercase;

  /// Whether at least one digit is required (0–9).
  final bool requireNumber;

  /// Whether at least one special character is required.
  final bool requireSpecialCharacter;

  /// Optional list of exact passwords to disallow (e.g., company name).
  final List<String> bannedPasswords;

  const PasswordPolicy({
    this.minLength = 6,
    this.maxLength,
    this.requireUppercase = false,
    this.requireLowercase = false,
    this.requireNumber = false,
    this.requireSpecialCharacter = false,
    this.bannedPasswords = const [],
  }) : assert(minLength > 0, 'minLength must be at least 1');

  /// Validates [password] against all policy rules.
  ///
  /// Returns a [PasswordValidationResult] with all violations.
  /// Does NOT throw — use [validateOrThrow] if you prefer exceptions.
  PasswordValidationResult validate(String password) {
    final violations = <String>[];

    final lowerPassword = password.toLowerCase();
    for (final banned in bannedPasswords) {
      if (lowerPassword == banned.toLowerCase()) {
        violations.add('This password is not allowed.');
        break;
      }
    }

    if (password.length < minLength) {
      violations.add(
        'Password must be at least $minLength characters long '
        '(got ${password.length}).',
      );
    }

    if (maxLength != null && password.length > maxLength!) {
      violations.add(
        'Password must not exceed $maxLength characters '
        '(got ${password.length}).',
      );
    }

    if (requireUppercase && !RegExp('[A-Z]').hasMatch(password)) {
      violations
          .add('Password must contain at least one uppercase letter (A–Z).');
    }

    if (requireLowercase && !RegExp('[a-z]').hasMatch(password)) {
      violations
          .add('Password must contain at least one lowercase letter (a–z).');
    }

    if (requireNumber && !RegExp('[0-9]').hasMatch(password)) {
      violations.add('Password must contain at least one number (0–9).');
    }

    if (requireSpecialCharacter && !RegExp('[^A-Za-z0-9]').hasMatch(password)) {
      violations.add(
        'Password must contain at least one special character '
        r'(e.g., !@#$%^&*).',
      );
    }

    return PasswordValidationResult(
      isValid: violations.isEmpty,
      violations: violations,
    );
  }

  /// Validates [password] and throws [PasswordPolicyException] if invalid.
  ///
  /// Use this in server-side code where you want an exception on failure:
  /// ```dart
  /// policy.validateOrThrow(password); // throws if invalid
  /// ```
  void validateOrThrow(String password) {
    final result = validate(password);
    if (!result.isValid) {
      throw PasswordPolicyException(result.violations);
    }
  }

  @override
  String toString() => 'PasswordPolicy('
      'minLength: $minLength, '
      'maxLength: $maxLength, '
      'requireUppercase: $requireUppercase, '
      'requireLowercase: $requireLowercase, '
      'requireNumber: $requireNumber, '
      'requireSpecialCharacter: $requireSpecialCharacter'
      ')';
}
