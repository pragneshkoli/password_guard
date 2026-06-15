import 'package:password_guard/src/generators/secure_random.dart';

/// Generates secure random passwords.
///
/// Ensures that at least one character from each requested category
/// is guaranteed to be present, and randomizes character placement
/// using cryptographically secure random values.
///
/// Example:
/// ```dart
/// // Generate a standard 16-character password with all character sets enabled
/// final password = PasswordGenerator.generate();
///
/// // Generate a custom 20-character password without special characters
/// final custom = PasswordGenerator.generate(
///   length: 20,
///   includeSpecial: false,
/// );
/// ```
class PasswordGenerator {
  PasswordGenerator._();

  /// Lowercase character set (a–z).
  static const String lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';

  /// Uppercase character set (A–Z).
  static const String uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

  /// Numeric character set (0–9).
  static const String digitChars = '0123456789';

  /// Default special character set.
  static const String defaultSpecialChars = '!@#\$%^&*()_+-=[]{}|;:,.<>?/';

  /// Generates a cryptographically secure random password.
  ///
  /// ## Parameters
  ///
  /// - [length]: Total length of the password. Default is 16.
  /// - [includeLowercase]: Include lowercase letters. Default is true.
  /// - [includeUppercase]: Include uppercase letters. Default is true.
  /// - [includeDigits]: Include numbers. Default is true.
  /// - [includeSpecial]: Include special characters. Default is true.
  /// - [specialChars]: List of allowed special characters.
  ///
  /// Throws [ArgumentError] if no character set is selected or if the requested
  /// [length] is less than the number of required character sets.
  static String generate({
    int length = 16,
    bool includeLowercase = true,
    bool includeUppercase = true,
    bool includeDigits = true,
    bool includeSpecial = true,
    String specialChars = defaultSpecialChars,
  }) {
    int requiredGroups = 0;
    if (includeLowercase) requiredGroups++;
    if (includeUppercase) requiredGroups++;
    if (includeDigits) requiredGroups++;
    if (includeSpecial && specialChars.isNotEmpty) requiredGroups++;

    if (requiredGroups == 0) {
      throw ArgumentError('At least one character set must be enabled.');
    }

    if (length < requiredGroups) {
      throw ArgumentError(
        'Password length ($length) is too short to satisfy the required '
        'character groups. Minimum length is $requiredGroups.',
      );
    }

    final pool = StringBuffer();
    final guaranteed = <String>[];

    if (includeLowercase) {
      pool.write(lowercaseChars);
      guaranteed.add(lowercaseChars[SecureRandom.nextInt(lowercaseChars.length)]);
    }
    if (includeUppercase) {
      pool.write(uppercaseChars);
      guaranteed.add(uppercaseChars[SecureRandom.nextInt(uppercaseChars.length)]);
    }
    if (includeDigits) {
      pool.write(digitChars);
      guaranteed.add(digitChars[SecureRandom.nextInt(digitChars.length)]);
    }
    if (includeSpecial && specialChars.isNotEmpty) {
      pool.write(specialChars);
      guaranteed.add(specialChars[SecureRandom.nextInt(specialChars.length)]);
    }

    final fullPool = pool.toString();
    final remainingCount = length - guaranteed.length;
    final passwordChars = List<String>.from(guaranteed);

    for (int i = 0; i < remainingCount; i++) {
      passwordChars.add(fullPool[SecureRandom.nextInt(fullPool.length)]);
    }

    // Shuffle the character array using Fisher-Yates cryptographically secure shuffle
    for (int i = passwordChars.length - 1; i > 0; i--) {
      final j = SecureRandom.nextInt(i + 1);
      final temp = passwordChars[i];
      passwordChars[i] = passwordChars[j];
      passwordChars[j] = temp;
    }

    return passwordChars.join();
  }
}
