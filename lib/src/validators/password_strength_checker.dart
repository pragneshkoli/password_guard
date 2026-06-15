import 'dart:math';
import 'package:password_guard/src/models/password_strength_result.dart';

/// Checks password strength and returns a score with suggestions.
///
/// Works entirely in-memory, no network requests — safe to call
/// on every keystroke in a password field.
///
/// ## Compatibility
///
/// Works with any state management solution:
///
/// ```dart
/// // Provider / Riverpod
/// ref.watch(passwordProvider.select((p) => PasswordStrength.check(p)));
///
/// // BLoC
/// on<PasswordChanged>((event, emit) {
///   emit(state.copyWith(strength: PasswordStrength.check(event.password)));
/// });
///
/// // GetX
/// final strength = PasswordStrength.check(passwordController.text);
/// ```
class PasswordStrength {
  PasswordStrength._();

  /// Analyzes [password] asynchronously, allowing a custom breach checking
  /// callback (e.g. checking via HaveIBeenPwned API).
  ///
  /// If [isBreached] returns true, the score is significantly penalized and a
  /// suggestion to avoid using the breached password is added.
  static Future<PasswordStrengthResult> checkAsync(
    String password, {
    Future<bool> Function(String)? isBreached,
  }) async {
    final result = check(password);
    if (isBreached != null && password.isNotEmpty) {
      try {
        final breached = await isBreached(password);
        if (breached) {
          final score = (result.score * 0.2).round();
          final suggestions = List<String>.from(result.suggestions);
          suggestions.insert(
            0,
            'This password was found in a data breach and is unsafe to use.',
          );
          return PasswordStrengthResult(
            score: score,
            level: _scoreToLevel(score),
            suggestions: suggestions,
          );
        }
      } catch (_) {
        // Fail silently to prevent crashing client strength checks
      }
    }
    return result;
  }

  /// Analyzes [password] and returns a [PasswordStrengthResult].
  ///
  /// Score breakdown (0–100):
  /// - Length points: up to 30
  /// - Uppercase letters: up to 10
  /// - Lowercase letters: up to 10
  /// - Digits: up to 10
  /// - Special characters: up to 15
  /// - Entropy bonus: up to 25
  static PasswordStrengthResult check(String password) {
    if (password.isEmpty) {
      return const PasswordStrengthResult(
        score: 0,
        level: StrengthLevel.veryWeak,
        suggestions: ['Password cannot be empty.'],
      );
    }

    int score = 0;
    final suggestions = <String>[];

    // ── Length ──────────────────────────────────────────────
    final length = password.length;
    if (length < 6) {
      score += 0;
      suggestions.add('Use at least 6 characters.');
    } else if (length < 8) {
      score += 5;
      suggestions.add('Consider using 8 or more characters.');
    } else if (length < 12) {
      score += 15;
      suggestions.add('Consider using 12 or more characters.');
    } else if (length < 16) {
      score += 22;
    } else if (length < 20) {
      score += 27;
    } else {
      score += 30;
    }

    // ── Character variety ────────────────────────────────────
    final hasUppercase = RegExp('[A-Z]').hasMatch(password);
    final hasLowercase = RegExp('[a-z]').hasMatch(password);
    final hasDigits = RegExp('[0-9]').hasMatch(password);
    final hasSpecial = RegExp('[^A-Za-z0-9]').hasMatch(password);

    if (hasUppercase) {
      score += 10;
    } else {
      suggestions.add('Add uppercase letters (A–Z).');
    }

    if (hasLowercase) {
      score += 10;
    } else {
      suggestions.add('Add lowercase letters (a–z).');
    }

    if (hasDigits) {
      score += 10;
    } else {
      suggestions.add('Add numbers (0–9).');
    }

    if (hasSpecial) {
      score += 15;
    } else {
      suggestions.add('Add special characters (!@#\$%^&*).');
    }

    // ── Entropy bonus ────────────────────────────────────────
    // Estimate character set size
    int charsetSize = 0;
    if (hasLowercase) charsetSize += 26;
    if (hasUppercase) charsetSize += 26;
    if (hasDigits) charsetSize += 10;
    if (hasSpecial) charsetSize += 32;

    if (charsetSize > 0) {
      final entropy = length * (log(charsetSize) / ln2);
      if (entropy >= 100) {
        score += 25;
      } else if (entropy >= 70) {
        score += 18;
      } else if (entropy >= 45) {
        score += 10;
      } else {
        score += 3;
      }
    }

    // ── Common patterns penalty ──────────────────────────────
    if (_isCommonPassword(password)) {
      score = (score * 0.3).round();
      suggestions.insert(
          0, 'This is a commonly used password, please avoid it.');
    } else if (_hasRepeatingChars(password)) {
      score -= 10;
      suggestions.add('Avoid repeating characters (e.g., "aaaa").');
    } else if (_hasSequentialChars(password)) {
      score -= 5;
      suggestions.add('Avoid sequential patterns (e.g., "1234", "abcd").');
    }

    // Clamp score to [0, 100]
    score = score.clamp(0, 100);

    return PasswordStrengthResult(
      score: score,
      level: _scoreToLevel(score),
      suggestions: suggestions,
    );
  }

  static StrengthLevel _scoreToLevel(int score) {
    if (score < 20) return StrengthLevel.veryWeak;
    if (score < 40) return StrengthLevel.weak;
    if (score < 60) return StrengthLevel.medium;
    if (score < 80) return StrengthLevel.strong;
    return StrengthLevel.veryStrong;
  }

  static bool _isCommonPassword(String password) {
    const common = {
      'password',
      'password1',
      '123456',
      '12345678',
      'qwerty',
      'abc123',
      'monkey',
      '1234567',
      'letmein',
      'dragon',
      '111111',
      'baseball',
      'iloveyou',
      'master',
      'sunshine',
      'ashley',
      'bailey',
      'passw0rd',
      'shadow',
      '123123',
      '654321',
      'superman',
      'qazwsx',
      'michael',
      'football',
      '1234',
      '12345',
      '123456789',
      '1234567890',
      '123123123',
      '11111111',
      '22222222',
      '33333333',
      '44444444',
      '55555555',
      '66666666',
      '77777777',
      '88888888',
      '99999999',
      '00000000',
      'admin',
      'admin123',
      'root',
      'login',
      'security',
      'welcome',
      'welcome1',
      'guest',
      'hunter2',
      'charlie',
      'jessica',
      'andrew',
      'matthew',
      'daniel',
      'joseph',
      'mustang',
      'princess',
      'bubblegum',
      'secret',
      'snoopy',
      'killer',
      'phoenix',
      'morgan',
      'cookie',
      'cooper',
      'guitar',
      'soccer',
      'hockey',
      'joshua',
      'brandon',
      'nathan',
      'justin',
      'thomas',
      'robert',
      'william',
      'hunter',
      'brian',
      'kevin',
      'christopher',
      'david',
      'hannah',
      'sarah',
      'elizabeth',
      'lauren',
      'megan',
      'amanda',
      'rachel',
      'rebecca',
      'nicole',
      'emily',
      'taylor',
      'jessica1',
      'ashley1',
      'sarah1',
      'emily1',
      'charlie1',
      'david1',
      'daniel1',
      'james',
      'john',
      'mary',
      'patricia',
      'jennifer',
      'linda',
      'barbara'
    };
    return common.contains(password.toLowerCase());
  }

  static bool _hasRepeatingChars(String password) {
    // Detects 3+ identical consecutive chars
    return RegExp(r'(.)\1{2,}').hasMatch(password);
  }

  static bool _hasSequentialChars(String password) {
    const sequences = [
      '0123456789',
      'abcdefghijklmnopqrstuvwxyz',
      'qwertyuiop',
      'asdfghjkl',
      'zxcvbnm',
    ];
    final lower = password.toLowerCase();
    for (final seq in sequences) {
      for (int i = 0; i < seq.length - 3; i++) {
        if (lower.contains(seq.substring(i, i + 4))) return true;
      }
    }
    return false;
  }
}
