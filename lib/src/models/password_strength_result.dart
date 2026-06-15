/// The strength level of a password.
enum StrengthLevel {
  /// Score 0–19. Extremely weak — common words, very short.
  veryWeak,

  /// Score 20–39. Weak — simple patterns, short length.
  weak,

  /// Score 40–59. Moderate — some complexity but improvable.
  medium,

  /// Score 60–79. Strong — good length and variety.
  strong,

  /// Score 80–100. Very strong — high entropy, long, diverse characters.
  veryStrong,
}

/// Extension to get display labels for [StrengthLevel].
extension StrengthLevelExtension on StrengthLevel {
  /// Human-readable label for display in UI.
  String get label {
    switch (this) {
      case StrengthLevel.veryWeak:
        return 'Very Weak';
      case StrengthLevel.weak:
        return 'Weak';
      case StrengthLevel.medium:
        return 'Medium';
      case StrengthLevel.strong:
        return 'Strong';
      case StrengthLevel.veryStrong:
        return 'Very Strong';
    }
  }

  /// Returns true if this level is considered acceptably secure.
  bool get isAcceptable =>
      this == StrengthLevel.medium ||
      this == StrengthLevel.strong ||
      this == StrengthLevel.veryStrong;
}

/// The result of a password strength check.
///
/// Example:
/// ```dart
/// final result = PasswordStrength.check('MyPassword123!');
/// print(result.score);       // 72
/// print(result.level.label); // 'Strong'
/// print(result.suggestions); // []
/// ```
class PasswordStrengthResult {
  /// Score from 0 (worst) to 100 (best).
  final int score;

  /// Categorized strength level.
  final StrengthLevel level;

  /// List of suggestions to improve the password.
  ///
  /// Empty if the password is already [StrengthLevel.veryStrong].
  final List<String> suggestions;

  const PasswordStrengthResult({
    required this.score,
    required this.level,
    required this.suggestions,
  });

  @override
  String toString() =>
      'PasswordStrengthResult(score: $score, level: ${level.label})';
}
