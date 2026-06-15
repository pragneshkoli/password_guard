import 'package:password_guard/password_guard.dart';
import 'package:test/test.dart';

void main() {
  group('PasswordStrength.check', () {
    test('empty password is veryWeak with score 0', () {
      final result = PasswordStrength.check('');
      expect(result.score, 0);
      expect(result.level, StrengthLevel.veryWeak);
      expect(result.suggestions, isNotEmpty);
    });

    test('short simple password is veryWeak', () {
      final result = PasswordStrength.check('abc');
      expect(result.level, StrengthLevel.veryWeak);
    });

    test('common password gets penalized', () {
      final result = PasswordStrength.check('password');
      expect(result.score, lessThan(30));
      expect(result.suggestions.first, contains('commonly used'));
    });

    test('password with all character types scores well', () {
      final result = PasswordStrength.check('MyP@ssw0rd!2025');
      expect(result.score, greaterThanOrEqualTo(60));
    });

    test('very strong long password scores high', () {
      final result = PasswordStrength.check('C0rrect#Horse!Battery\$Staple99');
      expect(result.level, equals(StrengthLevel.veryStrong));
    });

    test('repeating characters are penalized', () {
      final regular = PasswordStrength.check('MyPass1!');
      final repeating = PasswordStrength.check('aaaaaaa1!');
      expect(repeating.score, lessThan(regular.score));
    });

    test('sequential characters suggestion shown', () {
      final result = PasswordStrength.check('abcd1234!');
      expect(result.suggestions.any((s) => s.contains('sequential')), isTrue);
    });

    test('missing uppercase triggers suggestion', () {
      final result = PasswordStrength.check('mypassword123!');
      expect(result.suggestions.any((s) => s.contains('uppercase')), isTrue);
    });

    test('missing special character triggers suggestion', () {
      final result = PasswordStrength.check('MyPassword123');
      expect(result.suggestions.any((s) => s.contains('special')), isTrue);
    });

    test('StrengthLevel.isAcceptable works correctly', () {
      expect(StrengthLevel.veryWeak.isAcceptable, isFalse);
      expect(StrengthLevel.weak.isAcceptable, isFalse);
      expect(StrengthLevel.medium.isAcceptable, isTrue);
      expect(StrengthLevel.strong.isAcceptable, isTrue);
      expect(StrengthLevel.veryStrong.isAcceptable, isTrue);
    });

    test('StrengthLevel labels are correct', () {
      expect(StrengthLevel.veryWeak.label, 'Very Weak');
      expect(StrengthLevel.weak.label, 'Weak');
      expect(StrengthLevel.medium.label, 'Medium');
      expect(StrengthLevel.strong.label, 'Strong');
      expect(StrengthLevel.veryStrong.label, 'Very Strong');
    });
  });

  group('PasswordPolicy.validate', () {
    test('accepts valid password meeting all rules', () {
      final policy = PasswordPolicy(
        requireUppercase: true,
        requireLowercase: true,
        requireNumber: true,
        requireSpecialCharacter: true,
      );
      final result = policy.validate('MyPass1!');
      expect(result.isValid, isTrue);
      expect(result.violations, isEmpty);
    });

    test('rejects password too short', () {
      final policy = PasswordPolicy(minLength: 12);
      final result = policy.validate('Short1!');
      expect(result.isValid, isFalse);
      expect(result.violations, hasLength(1));
      expect(result.violations.first, contains('12'));
    });

    test('rejects password too long when maxLength set', () {
      final policy = PasswordPolicy(maxLength: 10);
      final result = policy.validate('ALongerPassword1!');
      expect(result.isValid, isFalse);
      expect(result.violations.first, contains('10'));
    });

    test('rejects missing uppercase', () {
      final policy = PasswordPolicy(requireUppercase: true);
      final result = policy.validate('mypassword1!');
      expect(result.isValid, isFalse);
      expect(result.violations.first, contains('uppercase'));
    });

    test('rejects missing lowercase', () {
      final policy = PasswordPolicy(requireLowercase: true);
      final result = policy.validate('MYPASSWORD1!');
      expect(result.isValid, isFalse);
      expect(result.violations.first, contains('lowercase'));
    });

    test('rejects missing number', () {
      final policy = PasswordPolicy(requireNumber: true);
      final result = policy.validate('MyPassword!');
      expect(result.isValid, isFalse);
      expect(result.violations.first, contains('number'));
    });

    test('rejects missing special character', () {
      final policy = PasswordPolicy(requireSpecialCharacter: true);
      final result = policy.validate('MyPassword1');
      expect(result.isValid, isFalse);
      expect(result.violations.first, contains('special'));
    });

    test('returns all violations at once', () {
      final policy = PasswordPolicy(
        minLength: 20,
        requireUppercase: true,
        requireNumber: true,
        requireSpecialCharacter: true,
      );
      final result = policy.validate('abc');
      // Should report: too short, no uppercase, no number, no special
      expect(result.violations.length, greaterThanOrEqualTo(3));
    });

    test('rejects banned passwords', () {
      final policy = PasswordPolicy(
        bannedPasswords: ['CompanyName123!', 'Welcome1!'],
      );
      final result = policy.validate('CompanyName123!');
      expect(result.isValid, isFalse);
      expect(result.violations.first, contains('not allowed'));
    });

    test('banned passwords are case-insensitive', () {
      final policy = PasswordPolicy(bannedPasswords: ['mycompany']);
      expect(policy.validate('MyCompany').isValid, isFalse);
      expect(policy.validate('MYCOMPANY').isValid, isFalse);
    });

    test('validateOrThrow throws PasswordPolicyException', () {
      final policy = PasswordPolicy(minLength: 20);
      expect(
        () => policy.validateOrThrow('short'),
        throwsA(isA<PasswordPolicyException>()),
      );
    });

    test('validateOrThrow does not throw for valid password', () {
      final policy = PasswordPolicy(minLength: 4);
      expect(() => policy.validateOrThrow('ValidPass1!'), returnsNormally);
    });
  });

  group('PasswordStrength.checkAsync', () {
    test('returns normal strength check result when no callback provided',
        () async {
      final result = await PasswordStrength.checkAsync('MyPass1!');
      expect(result.score, greaterThan(40));
      expect(result.suggestions.any((s) => s.contains('breach')), isFalse);
    });

    test('penalizes score and adds suggestion when isBreached returns true',
        () async {
      final result = await PasswordStrength.checkAsync(
        'SomePassword',
        isBreached: (pwd) async {
          expect(pwd, 'SomePassword');
          return true;
        },
      );
      expect(result.score, lessThan(20)); // score is heavily penalized by 0.2
      expect(result.level, StrengthLevel.veryWeak);
      expect(result.suggestions.first, contains('data breach'));
    });

    test('does not penalize score when isBreached returns false', () async {
      final baseResult = PasswordStrength.check('StrongPass123!');
      final asyncResult = await PasswordStrength.checkAsync(
        'StrongPass123!',
        isBreached: (_) async => false,
      );
      expect(asyncResult.score, equals(baseResult.score));
      expect(asyncResult.suggestions, equals(baseResult.suggestions));
    });

    test('handles breached callback throwing gracefully (fails silently)',
        () async {
      final baseResult = PasswordStrength.check('StrongPass123!');
      final asyncResult = await PasswordStrength.checkAsync(
        'StrongPass123!',
        isBreached: (_) async => throw Exception('Network timeout'),
      );
      expect(asyncResult.score, equals(baseResult.score));
    });
  });
}
