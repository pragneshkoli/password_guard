import 'package:password_guard/password_guard.dart';
import 'package:test/test.dart';

void main() {
  group('PasswordGenerator', () {
    test('generates default 16-character password', () {
      final password = PasswordGenerator.generate();
      expect(password.length, 16);
    });

    test('generates password with custom length', () {
      final password = PasswordGenerator.generate(length: 24);
      expect(password.length, 24);
    });

    test('throws ArgumentError if no character pool is selected', () {
      expect(
        () => PasswordGenerator.generate(
          includeLowercase: false,
          includeUppercase: false,
          includeDigits: false,
          includeSpecial: false,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws ArgumentError if length is less than enabled pools count', () {
      expect(
        () => PasswordGenerator.generate(
          length: 3,
          includeLowercase: true,
          includeUppercase: true,
          includeDigits: true,
          includeSpecial: true,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('guarantees character categories when requested', () {
      final password = PasswordGenerator.generate(
        length: 8,
        includeLowercase: true,
        includeUppercase: true,
        includeDigits: true,
        includeSpecial: true,
      );

      expect(password.length, 8);
      expect(RegExp('[a-z]').hasMatch(password), isTrue);
      expect(RegExp('[A-Z]').hasMatch(password), isTrue);
      expect(RegExp('[0-9]').hasMatch(password), isTrue);
      expect(RegExp('[^A-Za-z0-9]').hasMatch(password), isTrue);
    });

    test('respects character exclusions', () {
      final password = PasswordGenerator.generate(
        length: 20,
        includeLowercase: true,
        includeUppercase: false,
        includeDigits: false,
        includeSpecial: false,
      );

      expect(password.length, 20);
      expect(RegExp('^[a-z]+\$').hasMatch(password), isTrue);
    });

    test('uses custom special character set', () {
      final password = PasswordGenerator.generate(
        length: 10,
        includeLowercase: false,
        includeUppercase: false,
        includeDigits: false,
        includeSpecial: true,
        specialChars: '@',
      );

      expect(password, '@@@@@@@@@@');
    });
  });

  group('PassphraseGenerator', () {
    test('generates default passphrase with 4 words separated by dashes', () {
      final phrase = PassphraseGenerator.generate();
      final words = phrase.split('-');
      expect(words.length, 4);
      for (final word in words) {
        expect(PassphraseGenerator.defaultWordList.contains(word), isTrue);
      }
    });

    test('generates custom word count and separator', () {
      final phrase = PassphraseGenerator.generate(wordCount: 6, separator: '_');
      final words = phrase.split('_');
      expect(words.length, 6);
    });

    test('throws ArgumentError if wordCount is less than 2', () {
      expect(
        () => PassphraseGenerator.generate(wordCount: 1),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('uses custom word list', () {
      final customList = ['one', 'two', 'three'];
      final phrase = PassphraseGenerator.generate(
        wordCount: 3,
        customWordList: customList,
      );
      final words = phrase.split('-');
      expect(words.length, 3);
      for (final word in words) {
        expect(customList.contains(word), isTrue);
      }
    });

    test('throws ArgumentError if custom word list is empty', () {
      expect(
        () => PassphraseGenerator.generate(customWordList: []),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('calculates correct entropy in bits', () {
      // 4 words with 512 pool = 4 * 9 = 36 bits
      expect(PassphraseGenerator.calculateEntropy(wordCount: 4), closeTo(36.0, 0.001));
      // 5 words with 512 pool = 5 * 9 = 45 bits
      expect(PassphraseGenerator.calculateEntropy(wordCount: 5), closeTo(45.0, 0.001));

      // Custom pool of 4 elements (log2(4) = 2 bits per word)
      final customList = ['a', 'b', 'c', 'd'];
      expect(
        PassphraseGenerator.calculateEntropy(
          wordCount: 6,
          customWordList: customList,
        ),
        closeTo(12.0, 0.001),
      );
    });
  });
}
