import 'dart:convert';
import 'dart:typed_data';

import 'package:password_guard/src/generators/salt_generator.dart';
import 'package:password_guard/src/generators/secure_random.dart';
import 'package:test/test.dart';

void main() {
  group('SecureRandom.bytes', () {
    test('returns correct length', () {
      expect(SecureRandom.bytes(16).length, 16);
      expect(SecureRandom.bytes(32).length, 32);
      expect(SecureRandom.bytes(64).length, 64);
    });

    test('returns Uint8List', () {
      expect(SecureRandom.bytes(16), isA<Uint8List>());
    });

    test('each call returns different bytes', () {
      final a = SecureRandom.bytes(32);
      final b = SecureRandom.bytes(32);
      // Astronomically unlikely to be equal
      expect(a, isNot(equals(b)));
    });

    test('throws assertion for zero length', () {
      expect(() => SecureRandom.bytes(0), throwsA(isA<AssertionError>()));
    });
  });

  group('SecureRandom.base64', () {
    test('returns valid base64 string', () {
      final b64 = SecureRandom.base64(16);
      expect(() => base64Decode(b64), returnsNormally);
    });

    test('decoded length matches requested bytes', () {
      final b64 = SecureRandom.base64(32);
      expect(base64Decode(b64).length, 32);
    });

    test('each call returns unique string', () {
      final a = SecureRandom.base64(32);
      final b = SecureRandom.base64(32);
      expect(a, isNot(equals(b)));
    });
  });

  group('SecureRandom.hex', () {
    test('returns hex string of correct length (2x bytes)', () {
      expect(SecureRandom.hex(16).length, 32);
      expect(SecureRandom.hex(32).length, 64);
    });

    test('contains only hex characters', () {
      final hex = SecureRandom.hex(32);
      expect(RegExp(r'^[0-9a-f]+$').hasMatch(hex), isTrue);
    });

    test('each call returns unique string', () {
      final a = SecureRandom.hex(32);
      final b = SecureRandom.hex(32);
      expect(a, isNot(equals(b)));
    });
  });

  group('SaltGenerator', () {
    test('generate returns non-empty string', () {
      final salt = SaltGenerator.generate();
      expect(salt, isNotEmpty);
    });

    test('generated salt is valid base64', () {
      final salt = SaltGenerator.generate();
      expect(() => base64Decode(salt), returnsNormally);
    });

    test('generated salt is at least 16 bytes when decoded', () {
      final salt = SaltGenerator.generate();
      expect(base64Decode(salt).length, greaterThanOrEqualTo(16));
    });

    test('each generated salt is unique', () {
      final a = SaltGenerator.generate();
      final b = SaltGenerator.generate();
      expect(a, isNot(equals(b)));
    });

    test('throws ArgumentError when length below minimum', () {
      expect(
        () => SaltGenerator.generate(length: 8),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom length 32 bytes decodes correctly', () {
      final salt = SaltGenerator.generate(length: 32);
      expect(base64Decode(salt).length, 32);
    });
  });
}
