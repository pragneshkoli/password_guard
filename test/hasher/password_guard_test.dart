import 'package:password_guard/password_guard.dart';
import 'package:test/test.dart';

void main() {
  group('PasswordGuard.hash', () {
    test('returns a PasswordHashResult with non-empty hash', () async {
      final result = await PasswordGuard.hash(password: 'TestPassword123!');
      expect(result.hash, isNotEmpty);
      expect(result.salt, isNotEmpty);
      expect(result.algorithm, equals(PasswordAlgorithm.argon2id));
      expect(result.createdAt, isA<DateTime>());
    });

    test('default algorithm is argon2id', () async {
      final result = await PasswordGuard.hash(password: 'TestPassword123!');
      expect(result.algorithm, PasswordAlgorithm.argon2id);
      expect(result.hash, contains(r'$pg$argon2id$'));
    });

    test('hash starts with \$pg\$ prefix', () async {
      final result = await PasswordGuard.hash(password: 'TestPassword123!');
      expect(result.hash, startsWith(r'$pg$'));
    });

    test('each call produces a unique hash (unique salt)', () async {
      final result1 = await PasswordGuard.hash(password: 'SamePassword1!');
      final result2 = await PasswordGuard.hash(password: 'SamePassword1!');
      expect(result1.hash, isNot(equals(result2.hash)));
      expect(result1.salt, isNot(equals(result2.salt)));
    });

    test('throws InvalidConfigurationException for empty password', () async {
      expect(
        () => PasswordGuard.hash(password: ''),
        throwsA(isA<InvalidConfigurationException>()),
      );
    });

    test('throws when both pepper and pepperProvider provided', () async {
      expect(
        () => PasswordGuard.hash(
          password: 'test',
          pepper: 'raw-pepper',
          pepperProvider: MemoryPepperProvider('provider-pepper'),
        ),
        throwsA(isA<InvalidConfigurationException>()),
      );
    });

    test('uses pepper when provided', () async {
      const pepper = 'my-secret-pepper';
      final withPepper = await PasswordGuard.hash(
        password: 'TestPassword!',
        pepper: pepper,
      );
      final withoutPepper = await PasswordGuard.hash(
        password: 'TestPassword!',
      );
      // Different peppers → different hashes
      expect(withPepper.hash, isNot(equals(withoutPepper.hash)));
    });

    test('uses MemoryPepperProvider', () async {
      final provider = MemoryPepperProvider('my-pepper');
      final result = await PasswordGuard.hash(
        password: 'TestPassword!',
        pepperProvider: provider,
      );
      expect(result.hash, isNotEmpty);
    });

    test('hashes with bcrypt algorithm', () async {
      final result = await PasswordGuard.hash(
        password: 'TestPassword123!',
        algorithm: PasswordAlgorithm.bcrypt,
        config: BcryptConfig(cost: 4), // low cost for speed in tests
      );
      expect(result.algorithm, PasswordAlgorithm.bcrypt);
      expect(result.hash, contains(r'$pg$bcrypt$'));
    });

    test('hashes with pbkdf2 algorithm', () async {
      final result = await PasswordGuard.hash(
        password: 'TestPassword123!',
        algorithm: PasswordAlgorithm.pbkdf2,
        config: PBKDF2Config(iterations: 100000), // low for test speed
      );
      expect(result.algorithm, PasswordAlgorithm.pbkdf2);
      expect(result.hash, contains(r'$pg$pbkdf2$'));
    });

    test('custom Argon2Config is respected', () async {
      final config = Argon2Config(
        memory: 8192,
        iterations: 1,
        parallelism: 1,
      );
      final result = await PasswordGuard.hash(
        password: 'TestPassword123!',
        config: config,
      );
      expect(result.hash, contains('m=8192'));
    });

    test('custom salt length is used', () async {
      final result = await PasswordGuard.hash(
        password: 'TestPassword123!',
        saltLength: 32,
      );
      // salt should be longer base64 for 32 bytes
      expect(result.salt.length, greaterThan(20));
    });

    test('throws on salt length below minimum', () async {
      expect(
        () => PasswordGuard.hash(
          password: 'TestPassword123!',
          saltLength: 8,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('PasswordGuard.verify', () {
    test('returns true for correct password', () async {
      const password = 'CorrectHorseBatteryStaple!1';
      final result = await PasswordGuard.hash(
        password: password,
        config: Argon2Config(memory: 8192, iterations: 1, parallelism: 1),
      );
      final valid = await PasswordGuard.verify(
        password: password,
        hash: result.hash,
      );
      expect(valid, isTrue);
    });

    test('returns false for incorrect password', () async {
      final result = await PasswordGuard.hash(
        password: 'CorrectPassword1!',
        config: Argon2Config(memory: 8192, iterations: 1, parallelism: 1),
      );
      final valid = await PasswordGuard.verify(
        password: 'WrongPassword1!',
        hash: result.hash,
      );
      expect(valid, isFalse);
    });

    test('returns false for empty password', () async {
      final result = await PasswordGuard.hash(
        password: 'CorrectPassword1!',
        config: Argon2Config(memory: 8192, iterations: 1, parallelism: 1),
      );
      final valid = await PasswordGuard.verify(
        password: '',
        hash: result.hash,
      );
      expect(valid, isFalse);
    });

    test('throws InvalidHashException for malformed hash', () async {
      expect(
        () => PasswordGuard.verify(
          password: 'pass',
          hash: 'not-a-valid-hash',
        ),
        throwsA(isA<InvalidHashException>()),
      );
    });

    test('verifies with pepper correctly', () async {
      const pepper = 'secret-pepper-value';
      const password = 'MySecurePass1!';

      final result = await PasswordGuard.hash(
        password: password,
        pepper: pepper,
        config: Argon2Config(memory: 8192, iterations: 1, parallelism: 1),
      );

      // Correct pepper → true
      final valid = await PasswordGuard.verify(
        password: password,
        hash: result.hash,
        pepper: pepper,
      );
      expect(valid, isTrue);

      // Wrong pepper → false
      final invalid = await PasswordGuard.verify(
        password: password,
        hash: result.hash,
        pepper: 'wrong-pepper',
      );
      expect(invalid, isFalse);
    });

    test('verifies bcrypt hash', () async {
      const password = 'BcryptTestPass1!';
      final result = await PasswordGuard.hash(
        password: password,
        algorithm: PasswordAlgorithm.bcrypt,
        config: BcryptConfig(cost: 4),
      );
      final valid = await PasswordGuard.verify(
        password: password,
        hash: result.hash,
      );
      expect(valid, isTrue);
    });

    test('verifies pbkdf2 hash', () async {
      const password = 'PBKDF2TestPass1!';
      final result = await PasswordGuard.hash(
        password: password,
        algorithm: PasswordAlgorithm.pbkdf2,
        config: PBKDF2Config(iterations: 100000),
      );
      final valid = await PasswordGuard.verify(
        password: password,
        hash: result.hash,
      );
      expect(valid, isTrue);
    });
  });

  group('PasswordGuard.needsRehash', () {
    test('returns false for current argon2id with default config', () async {
      final result = await PasswordGuard.hash(
        password: 'Test1!',
        config: Argon2Config(memory: 8192, iterations: 1, parallelism: 1),
      );
      // With low config — should need rehash vs OWASP defaults
      expect(PasswordGuard.needsRehash(result.hash), isTrue);
    });

    test('returns false for hash meeting default config', () async {
      final result = await PasswordGuard.hash(
        password: 'Test1!',
        // OWASP defaults
      );
      expect(PasswordGuard.needsRehash(result.hash), isFalse);
    });

    test('returns true for non-pg-prefix hash (legacy)', () {
      // Simulated legacy bcrypt hash
      const legacyHash =
          r'$2b$12$somehashedvaluehere.andmorecharacters';
      expect(PasswordGuard.needsRehash(legacyHash), isTrue);
    });

    test('returns true for bcrypt hash when target is argon2id', () async {
      final result = await PasswordGuard.hash(
        password: 'Test1!',
        algorithm: PasswordAlgorithm.bcrypt,
        config: BcryptConfig(cost: 4),
      );
      expect(
        PasswordGuard.needsRehash(
          result.hash,
        ),
        isTrue,
      );
    });
  });
}
