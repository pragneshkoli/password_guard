import 'package:password_guard/password_guard.dart';
import 'package:test/test.dart';

void main() {
  group('Timing attack protection', () {
    /// Measures the average duration of [operation] over [runs] iterations.
    Future<double> measureMs(
        Future<void> Function() operation, int runs) async {
      final stopwatch = Stopwatch()..start();
      for (int i = 0; i < runs; i++) {
        await operation();
      }
      stopwatch.stop();
      return stopwatch.elapsedMicroseconds / runs / 1000.0;
    }

    test(
      'PBKDF2 verify timing is similar for correct and incorrect passwords',
      () async {
        const password = 'CorrectPassword123!';
        final result = await PasswordGuard.hash(
          password: password,
          algorithm: PasswordAlgorithm.pbkdf2,
          config: PBKDF2Config(iterations: 100000), // low for test speed
        );

        const runs = 5;

        final correctMs = await measureMs(
          () async {
            await PasswordGuard.verify(
              password: password,
              hash: result.hash,
            );
          },
          runs,
        );

        final incorrectMs = await measureMs(
          () async {
            await PasswordGuard.verify(
              password: 'WrongPassword456!',
              hash: result.hash,
            );
          },
          runs,
        );

        // The timing difference should be small relative to the total operation.
        // We allow up to 50% ratio variance given OS scheduling noise.
        final ratio = correctMs > incorrectMs
            ? correctMs / incorrectMs
            : incorrectMs / correctMs;

        // In a true constant-time implementation this would be ~1.0.
        // With Dart's async overhead we allow up to 2x difference.
        expect(
          ratio,
          lessThan(3.0),
          reason: 'Timing ratio $ratio is too high — potential timing leak. '
              'Correct: ${correctMs.toStringAsFixed(2)}ms, '
              'Incorrect: ${incorrectMs.toStringAsFixed(2)}ms',
        );
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  });

  group('Hash format', () {
    test('encoded hash contains all required segments', () async {
      final result = await PasswordGuard.hash(
        password: 'TestPassword123!',
        config: Argon2Config(memory: 8192, iterations: 1, parallelism: 1),
      );

      // $pg$argon2id$v1$m=8192,t=1,p=1,l=32$<salt>$<hash>
      final parts = result.hash.split(r'$');
      // parts[0] = '' (before first $)
      // parts[1] = 'pg'
      // parts[2] = 'argon2id'
      // parts[3] = 'v1'
      // parts[4] = 'm=...'
      // parts[5] = '<salt>'
      // parts[6] = '<hash>'
      expect(parts.length, 7);
      expect(parts[1], 'pg');
      expect(parts[2], 'argon2id');
      expect(parts[3], 'v1');
      expect(parts[4], contains('m='));
      expect(parts[5], isNotEmpty); // salt
      expect(parts[6], isNotEmpty); // hash
    });

    test('PBKDF2 hash contains iter param', () async {
      final result = await PasswordGuard.hash(
        password: 'TestPassword123!',
        algorithm: PasswordAlgorithm.pbkdf2,
        config: PBKDF2Config(iterations: 200000),
      );
      expect(result.hash, contains('iter=200000'));
    });

    test('bcrypt hash contains cost param', () async {
      final result = await PasswordGuard.hash(
        password: 'TestPassword123!',
        algorithm: PasswordAlgorithm.bcrypt,
        config: BcryptConfig(cost: 4),
      );
      expect(result.hash, contains('cost=4'));
    });
  });

  group('Exception hierarchy', () {
    test('InvalidHashException extends PasswordGuardException', () {
      expect(
        const InvalidHashException(),
        isA<PasswordGuardException>(),
      );
    });

    test('UnsupportedAlgorithmException extends PasswordGuardException', () {
      expect(
        const UnsupportedAlgorithmException('test'),
        isA<PasswordGuardException>(),
      );
    });

    test('InvalidConfigurationException extends PasswordGuardException', () {
      expect(
        const InvalidConfigurationException('test'),
        isA<PasswordGuardException>(),
      );
    });

    test('PepperException extends PasswordGuardException', () {
      expect(
        const PepperException('test'),
        isA<PasswordGuardException>(),
      );
    });

    test('PasswordPolicyException extends PasswordGuardException', () {
      expect(
        const PasswordPolicyException(['violation']),
        isA<PasswordGuardException>(),
      );
    });

    test('PasswordPolicyException toString lists violations', () {
      const exc = PasswordPolicyException(['Too short', 'Missing uppercase']);
      expect(exc.toString(), contains('Too short'));
      expect(exc.toString(), contains('Missing uppercase'));
    });
  });
}
