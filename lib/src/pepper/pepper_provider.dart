import 'package:password_guard/src/exceptions/exceptions.dart';

/// Abstract interface for providing pepper values.
///
/// A pepper is a secret value added to passwords before hashing.
/// Unlike salt, pepper is NOT stored in the database — it's kept
/// separately (environment variable, secrets manager, etc.).
///
/// Implement this to integrate with your secrets infrastructure:
/// ```dart
/// class MyVaultPepperProvider implements PepperProvider {
///   @override
///   Future<String> getPepper() async {
///     return await vaultClient.getSecret('password-pepper');
///   }
/// }
/// ```
abstract class PepperProvider {
  const PepperProvider();

  /// Returns the pepper value.
  ///
  /// Throws [PepperException] if the pepper cannot be retrieved.
  Future<String> getPepper();
}

/// Stores the pepper in memory.
///
/// Useful for testing and for environments where the pepper is
/// provided at app startup (e.g., loaded from a remote config,
/// passed via constructor injection, etc.).
///
/// ⚠️ In production servers, prefer [EnvPepperProvider] (dart:io only)
/// or a custom secrets-manager provider.
///
/// Example:
/// ```dart
/// final provider = MemoryPepperProvider('my-secret-pepper');
/// await PasswordGuard.hash(
///   password: 'myPassword',
///   pepperProvider: provider,
/// );
/// ```
class MemoryPepperProvider implements PepperProvider {
  final String _pepper;

  const MemoryPepperProvider(String pepper) : _pepper = pepper;

  @override
  Future<String> getPepper() async {
    if (_pepper.isEmpty) {
      throw const PepperException(
        'MemoryPepperProvider was initialized with an empty pepper string.',
      );
    }
    return _pepper;
  }
}
