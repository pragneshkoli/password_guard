// ignore: avoid_classes_with_only_static_members
import 'dart:io' show Platform;

import 'package:password_guard/src/exceptions/exceptions.dart';
import 'package:password_guard/src/pepper/pepper_provider.dart';

/// Reads the pepper from an environment variable.
///
/// ⚠️ Requires `dart:io` — NOT available on Web.
/// For Web, use [MemoryPepperProvider] or a custom HTTP-based provider.
///
/// Example:
/// ```dart
/// // Set env var: PASSWORD_GUARD_PEPPER=your-secret-pepper
/// final provider = EnvPepperProvider();
/// final pepper = await provider.getPepper();
/// ```
///
/// Custom key:
/// ```dart
/// final provider = EnvPepperProvider(key: 'APP_SECRET_PEPPER');
/// ```
class EnvPepperProvider implements PepperProvider {
  /// The environment variable name to read from.
  final String key;

  const EnvPepperProvider({this.key = 'PASSWORD_GUARD_PEPPER'});

  @override
  Future<String> getPepper() async {
    final pepper = Platform.environment[key];
    if (pepper == null || pepper.isEmpty) {
      throw PepperException(
        'Environment variable "$key" is not set or is empty. '
        'Set this variable with your secret pepper value.',
      );
    }
    return pepper;
  }
}
