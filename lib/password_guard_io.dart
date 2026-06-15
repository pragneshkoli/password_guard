/// Platform-specific password_guard entry point for native platforms (VM / dart:io).
///
/// Contains [EnvPepperProvider] which depends on `dart:io` and is not compatible with Web.
library password_guard_io;

export 'password_guard.dart';
export 'src/pepper/env_pepper_provider.dart' show EnvPepperProvider;
