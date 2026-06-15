import 'dart:async';

/// Stub implementation that runs the computation on the main thread.
Future<R> runInIsolate<R>(FutureOr<R> Function() computation) async {
  return computation();
}
