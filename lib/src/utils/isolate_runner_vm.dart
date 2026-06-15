import 'dart:async';
import 'dart:isolate';

/// VM implementation that runs the computation in a background isolate.
Future<R> runInIsolate<R>(FutureOr<R> Function() computation) {
  return Isolate.run(computation);
}
