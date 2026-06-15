// Selects the correct isolate runner implementation based on platform capability.
export 'isolate_runner_stub.dart'
    if (dart.library.isolate) 'isolate_runner_vm.dart';
