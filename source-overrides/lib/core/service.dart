import 'dart:async';

import 'package:fl_clash/common/constant.dart';
import 'package:fl_clash/common/function.dart';
import 'package:fl_clash/common/system.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/core.dart';
import 'package:flutter/foundation.dart';

import 'desktop/helper_client.dart';
import 'desktop/launcher.dart';
import 'desktop/lifecycle.dart';
import 'desktop/model.dart';
import 'desktop/rpc_client.dart';
import 'desktop/transport.dart';
import 'event.dart';
import 'interface.dart';
import 'method.dart';

class CoreService extends CoreHandlerInterface {
  static CoreService? _instance;

  final DesktopCoreLifecycleController _lifecycle;
  final CoreRpcChannel _rpcClient;
  late final StreamSubscription<DesktopCoreFailure> _crashSubscription;
  Future<CoreLifecycleResult>? _closeOperation;
  final _DnsLaunchPolicy _dnsPolicy;
  String? _guardSession;
  final _guardScheduler = SerialTaskScheduler();
  final HelperClient _helperClient;

  String? get _guardQuerySession =>
      _guardSession ??
      switch (_lifecycle.state) {
        DesktopCoreRunning(:final session)
            when session.owner == CoreProcessOwner.helper =>
          session.sessionId,
        _ => null,
      };

  factory CoreService() {
    return _instance ??= CoreService._create();
  }

  @visibleForTesting
  static void resetInstance() {
    _instance = null;
  }

  factory CoreService._create() {
    final address = system.isWindows ? windowsPipeName : unixSocketPath;
    final directLauncher = DirectCoreLauncher();
    final dnsPolicy = _DnsLaunchPolicy();

    final lifecycle = DesktopCoreLifecycle(
      transportFactory: () => IpcCoreTransport(address: address),
      launcherResolver: HelperLauncherResolver(
        hasHelper: system.hasHelperService && !safeModeBuild,
        directLauncher: directLauncher,
        helperLauncher: HelperLauncher(helperClient),
        helperReady: () => helperClient.readiness(),
        requireHelper: () => dnsPolicy.required,
      ),
      verifyPeerPid: system.isWindows,
    );
    return CoreService._(
      lifecycle: lifecycle,
      rpcClient: CoreRpcClient(lifecycle.transport),
      dnsPolicy: dnsPolicy,
    );
  }

  @visibleForTesting
  CoreService.forTesting({
    required DesktopCoreLifecycleController lifecycle,
    required CoreRpcChannel rpcClient,
    HelperClient? helper,
  }) : this._(lifecycle: lifecycle, rpcClient: rpcClient, helper: helper);

  CoreService._({
    required DesktopCoreLifecycleController lifecycle,
    required CoreRpcChannel rpcClient,
    _DnsLaunchPolicy? dnsPolicy,
    HelperClient? helper,
  }) : _lifecycle = lifecycle,
       _dnsPolicy = dnsPolicy ?? _DnsLaunchPolicy(),
       _helperClient = helper ?? helperClient,
       _rpcClient = rpcClient {
    _crashSubscription = _lifecycle.crashEvents.listen((failure) {
      coreEventManager.sendEvent(
        CoreEvent(
          type: CoreEventType.crash,
          data: failure.cause?.toString() ?? 'core done',
        ),
      );
    });
  }

  @override
  Future<CoreLifecycleResult> start() => _lifecycle.start();

  @override
  Future<CoreLifecycleResult> restart() => _lifecycle.restart();

  @override
  Future<CoreLifecycleResult> stop() => _lifecycle.stop();

  @override
  Future<CoreLifecycleResult> close() {
    return _closeOperation ??= _close();
  }

  Future<CoreLifecycleResult> _close() async {
    try {
      final result = await _lifecycle.close();
      await releaseDnsProtection();
      return result;
    } finally {
      await _rpcClient.close();
      await _crashSubscription.cancel();
    }
  }

  @override
  void requireDnsProtection(bool required) {
    _dnsPolicy.required = required && !safeModeBuild;
  }

  @override
  bool get hasProtectedHelper => switch (_lifecycle.state) {
    DesktopCoreRunning(:final session) =>
      session.owner == CoreProcessOwner.helper,
    _ => false,
  };

  @override
  Future<void> prepareDnsProtection(bool enabled) =>
      _guardScheduler.run(() async {
        if (!enabled) return;
        if (safeModeBuild || !hasProtectedHelper) {
          throw StateError('DP_GUARD_FAILED: protected Helper required');
        }
        final session = (_lifecycle.state as DesktopCoreRunning).session;
        _guardSession = session.sessionId;
        final status = await _helperClient.dnsProtection(
          session.sessionId,
          enabled: true,
        );
        if (status['armed'] != true) throw StateError('DP_GUARD_FAILED');
      });

  @override
  Future<void> releaseDnsProtection() => _guardScheduler.run(() async {
    final session = _guardQuerySession;
    if (session == null) return;
    final status = await _helperClient.dnsProtection(session);
    if (status['armed'] == true) {
      final owner = status['sessionId'];
      if (owner is! String) throw StateError('DP_GUARD_FAILED: missing owner');
      await _helperClient.dnsProtection(owner, enabled: false);
    }
    if (_guardSession == session) _guardSession = null;
  });

  @override
  Future<Map<String, dynamic>> dnsProtectionGuardStatus() async {
    final session = _guardQuerySession;
    if (session == null) return {'armed': false, 'bound': false};
    return _helperClient.dnsProtection(session);
  }

  @override
  Future<T?> invokeMethod<T>({
    required CoreMethod method,
    Object? arguments,
    Duration? timeout,
  }) {
    return _rpcClient.invoke<T>(
      method: method,
      arguments: arguments,
      timeout: timeout,
    );
  }
}

class _DnsLaunchPolicy {
  bool required = false;
}

final coreService = system.isDesktop ? CoreService() : null;
