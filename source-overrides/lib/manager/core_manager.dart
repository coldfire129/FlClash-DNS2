import 'dart:async';
import 'dart:convert';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/common/dns_protection_probe.dart';
import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/action.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/core.dart';
import 'package:fl_clash/providers/database.dart';
import 'package:fl_clash/providers/route_state.dart';
import 'package:fl_clash/providers/state.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class CoreManager extends ConsumerStatefulWidget {
  final Widget child;

  const CoreManager({super.key, required this.child});

  @override
  ConsumerState<CoreManager> createState() => _CoreContainerState();
}

class _CoreContainerState extends ConsumerState<CoreManager>
    with CoreEventListener {
  CoreController get _core => ref.read(coreHandlerProvider);
  Timer? _dnsWatch;
  bool _dnsWatchBusy = false;
  String? _dnsHealthRevision;
  Stopwatch? _dnsHealthAge;
  bool _dnsHealthReady = false;

  @override
  Widget build(BuildContext context) {
    return widget.child;
  }

  @override
  void initState() {
    super.initState();
    coreEventManager.addListener(this);
    _syncDnsWatch();
    ref.listenManual(
      appSettingProvider.select((state) => state.dnsProtection),
      (previous, next) {
        if (previous != next) {
          ref.read(dnsProtectionReadyProvider.notifier).value = false;
          _syncDnsWatch();
        }
      },
    );
    ref.read(updatingActionProvider.notifier);
    // A rejected profile stays selected on purpose: silently reverting to
    // the previous one hides the error and looks like the switch was lost.
    ref.listenManual(currentProfileIdProvider, (prev, next) {
      if (prev == next) return;
      runAfterFrame(() {
        unawaited(ref.read(setupActionProvider.notifier).fullSetup());
      });
    });
    ref.listenManual(updateParamsProvider, (prev, next) {
      if (prev != next) {
        ref.read(setupActionProvider.notifier).updateConfigDebounce();
      }
    });
    ref.listenManual(setupPatchProvider, (prev, next) {
      if (prev != next) {
        ref
            .read(setupActionProvider.notifier)
            .applyProfileDebounce(
              silence: true,
              // The test URL changes no YAML, so only a forced apply hands
              // it over.
              force:
                  prev != null &&
                  prev.patchConfig.testUrl != next.patchConfig.testUrl,
            );
      }
    });
    ref.listenManual(globalRulesProvider, (prev, next) {
      if (prev?.value != null && next.hasValue) {
        ref.read(setupActionProvider.notifier).applyIfGlobalRulesUsed();
      }
    });
    ref.listenManual(appSettingProvider.select((state) => state.openLogs), (
      prev,
      next,
    ) {
      if (prev != next) {
        _syncLogStream();
      }
    });
    // Every Core process starts without a log stream.
    ref.listenManual(coreStatusProvider, (prev, next) {
      if (next != CoreStatus.connected) {
        unawaited(
          Future<void>.microtask(() {
            if (mounted &&
                ref.read(coreStatusProvider) != CoreStatus.connected) {
              ref.read(dnsProtectionReadyProvider.notifier).value = false;
              _dnsHealthRevision = null;
              _dnsHealthAge?.stop();
              _dnsHealthAge = null;
              _dnsHealthReady = false;
            }
          }),
        );
      }
      if (next == CoreStatus.connected && prev != CoreStatus.connected) {
        _syncLogStream();
      }
    }, fireImmediately: true);
  }

  void _syncLogStream() {
    if (ref.read(coreStatusProvider) != CoreStatus.connected) {
      return;
    }
    if (ref.read(appSettingProvider).openLogs) {
      _core.startLog();
    } else {
      _core.stopLog();
    }
  }

  void _syncDnsWatch() {
    _dnsWatch?.cancel();
    _dnsWatch = null;
    _dnsHealthRevision = null;
    _dnsHealthAge?.stop();
    _dnsHealthAge = null;
    _dnsHealthReady = false;
    if (system.isWindows &&
        !ref.read(safeModeProvider) &&
        ref.read(appSettingProvider).dnsProtection.enabled) {
      _dnsWatch = Timer.periodic(
        const Duration(seconds: 2),
        (_) => _checkDnsGuard(),
      );
    }
  }

  @override
  void dispose() {
    _dnsWatch?.cancel();
    _dnsHealthAge?.stop();
    coreEventManager.removeListener(this);
    super.dispose();
  }

  Future<void> _checkDnsGuard() async {
    if (_dnsWatchBusy || !system.isWindows || ref.read(safeModeProvider)) {
      return;
    }
    final settings = ref.read(appSettingProvider).dnsProtection;
    if (!settings.enabled || !ref.read(isStartProvider)) return;
    _dnsWatchBusy = true;
    var ready = false;
    try {
      final status = await _core.dnsProtectionStatus();
      final revision = json.encode(settings.toJson()).toMd5();
      if (dnsProtectionControlReady(status, revision)) {
        final sessionKey = '$revision:${dnsProtectionSessionKey(status)}';
        final lastCheck = _dnsHealthAge;
        if (_dnsHealthRevision != sessionKey ||
            lastCheck == null ||
            lastCheck.elapsed >= const Duration(seconds: 15)) {
          final probes = await runProtectedDnsProbes();
          final confirmed = await _core.dnsProtectionStatus();
          _dnsHealthReady =
              dnsProtectionProbesReady(probes) &&
              dnsProtectionControlReady(confirmed, revision) &&
              dnsProtectionSessionKey(status) ==
                  dnsProtectionSessionKey(confirmed);
          _dnsHealthRevision = sessionKey;
          _dnsHealthAge?.stop();
          _dnsHealthAge = Stopwatch()..start();
        }
        ready = _dnsHealthReady;
      } else {
        _dnsHealthReady = false;
        _dnsHealthAge?.stop();
        _dnsHealthAge = null;
      }
    } catch (_) {
      ready = false;
    } finally {
      _dnsWatchBusy = false;
    }
    if (mounted && ref.read(appSettingProvider).dnsProtection == settings) {
      ref.read(dnsProtectionReadyProvider.notifier).value =
          ready &&
          ref.read(coreStatusProvider) == CoreStatus.connected &&
          ref.read(isStartProvider) &&
          !ref.read(suspendProvider);
    }
  }

  @override
  Future<void> onDelay(Delay delay) async {
    super.onDelay(delay);
    final proxiesAction = ref.read(proxiesActionProvider.notifier);
    proxiesAction.setDelay(delay);
    debouncer.call(FunctionTag.updateDelay, () async {
      proxiesAction.updateGroupsDebounce();
    }, duration: const Duration(milliseconds: 5000));
  }

  @override
  void onLog(Log log) {
    ref.read(logsProvider.notifier).add(log);
    if (log.logLevel == LogLevel.error) {
      throttler.call(
        FunctionTag.coreErrorNotifier,
        () => dialogs.showNotifier(log.payload, level: MessageLevel.error),
        duration: const Duration(seconds: 3),
        fire: true,
      );
    }
    super.onLog(log);
  }

  @override
  void onDialerLoop(String proxyName) {
    throttler.call(
      FunctionTag.dialerLoopNotifier,
      () => dialogs.showNotifier(
        currentAppLocalizations.dialerProxyLoopStopped(proxyName),
        level: MessageLevel.error,
      ),
      duration: const Duration(seconds: 3),
      fire: true,
    );
    super.onDialerLoop(proxyName);
  }

  @override
  void onRequest(TrackerInfo trackerInfo) async {
    ref.read(requestsProvider.notifier).addRequest(trackerInfo);
    ref.read(requestCountProvider.notifier).update((count) => count + 1);
    super.onRequest(trackerInfo);
  }

  @override
  void onRequestTraffic(Map<String, RequestTraffic> traffic) {
    ref.read(requestsProvider.notifier).updateTraffic(traffic);
    super.onRequestTraffic(traffic);
  }

  @override
  void onDns(DnsQuery dnsQuery) {
    ref.read(dnsQueriesProvider.notifier).addQuery(dnsQuery);
    ref.read(dnsQueryCountProvider.notifier).update((count) => count + 1);
    super.onDns(dnsQuery);
  }

  @override
  Future<void> onLoaded(String providerName) async {
    final provider = await _core.getExternalProvider(providerName);
    if (!mounted) {
      return;
    }
    ref.read(providersProvider.notifier).setProvider(provider);
    debouncer.call(FunctionTag.loadedProvider, () async {
      if (!mounted) {
        return;
      }
      ref.read(proxiesActionProvider.notifier).updateGroupsDebounce();
    }, duration: const Duration(milliseconds: 5000));
    super.onLoaded(providerName);
  }

  @override
  Future<void> onCrash(String message) async {
    if (ref.read(coreStatusProvider) != CoreStatus.connected) {
      return;
    }
    ref.read(coreStatusProvider.notifier).value = CoreStatus.disconnected;
    if (WidgetsBinding.instance.lifecycleState == AppLifecycleState.resumed) {
      context.showNotifier(message, level: MessageLevel.error);
    }
    super.onCrash(message);
  }

  @override
  void onGeoUpdate(String geoType, bool updating, bool skipped, String? error) {
    ref
        .read(geoResourceActionProvider.notifier)
        .handleCoreUpdate(geoType, updating, skipped, error);
    super.onGeoUpdate(geoType, updating, skipped, error);
  }

  @override
  void onRouteChanged(RouteSnapshot snapshot) {
    ref.read(routeTrackerProvider.notifier).applySnapshot(snapshot);
    super.onRouteChanged(snapshot);
  }
}
