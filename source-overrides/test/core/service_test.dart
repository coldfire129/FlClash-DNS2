import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:fl_clash/core/desktop/lifecycle.dart';
import 'package:fl_clash/core/desktop/helper_client.dart';
import 'package:fl_clash/core/desktop/model.dart';
import 'package:fl_clash/core/desktop/rpc_client.dart';
import 'package:fl_clash/core/event.dart';
import 'package:fl_clash/core/method.dart';
import 'package:fl_clash/core/service.dart';
import 'package:mocktail/mocktail.dart';
import 'package:flutter_test/flutter_test.dart';

final class _MockLifecycle extends Mock
    implements DesktopCoreLifecycleController {}

final class _MockRpcClient extends Mock implements CoreRpcChannel {}

final class _MockLease extends Mock implements CoreProcessLease {}

void main() {
  late _MockLifecycle lifecycle;
  late _MockRpcClient rpcClient;
  late StreamController<DesktopCoreFailure> crashes;
  late CoreService service;

  const result = CoreLifecycleResult(
    revision: 1,
    outcome: CoreLifecycleOutcome.applied,
  );

  setUp(() {
    lifecycle = _MockLifecycle();
    rpcClient = _MockRpcClient();
    crashes = StreamController<DesktopCoreFailure>.broadcast();
    when(() => lifecycle.crashEvents).thenAnswer((_) => crashes.stream);
    when(() => lifecycle.state).thenReturn(const DesktopCoreIdle());
    when(() => lifecycle.start()).thenAnswer((_) async => result);
    when(() => lifecycle.restart()).thenAnswer((_) async => result);
    when(() => lifecycle.stop()).thenAnswer((_) async => result);
    when(() => lifecycle.close()).thenAnswer((_) async => result);
    when(() => rpcClient.close()).thenAnswer((_) async {});
    service = CoreService.forTesting(
      lifecycle: lifecycle,
      rpcClient: rpcClient,
    );
  });

  tearDown(() async {
    await service.close();
    await crashes.close();
  });

  test(
    'delegates lifecycle commands without owning platform details',
    () async {
      expect(await service.start(), same(result));
      expect(await service.restart(), same(result));
      expect(await service.stop(), same(result));

      verify(() => lifecycle.start()).called(1);
      verify(() => lifecycle.restart()).called(1);
      verify(() => lifecycle.stop()).called(1);
    },
  );

  test('delegates Core method calls to the RPC channel', () async {
    when(
      () => rpcClient.invoke<bool>(
        method: CoreMethod.getIsInit,
        arguments: null,
        timeout: null,
      ),
    ).thenAnswer((_) async => true);

    expect(
      await service.invokeMethod<bool>(method: CoreMethod.getIsInit),
      isTrue,
    );
  });

  test('forwards lifecycle crash events once', () async {
    final listener = _CrashListener();
    coreEventManager.addListener(listener);

    crashes.add(
      const DesktopCoreFailure(
        code: 'unexpected_disconnect',
        phase: DesktopCorePhase.running,
        revision: 2,
      ),
    );
    await pumpEventQueue();

    expect(listener.messages, ['core done']);
    coreEventManager.removeListener(listener);
  });

  test('close coalesces lifecycle and RPC cleanup', () async {
    final first = service.close();
    final second = service.close();

    expect(await first, same(result));
    expect(await second, same(result));
    verify(() => lifecycle.close()).called(1);
    verify(() => rpcClient.close()).called(1);
  });

  test('recovery releases Guard after an outstanding arm request', () async {
    await service.close();
    final lease = _MockLease();
    const sessionId = '0123456789abcdef0123456789abcdef';
    when(() => lease.owner).thenReturn(CoreProcessOwner.helper);
    when(() => lifecycle.state).thenReturn(
      DesktopCoreRunning(
        DesktopCoreSession(
          sessionId: sessionId,
          lease: lease,
          connectionGeneration: 1,
        ),
      ),
    );
    final armed = Completer<Map<String, dynamic>>();
    final events = <String>[];
    final helper = _helper((request) async {
      expect(request.path, endsWith('/dns-protection'));
      final data = request.data as Map<String, dynamic>;
      expect(data['sessionId'], sessionId);
      if (data['enabled'] == true) {
        events.add('arm');
        return armed.future;
      }
      if (data['enabled'] == false) {
        events.add('release');
        return {'armed': false};
      }
      return {'armed': true, 'sessionId': sessionId};
    });
    service = CoreService.forTesting(
      lifecycle: lifecycle,
      rpcClient: rpcClient,
      helper: helper,
    );
    final arming = service.prepareDnsProtection(true);
    await pumpEventQueue();
    final releasing = service.releaseDnsProtection();
    await pumpEventQueue();
    expect(events, ['arm']);
    armed.complete({'armed': true});
    await Future.wait([arming, releasing]);
    expect(events, ['arm', 'release']);
  });

  test(
    'recovery can release an inherited Guard after the app restarts',
    () async {
      await service.close();
      final lease = _MockLease();
      const currentSession = '0123456789abcdef0123456789abcdef';
      const oldSession = 'abcdef0123456789abcdef0123456789';
      when(() => lease.owner).thenReturn(CoreProcessOwner.helper);
      when(() => lifecycle.state).thenReturn(
        DesktopCoreRunning(
          DesktopCoreSession(
            sessionId: currentSession,
            lease: lease,
            connectionGeneration: 2,
          ),
        ),
      );
      final releases = <String>[];
      final helper = _helper((request) async {
        final data = request.data as Map<String, dynamic>;
        if (data['enabled'] == false) {
          releases.add(data['sessionId'] as String);
          return {'armed': false};
        }
        expect(data['sessionId'], currentSession);
        return {
          'armed': releases.isEmpty,
          'bound': false,
          'sessionId': oldSession,
        };
      });
      service = CoreService.forTesting(
        lifecycle: lifecycle,
        rpcClient: rpcClient,
        helper: helper,
      );
      expect((await service.dnsProtectionGuardStatus())['armed'], isTrue);
      await service.releaseDnsProtection();
      expect(releases, [oldSession]);
    },
  );
}

HelperClient _helper(
  Future<Map<String, dynamic>> Function(RequestOptions request) response,
) {
  final dio = Dio()..httpClientAdapter = _HelperAdapter(response);
  return HelperClient(dio: dio, baseUrl: 'http://helper.invalid');
}

final class _HelperAdapter implements HttpClientAdapter {
  final Future<Map<String, dynamic>> Function(RequestOptions request) response;

  _HelperAdapter(this.response);

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async => ResponseBody.fromString(
    jsonEncode(await response(options)),
    200,
    headers: {
      Headers.contentTypeHeader: ['application/json'],
    },
  );

  @override
  void close({bool force = false}) {}
}

final class _CrashListener with CoreEventListener {
  final List<String> messages = [];

  @override
  void onCrash(String message) {
    messages.add(message);
  }
}
