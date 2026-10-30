import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

Future<List<Map<String, Object?>>> runProtectedDnsProbes() => Future.wait([
  for (final target in [
    (InternetAddress.loopbackIPv4, 1053),
    (InternetAddress('8.8.8.8'), 53),
  ])
    for (final tcp in [false, true])
      probeProtectedDns(server: target.$1, port: target.$2, tcp: tcp),
]);

bool dnsProtectionProbesReady(List<Map<String, Object?>> probes) {
  const expected = {
    'udp:127.0.0.1:1053',
    'tcp:127.0.0.1:1053',
    'udp:8.8.8.8:53',
    'tcp:8.8.8.8:53',
  };
  final received = <String>{};
  for (final probe in probes) {
    if (probe['result'] != 'success' ||
        !const [0, 3].contains(probe['rcode'])) {
      return false;
    }
    received.add('${probe['transport']}:${probe['target']}');
  }
  return probes.length == expected.length &&
      received.length == expected.length &&
      received.containsAll(expected);
}

Future<Map<String, Object?>> probeProtectedDns({
  required InternetAddress server,
  required int port,
  required bool tcp,
  Duration timeout = const Duration(seconds: 7),
}) async {
  final random = Random.secure();
  final id = random.nextInt(65536);
  final nonce = random.nextInt(0x7fffffff).toRadixString(16);
  final query = BytesBuilder()
    ..add([id >> 8, id & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
  for (final label in ['$nonce-dp', 'example', 'com']) {
    query
      ..addByte(label.length)
      ..add(label.codeUnits);
  }
  query.add([0, 0, 16, 0, 1]);
  final watch = Stopwatch()..start();
  try {
    final request = query.toBytes();
    final response = tcp
        ? await _tcpQuery(server, port, request, timeout)
        : await _udpQuery(server, port, request, timeout);
    final valid =
        response.length >= request.length &&
        response[0] == (id >> 8) &&
        response[1] == (id & 255) &&
        (response[2] & 248) == 128 &&
        (response[2] & 2) == 0 &&
        response[4] == 0 &&
        response[5] == 1 &&
        List.generate(
          request.length - 12,
          (index) => response[index + 12] == request[index + 12],
        ).every((matches) => matches);
    final rcode = valid ? response[3] & 15 : null;
    final healthy = valid && const [0, 3].contains(rcode);
    return {
      'transport': tcp ? 'tcp' : 'udp',
      'target': '${server.address}:$port',
      'result': healthy ? 'success' : 'failed',
      'rcode': rcode,
      if (!healthy) 'error_code': valid ? 'DP_DNS_RCODE' : 'DP_PROBE_INVALID',
      'duration_ms': watch.elapsedMilliseconds,
    };
  } catch (_) {
    return {
      'transport': tcp ? 'tcp' : 'udp',
      'target': '${server.address}:$port',
      'result': 'unknown',
      'error_code': 'DP_PROBE_UNKNOWN',
      'duration_ms': watch.elapsedMilliseconds,
    };
  }
}

Future<Uint8List> _udpQuery(
  InternetAddress server,
  int port,
  Uint8List query,
  Duration timeout,
) async {
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  final result = Completer<Uint8List>();
  final subscription = socket.listen(
    (event) {
      if (event != RawSocketEvent.read) return;
      final packet = socket.receive();
      if (packet != null &&
          packet.address == server &&
          packet.port == port &&
          !result.isCompleted) {
        result.complete(packet.data);
      }
    },
    onError: (Object error, StackTrace stack) {
      if (!result.isCompleted) result.completeError(error, stack);
    },
  );
  try {
    socket.send(query, server, port);
    return await result.future.timeout(timeout);
  } finally {
    await subscription.cancel();
    socket.close();
  }
}

Future<Uint8List> _tcpQuery(
  InternetAddress server,
  int port,
  Uint8List query,
  Duration timeout,
) async {
  final watch = Stopwatch()..start();
  final socket = await Socket.connect(server, port, timeout: timeout);
  final bytes = BytesBuilder();
  final result = Completer<Uint8List>();
  final subscription = socket.listen(
    (data) {
      bytes.add(data);
      final current = bytes.toBytes();
      if (current.length < 2) return;
      final length = (current[0] << 8) | current[1];
      if (current.length >= length + 2 && !result.isCompleted) {
        result.complete(Uint8List.sublistView(current, 2, length + 2));
      }
    },
    onDone: () {
      if (!result.isCompleted) {
        result.completeError(const SocketException('Incomplete DNS response'));
      }
    },
    onError: (Object error, StackTrace stack) {
      if (!result.isCompleted) result.completeError(error, stack);
    },
  );
  try {
    socket.add([query.length >> 8, query.length & 255, ...query]);
    final remaining = timeout - watch.elapsed;
    final responses = await Future.wait<Object?>([
      socket.flush().timeout(remaining),
      result.future.timeout(remaining),
    ], eagerError: true);
    return responses.last as Uint8List;
  } finally {
    await subscription.cancel();
    socket.destroy();
  }
}
