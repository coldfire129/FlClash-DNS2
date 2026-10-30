import 'dart:io';

import 'package:fl_clash/common/dns_protection_probe.dart';
import 'package:fl_clash/common/dns_protection.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('the reported bound Guard with four timeouts cannot be ready', () {
    final status = <String, dynamic>{
      'core': {'enabled': true, 'running': true, 'policyRevision': 'policy'},
      'guard': {'armed': true, 'bound': true, 'errorCode': null},
    };
    final probes = [
      for (final target in ['127.0.0.1:1053', '8.8.8.8:53'])
        for (final transport in ['udp', 'tcp'])
          <String, Object?>{
            'target': target,
            'transport': transport,
            'result': 'unknown',
            'error_code': 'DP_PROBE_UNKNOWN',
          },
    ];
    expect(dnsProtectionControlReady(status, 'policy'), isTrue);
    expect(dnsProtectionProbesReady(probes), isFalse);
  });

  test('all four distinct paths need a usable DNS response', () {
    final probes = [
      for (final target in ['127.0.0.1:1053', '8.8.8.8:53'])
        for (final transport in ['udp', 'tcp'])
          <String, Object?>{
            'target': target,
            'transport': transport,
            'result': 'success',
            'rcode': 3,
          },
    ];
    expect(dnsProtectionProbesReady(probes), isTrue);
    expect(dnsProtectionProbesReady(probes.take(3).toList()), isFalse);
    expect(
      dnsProtectionProbesReady([probes[0], probes[0], probes[0], probes[0]]),
      isFalse,
    );
    for (final rcode in [2, 5, null]) {
      expect(
        dnsProtectionProbesReady([
          ...probes.take(3),
          {...probes.last, 'rcode': rcode},
        ]),
        isFalse,
      );
    }
  });

  test(
    'a different Core process or TUN binding invalidates a health sample',
    () {
      Map<String, dynamic> status(int pid, int revision, String luid) => {
        'core': {'processId': pid, 'revision': revision},
        'guard': {'sessionId': 'session', 'interfaceLuid': luid},
      };
      final original = dnsProtectionSessionKey(status(1, 2, 'large-luid'));
      expect(
        original,
        isNot(dnsProtectionSessionKey(status(3, 2, 'large-luid'))),
      );
      expect(
        original,
        isNot(dnsProtectionSessionKey(status(1, 3, 'large-luid'))),
      );
      expect(
        original,
        isNot(dnsProtectionSessionKey(status(1, 2, 'new-luid'))),
      );
    },
  );

  test('SERVFAIL and REFUSED replies are failures, not healthy DNS', () async {
    for (final rcode in [2, 5]) {
      final socket = await RawDatagramSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      final listener = socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        final packet = socket.receive();
        if (packet == null) return;
        final response = packet.data;
        response[2] |= 128;
        response[3] = rcode;
        socket.send(response, packet.address, packet.port);
      });
      try {
        final result = await probeProtectedDns(
          server: InternetAddress.loopbackIPv4,
          port: socket.port,
          tcp: false,
        );
        expect(result['result'], 'failed');
        expect(result['rcode'], rcode);
        expect(result['error_code'], 'DP_DNS_RCODE');
      } finally {
        await listener.cancel();
        socket.close();
      }
    }
  });

  test('a correlated DNS response reports its rcode', () async {
    final socket = await RawDatagramSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    final listener = socket.listen((event) {
      if (event != RawSocketEvent.read) return;
      final packet = socket.receive();
      if (packet == null) return;
      final response = packet.data;
      response[2] |= 128;
      response[3] = 3;
      socket.send(response, packet.address, packet.port);
    });
    try {
      final result = await probeProtectedDns(
        server: InternetAddress.loopbackIPv4,
        port: socket.port,
        tcp: false,
      );
      expect(result['result'], 'success');
      expect(result['rcode'], 3);
    } finally {
      await listener.cancel();
      socket.close();
    }
  });

  test('a forged transaction id cannot count as a DNS response', () async {
    final socket = await RawDatagramSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    final listener = socket.listen((event) {
      if (event != RawSocketEvent.read) return;
      final packet = socket.receive();
      if (packet == null) return;
      final response = packet.data;
      response[0] ^= 255;
      response[2] |= 128;
      socket.send(response, packet.address, packet.port);
    });
    try {
      final result = await probeProtectedDns(
        server: InternetAddress.loopbackIPv4,
        port: socket.port,
        tcp: false,
      );
      expect(result['result'], 'failed');
      expect(result['rcode'], isNull);
    } finally {
      await listener.cancel();
      socket.close();
    }
  });

  test('silence is unknown and never a successful leak check', () async {
    final socket = await RawDatagramSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    try {
      final result = await probeProtectedDns(
        server: InternetAddress.loopbackIPv4,
        port: socket.port,
        tcp: false,
        timeout: const Duration(milliseconds: 150),
      );
      expect(result['result'], 'unknown');
      expect(result['error_code'], 'DP_PROBE_UNKNOWN');
    } finally {
      socket.close();
    }
  });

  test('TCP accepts a length framed response', () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final peers = <Socket>[];
    final listener = server.listen((peer) {
      peers.add(peer);
      peer.listen((request) {
        final response = request.toList();
        response[4] |= 128;
        response[5] = 0;
        peer.add(response);
      });
    });
    try {
      final result = await probeProtectedDns(
        server: InternetAddress.loopbackIPv4,
        port: server.port,
        tcp: true,
      );
      expect(result['result'], 'success');
      expect(result['transport'], 'tcp');
    } finally {
      for (final peer in peers) {
        peer.destroy();
      }
      await listener.cancel();
      await server.close();
    }
  });
}
