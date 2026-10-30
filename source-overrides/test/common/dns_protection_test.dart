import 'dart:convert';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yaml/yaml.dart';

const _protected = DnsProtectionProps(enabled: true, proxyTarget: 'HK-01');

void main() {
  test('old preferences migrate with protection disabled', () {
    final settings = AppSettingProps.fromJson({});
    expect(settings.dnsProtection.enabled, isFalse);
    expect(settings.dnsProtection.schemaVersion, 1);
    expect(DnsProtectionProps.fromJson(_protected.toJson()), _protected);
  });

  test('disabling protection leaves the profile byte-for-byte equivalent', () {
    final profile = <String, dynamic>{
      'dns': {
        'nameserver': ['system'],
      },
    };
    final before = json.encode(profile);
    applyDnsProtection(profile, const DnsProtectionProps());
    expect(json.encode(profile), before);
  });

  test('removes every inherited DNS bypass while preserving traffic rules', () {
    final profile = <String, dynamic>{
      'dns': {
        'nameserver': ['system'],
        'fallback': ['8.8.8.8'],
        'nameserver-policy': {'+.example.com': 'dhcp://Ethernet'},
        'proxy-server-nameserver-policy': {'+.example.com': 'system'},
        'direct-nameserver-follow-policy': true,
        'fallback-filter': {'geoip': true},
        'enhanced-mode': 'fake-ip',
      },
      'rules': ['MATCH,HK-01'],
      'proxies': [
        {'name': 'HK-01', 'type': 'socks5'},
      ],
      'external-controller': ':9090',
      'tun': {'mtu': 1400, 'enable': false},
      'ipv6': true,
    };
    applyDnsProtection(profile, _protected);
    final dns = profile['dns'] as Map;
    expect(dns['nameserver'], [
      'https://1.1.1.1/dns-query#HK-01&ecs=0.0.0.0/0&ecs-override=true',
    ]);
    expect(dns['direct-nameserver'], dns['nameserver']);
    expect(dns['proxy-server-nameserver'], [
      'https://1.1.1.1/dns-query#DIRECT&ecs=0.0.0.0/0&ecs-override=true',
    ]);
    expect(dns['default-nameserver'], dns['proxy-server-nameserver']);
    expect(dns['fallback'], isEmpty);
    expect(dns['nameserver-policy'], isEmpty);
    expect(dns['proxy-server-nameserver-policy'], isEmpty);
    expect(dns.containsKey('fallback-filter'), isFalse);
    expect(dns['enhanced-mode'], 'fake-ip');
    expect(profile['rules'], ['MATCH,HK-01']);
    expect(profile['external-controller'], '');
    expect(profile['ipv6'], isFalse);
    expect(profile['tun'], containsPair('mtu', 1400));
    expect((profile['tun'] as Map)['dns-hijack'], ['any:53', 'tcp://any:53']);
  });

  for (final address in [
    'system',
    'dhcp://Ethernet',
    'udp://8.8.8.8',
    'http://1.1.1.1/dns-query',
    'https://a/dns-query#DIRECT',
    'https://a/dns-query?skip-cert-verify=true',
    'https://user:password@a/dns-query',
  ]) {
    test('rejects unsafe resolver $address', () {
      expect(
        () => validateDnsProtection(_protected.copyWith(upstreams: [address])),
        throwsFormatException,
      );
    });
  }

  for (final target in [
    '',
    'DIRECT',
    'GLOBAL',
    'node&skip-cert-verify=true',
    'node#DIRECT',
  ]) {
    test('rejects bypass target $target', () {
      expect(
        () => validateDnsProtection(_protected.copyWith(proxyTarget: target)),
        throwsFormatException,
      );
    });
  }

  test('bootstrap cannot depend on system resolution or IPv6', () {
    for (final address in [
      'https://dns.example/dns-query',
      'tls://1.1.1.1',
      'https://[2606:4700:4700::1111]/dns-query',
    ]) {
      expect(
        () => validateDnsProtection(
          _protected.copyWith(bootstrapServers: [address]),
        ),
        throwsFormatException,
      );
    }
  });

  test(
    'profile pipeline applies policy last and leaves the source untouched',
    () async {
      final raw = <String, dynamic>{
        'dns': {
          'enable': true,
          'nameserver': ['system'],
        },
        'rules': ['MATCH,DIRECT'],
      };
      final before = json.encode(raw);
      final result = await makeRealProfileTask(
        MakeRealProfileState(
          profilesPath: '/profiles',
          profileId: 1,
          rawConfig: raw,
          realPatchConfig: const PatchClashConfig(),
          proxyGroups: const [],
          rules: const [],
          addedRules: const [],
          defaultUA: 'FlClash-Test',
          appendSystemDns: false,
          dnsProtection: _protected,
        ),
      );
      final config = loadYaml(result.yaml) as YamlMap;
      expect(
        (config['dns'] as Map)['nameserver'],
        everyElement(contains('#HK-01&')),
      );
      expect((config['tun'] as Map)['enable'], isTrue);
      expect(json.encode(raw), before);
    },
  );

  test('safe mode never installs the protected TUN policy', () async {
    final result = await makeRealProfileTask(
      const MakeRealProfileState(
        profilesPath: '/profiles',
        profileId: 1,
        rawConfig: {},
        realPatchConfig: PatchClashConfig(),
        proxyGroups: [],
        rules: [],
        addedRules: [],
        defaultUA: 'FlClash-Test',
        appendSystemDns: false,
        dnsProtection: _protected,
        safeMode: true,
      ),
    );
    final config = loadYaml(result.yaml) as YamlMap;
    expect((config['tun'] as Map)['enable'], isFalse);
    expect(config['external-controller'], '');
  });
}
