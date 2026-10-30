import 'dart:io';

import 'package:fl_clash/models/dns_protection.dart';

const dnsProtectionDevice = 'FlClashDNS';
const dnsProtectionListen = '127.0.0.1:1053';
const dnsProtectionBuildId = '0.9.2-dns2.1';

String dnsProtectionErrorCode(Object error) =>
    RegExp(r'DP_[A-Z0-9_]+').firstMatch(error.toString())?.group(0) ??
    'DP_CONFIG_REJECTED';

bool dnsProtectionControlReady(Map<String, dynamic> status, String revision) {
  final core = status['core'];
  final guard = status['guard'];
  return core is Map &&
      guard is Map &&
      core['enabled'] == true &&
      core['running'] == true &&
      core['policyRevision'] == revision &&
      guard['armed'] == true &&
      guard['bound'] == true &&
      guard['errorCode'] == null;
}

String dnsProtectionSessionKey(Map<String, dynamic> status) {
  final core = status['core'] as Map;
  final guard = status['guard'] as Map;
  return '${core['processId']}:${core['revision']}:'
      '${guard['sessionId']}:${guard['interfaceLuid']}';
}

void validateDnsProtection(DnsProtectionProps settings) {
  if (settings.schemaVersion != 1) {
    throw const FormatException('DP_CONFIG_REJECTED: unsupported policy');
  }
  final target = settings.proxyTarget;
  if (target.trim().isEmpty ||
      target != target.trim() ||
      RegExp(r'[&#=\r\n]').hasMatch(target) ||
      const {
        'DIRECT',
        'COMPATIBLE',
        'REJECT',
        'GLOBAL',
      }.contains(target.toUpperCase())) {
    throw const FormatException('DP_NO_PROXY: select a concrete proxy');
  }
  if (settings.upstreams.isEmpty || settings.bootstrapServers.isEmpty) {
    throw const FormatException('DP_UNSAFE_UPSTREAM: missing resolver');
  }
  if (settings.upstreams.length > 8 || settings.bootstrapServers.length > 8) {
    throw const FormatException('DP_CONFIG_REJECTED: too many resolvers');
  }
  for (final address in settings.upstreams) {
    validateDnsProtectionServer(address, bootstrap: false);
  }
  for (final address in settings.bootstrapServers) {
    validateDnsProtectionServer(address, bootstrap: true);
  }
}

void validateDnsProtectionServer(String address, {required bool bootstrap}) {
  final uri = Uri.tryParse(address);
  if (uri == null ||
      !(bootstrap
          ? uri.scheme == 'https'
          : const ['https', 'tls'].contains(uri.scheme)) ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty ||
      uri.hasQuery ||
      (uri.scheme == 'https' && uri.path.isEmpty) ||
      (uri.hasPort && uri.port <= 0)) {
    throw const FormatException('DP_UNSAFE_UPSTREAM: encrypted DNS required');
  }
  if (uri.hasFragment) {
    const prefix = 'name-cert-verify=';
    final name = uri.fragment.startsWith(prefix)
        ? uri.fragment.substring(prefix.length)
        : '';
    if (!bootstrap || !_validBootstrapCertificateName(name)) {
      throw const FormatException('DP_UNSAFE_UPSTREAM: invalid certificate name');
    }
  }
  if (bootstrap) {
    final address = InternetAddress.tryParse(uri.host);
    if (address == null || address.type != InternetAddressType.IPv4) {
      throw const FormatException('DP_BOOTSTRAP_LOOP: IPv4 literal required');
    }
  }
}

bool _validBootstrapCertificateName(String name) =>
    name.length <= 253 &&
    name.contains('.') &&
    InternetAddress.tryParse(name) == null &&
    name.split('.').every(
      (label) => RegExp(
        r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$',
      ).hasMatch(label),
    );

void applyDnsProtection(
  Map<dynamic, dynamic> config,
  DnsProtectionProps settings,
) {
  if (!settings.enabled) return;
  validateDnsProtection(settings);
  String server(String address, String target) {
    final parts = address.split('#');
    final certificate = parts.length == 2 ? '&${parts.last}' : '';
    return '${parts.first}#$target$certificate'
        '&ecs=0.0.0.0/0&ecs-override=true';
  }
  final protected = settings.upstreams
      .map((address) => server(address, settings.proxyTarget))
      .toList();
  final bootstrap = settings.bootstrapServers
      .map((address) => server(address, 'DIRECT'))
      .toList();
  final dns = <String, dynamic>{
    if (config['dns'] is Map)
      ...Map<String, dynamic>.from(config['dns'] as Map),
    'enable': true,
    'listen': dnsProtectionListen,
    'ipv6': false,
    'prefer-h3': false,
    'respect-rules': false,
    'nameserver': protected,
    'direct-nameserver': protected,
    'direct-nameserver-follow-policy': false,
    'default-nameserver': bootstrap,
    'proxy-server-nameserver': bootstrap,
    'nameserver-policy': <String, dynamic>{},
    'proxy-server-nameserver-policy': <String, dynamic>{},
    'fallback': <String>[],
  }..remove('fallback-filter');
  config['dns'] = dns;
  config['ipv6'] = false;
  config['tun'] = <String, dynamic>{
    if (config['tun'] is Map)
      ...Map<String, dynamic>.from(config['tun'] as Map),
    'enable': true,
    'device': dnsProtectionDevice,
    'auto-route': true,
    'auto-detect-interface': true,
    'strict-route': true,
    'dns-mode': 'hijack',
    'dns-hijack': ['any:53', 'tcp://any:53'],
  };
  for (final key in const [
    'external-controller',
    'external-controller-tls',
    'external-controller-unix',
    'external-controller-pipe',
  ]) {
    config[key] = '';
  }
}
