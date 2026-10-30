// GENERATED CODE - DO NOT MODIFY BY HAND

part of '../dns_protection.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

_DnsProtectionProps _$DnsProtectionPropsFromJson(Map<String, dynamic> json) =>
    _DnsProtectionProps(
      schemaVersion: (json['schemaVersion'] as num?)?.toInt() ?? 1,
      enabled: json['enabled'] as bool? ?? false,
      proxyTarget: json['proxyTarget'] as String? ?? '',
      upstreams:
          (json['upstreams'] as List<dynamic>?)
              ?.map((e) => e as String)
              .toList() ??
          const ['https://1.1.1.1/dns-query'],
      bootstrapServers:
          (json['bootstrapServers'] as List<dynamic>?)
              ?.map((e) => e as String)
              .toList() ??
          const ['https://1.1.1.1/dns-query'],
      verbose: json['verbose'] as bool? ?? false,
    );

Map<String, dynamic> _$DnsProtectionPropsToJson(_DnsProtectionProps instance) =>
    <String, dynamic>{
      'schemaVersion': instance.schemaVersion,
      'enabled': instance.enabled,
      'proxyTarget': instance.proxyTarget,
      'upstreams': instance.upstreams,
      'bootstrapServers': instance.bootstrapServers,
      'verbose': instance.verbose,
    };
