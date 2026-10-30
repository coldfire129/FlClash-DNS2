import 'package:freezed_annotation/freezed_annotation.dart';

part 'generated/dns_protection.freezed.dart';
part 'generated/dns_protection.g.dart';

@freezed
abstract class DnsProtectionProps with _$DnsProtectionProps {
  const factory DnsProtectionProps({
    @Default(1) int schemaVersion,
    @Default(false) bool enabled,
    @Default('') String proxyTarget,
    @Default(['https://1.1.1.1/dns-query']) List<String> upstreams,
    @Default(['https://1.1.1.1/dns-query']) List<String> bootstrapServers,
    @Default(false) bool verbose,
  }) = _DnsProtectionProps;

  factory DnsProtectionProps.fromJson(Map<String, dynamic> json) =>
      _$DnsProtectionPropsFromJson(json);
}
