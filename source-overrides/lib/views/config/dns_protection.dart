import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/common/dns_protection_log.dart';
import 'package:fl_clash/common/dns_protection_probe.dart';
import 'package:fl_clash/core/desktop/core_manifest.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

class DnsProtectionView extends ConsumerStatefulWidget {
  const DnsProtectionView({super.key});

  @override
  ConsumerState<DnsProtectionView> createState() => _DnsProtectionViewState();
}

class _DnsProtectionViewState extends ConsumerState<DnsProtectionView> {
  bool _busy = false;
  String? _detail;
  int? _probeReplies;
  Map<String, dynamic>? _lastCheck;

  void _update(DnsProtectionProps Function(DnsProtectionProps) update) {
    setState(() {
      _detail = null;
      _probeReplies = null;
      _lastCheck = null;
    });
    ref
        .read(appSettingProvider.notifier)
        .update(
          (state) => state.copyWith(dnsProtection: update(state.dnsProtection)),
        );
  }

  Future<void> _check() async {
    if (_busy || ref.read(safeModeProvider)) return;
    setState(() => _busy = true);
    final l = context.appLocalizations;
    final settings = ref.read(appSettingProvider).dnsProtection;
    try {
      final status = await ref.read(coreHandlerProvider).dnsProtectionStatus();
      _lastCheck = status;
      final revision = json.encode(settings.toJson()).toMd5();
      var ready = false;
      if (dnsProtectionControlReady(status, revision)) {
        final probes = await runProtectedDnsProbes();
        _lastCheck = {
          ...status,
          'dns_probes': probes,
          'checked_at': DateTime.now().toUtc().toIso8601String(),
        };
        final confirmed = await ref
            .read(coreHandlerProvider)
            .dnsProtectionStatus();
        ready =
            dnsProtectionProbesReady(probes) &&
            dnsProtectionControlReady(confirmed, revision) &&
            dnsProtectionSessionKey(status) ==
                dnsProtectionSessionKey(confirmed);
        _probeReplies = probes
            .where((probe) => probe['result'] == 'success')
            .length;
      }
      if (settings != ref.read(appSettingProvider).dnsProtection) return;
      if (mounted) {
        setState(
          () => _detail = ready
              ? l.dnsProtectionLocalReady
              : l.dnsProtectionRestricted,
        );
      }
      await dnsProtectionLog.record(
        'local_state_checked',
        ready ? 'success' : 'failed',
        errorCode: ready ? null : 'DP_DNS_UNREACHABLE',
      );
    } catch (_) {
      if (mounted) setState(() => _detail = l.dnsProtectionRestricted);
      await dnsProtectionLog.record(
        'local_state_checked',
        'failed',
        errorCode: 'DP_PROBE_UNKNOWN',
      );
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _export() async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      Map<String, dynamic> inspection;
      try {
        inspection = await ref
            .read(coreHandlerProvider)
            .dnsProtectionStatus()
            .timeout(const Duration(seconds: 4));
      } catch (error) {
        inspection = {
          'status': 'unavailable',
          'error_code': dnsProtectionErrorCode(error),
        };
      }
      final path = await dnsProtectionLog.export({
        'schema_version': 1,
        'build_id': dnsProtectionBuildId,
        'core_sha256': await CoreManifest.readCoreSha256(),
        'time': DateTime.now().toUtc().toIso8601String(),
        'platform': Platform.operatingSystem,
        'inspection': inspection,
        'last_manual_check': _lastCheck,
        'wire_capture': 'not_performed',
        'authoritative_egress_check': 'not_performed',
        'client_log_write_failed': dnsProtectionLog.writeFailed,
      });
      try {
        await picker.saveFileWithPath('FlClash-DNS-diagnostics.zip', path);
      } finally {
        final file = File(path);
        if (await file.exists()) await file.delete();
      }
    } catch (error) {
      if (mounted) dialogs.showNotifier(error.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final settings = ref.watch(
      appSettingProvider.select((s) => s.dnsProtection),
    );
    final ready = ref.watch(dnsProtectionReadyProvider);
    return BaseScaffold(
      title: l.dnsProtectionTitle,
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          generateSection(
            items: [
              ConfigToggleItem(
                title: (l) => l.dnsProtectionTitle,
                selector: appSettingProvider.select(
                  (s) => s.dnsProtection.enabled,
                ),
                onChanged: (_, enabled) {
                  try {
                    if (enabled) validateDnsProtection(settings);
                    _update((s) => s.copyWith(enabled: enabled));
                  } catch (_) {
                    dialogs.showNotifier(l.dnsProtectionInvalid);
                  }
                },
              ),
              ConfigTextItem(
                title: (l) => l.dnsProtectionTarget,
                selector: appSettingProvider.select(
                  (s) => s.dnsProtection.proxyTarget,
                ),
                normalize: (value) => value.trim(),
                onChanged: (_, target) =>
                    _update((s) => s.copyWith(proxyTarget: target)),
              ),
              ConfigListEditItem(
                title: (l) => l.dnsProtectionUpstream,
                selector: appSettingProvider.select(
                  (s) => s.dnsProtection.upstreams,
                ),
                itemValidator: (address, l) {
                  try {
                    validateDnsProtectionServer(
                      address ?? '',
                      bootstrap: false,
                    );
                    return null;
                  } catch (_) {
                    return l.dnsProtectionInvalid;
                  }
                },
                onChanged: (_, addresses) =>
                    _update((s) => s.copyWith(upstreams: addresses)),
              ),
              ConfigListEditItem(
                title: (l) => l.dnsProtectionBootstrap,
                selector: appSettingProvider.select(
                  (s) => s.dnsProtection.bootstrapServers,
                ),
                itemValidator: (address, l) {
                  try {
                    validateDnsProtectionServer(address ?? '', bootstrap: true);
                    return null;
                  } catch (_) {
                    return l.dnsProtectionInvalid;
                  }
                },
                onChanged: (_, addresses) =>
                    _update((s) => s.copyWith(bootstrapServers: addresses)),
              ),
              ConfigToggleItem(
                title: (l) => l.dnsProtectionVerbose,
                selector: appSettingProvider.select(
                  (s) => s.dnsProtection.verbose,
                ),
                onChanged: (_, verbose) =>
                    _update((s) => s.copyWith(verbose: verbose)),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Text(
            l.dnsProtectionDescription,
            style: AppTextStyle.subheadline.of(context),
          ),
          const SizedBox(height: 16),
          Text(
            !settings.enabled
                ? l.disabled
                : ready
                ? l.dnsProtectionActive
                : l.dnsProtectionRestricted,
            style: AppTextStyle.headline.of(context),
          ),
          if (_detail != null)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(
                _detail!,
                style: AppTextStyle.subheadline.of(context),
              ),
            ),
          if (_probeReplies != null)
            Text(
              '${l.dnsProtectionProbeReplies}: $_probeReplies/4',
              style: AppTextStyle.subheadline.of(context),
            ),
          const SizedBox(height: 16),
          FilledButton(
            onPressed: _busy ? null : _check,
            child: Text(l.dnsProtectionCheck),
          ),
          TextButton(
            onPressed: _busy ? null : _export,
            child: Text(l.exportLogs),
          ),
          TextButton(
            onPressed: ref.watch(safeModeProvider)
                ? null
                : () => launchUrl(Uri.parse('https://browserleaks.com/dns')),
            child: Text(l.dnsProtectionExternal),
          ),
          TextButton(
            onPressed: _busy
                ? null
                : () async {
                    _update((s) => s.copyWith(enabled: false));
                    try {
                      await ref
                          .read(setupActionProvider.notifier)
                          .setRunning(false);
                    } catch (error) {
                      if (mounted) dialogs.showNotifier(error.toString());
                    }
                  },
            child: Text(l.dnsProtectionRecover),
          ),
        ],
      ),
    );
  }
}
