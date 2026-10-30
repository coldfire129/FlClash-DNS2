import 'dart:convert';
import 'dart:io';

import 'package:archive/archive_io.dart';
import 'package:fl_clash/common/dns_protection_log.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;

import '../helpers/app_paths.dart';

void main() {
  test(
    'exports structured diagnostics without including profile secrets',
    () async {
      final root = Directory.systemTemp.createTempSync('dns-log-test');
      addTearDown(() => root.deleteSync(recursive: true));
      await useAppPaths(root);
      final log = DnsProtectionLog();
      await Future.wait([
        log.record('config_apply_started', 'pending'),
        log.record(
          'config_apply_failed',
          'failed',
          errorCode: 'DP_CONFIG_REJECTED',
        ),
      ]);
      final directory = await log.directory;
      final lines = await File(p.join(directory, 'client.jsonl')).readAsLines();
      expect(lines, hasLength(2));
      final failed = json.decode(lines.last) as Map;
      expect(failed['schema_version'], 1);
      expect(failed['level'], 'error');
      expect(failed['module'], 'client');
      expect(failed['error_code'], 'DP_CONFIG_REJECTED');
      expect(DateTime.parse(failed['ts'] as String).isUtc, isTrue);
      await File(
        p.join(directory, 'subscription-secret.yaml'),
      ).writeAsString('token: private');
      final archivePath = await log.export({'wire_capture': 'not_performed'});
      final archive = ZipDecoder().decodeBytes(
        await File(archivePath).readAsBytes(),
      );
      final names = archive.files.map((entry) => entry.name).toSet();
      expect(names, containsAll(['client.jsonl', 'summary.json']));
      expect(names, isNot(contains('subscription-secret.yaml')));
      expect(log.writeFailed, isFalse);
    },
  );
}
