import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:archive/archive_io.dart';
import 'package:fl_clash/common/dns_protection.dart';
import 'package:fl_clash/common/path.dart';
import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;

class DnsProtectionLog {
  Future<void> _tail = Future.value();
  int _pending = 0;
  int _dropped = 0;
  bool writeFailed = false;

  Future<void> record(String event, String result, {String? errorCode}) {
    if (_pending >= 512) {
      _dropped++;
      return Future.value();
    }
    final entry = json.encode({
      'schema_version': 1,
      'ts': DateTime.now().toUtc().toIso8601String(),
      'level': result == 'failed' ? 'error' : 'info',
      'module': 'client',
      'event': event,
      'result': result,
      'error_code': errorCode,
      'build_id': dnsProtectionBuildId,
      'dropped_count': _dropped,
    });
    _dropped = 0;
    _pending++;
    _tail = _tail.then((_) async {
      try {
        final root = await directory;
        await Directory(root).create(recursive: true);
        final file = File(p.join(root, 'client.jsonl'));
        if (await file.exists() && await file.length() > 10 * 1024 * 1024) {
          for (var i = 4; i >= 1; i--) {
            final old = File('${file.path}.$i');
            if (await old.exists()) {
              if (i == 4) {
                await old.delete();
              } else {
                await old.rename('${file.path}.${i + 1}');
              }
            }
          }
          await file.rename('${file.path}.1');
        }
        await file.writeAsString(
          '$entry\n',
          mode: FileMode.append,
          flush: true,
        );
      } catch (_) {
        writeFailed = true;
      } finally {
        _pending--;
      }
    });
    return _tail;
  }

  Future<String> get directory async =>
      p.join(await appPath.homeDirPath, 'diagnostics', 'dns-protection');

  Future<String> export(Map<String, dynamic> summary) async {
    await _tail;
    final output = '${await appPath.tempFilePath}.zip';
    await compute(_encodeDiagnostics, (
      source: await directory,
      output: output,
      summary: summary,
    ));
    return output;
  }
}

Future<void> _encodeDiagnostics(
  ({String source, String output, Map<String, dynamic> summary}) request,
) async {
  final encoder = ZipFileEncoder()..create(request.output);
  try {
    encoder.addArchiveFile(
      ArchiveFile.string('summary.json', json.encode(request.summary)),
    );
    final directory = Directory(request.source);
    if (await directory.exists()) {
      await for (final file in directory.list(
        recursive: true,
        followLinks: false,
      )) {
        if (file is File && file.path.contains('.jsonl')) {
          await encoder.addFile(
            file,
            p.relative(file.path, from: request.source),
          );
        }
      }
    }
  } finally {
    await encoder.close();
  }
}

final dnsProtectionLog = DnsProtectionLog();
