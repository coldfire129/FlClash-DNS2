import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/database.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/ui/switch.dart';
import 'package:fl_clash/views/config/dns_protection.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import '../helpers/test_app.dart';
import '../helpers/test_profiles.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late ProviderContainer container;

  setUp(() {
    container = ProviderContainer(
      overrides: [profilesProvider.overrideWith(TestProfiles.new)],
    );
    globalState.container = container;
    container.read(viewSizeProvider.notifier).value = const Size(1000, 3000);
  });

  tearDown(() => container.dispose());

  Future<void> pumpPage(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1000, 3000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: const TestApp(child: DnsProtectionView()),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('page exposes diagnostics and starts disabled', (tester) async {
    await pumpPage(tester);
    final l = currentAppLocalizations;
    expect(find.text(l.disabled), findsOneWidget);
    expect(find.text(l.dnsProtectionTarget), findsOneWidget);
    expect(find.text(l.exportLogs), findsOneWidget);
    expect(find.text(l.dnsProtectionDescription), findsOneWidget);
    expect(container.read(appSettingProvider).dnsProtection.enabled, isFalse);
  });

  testWidgets('missing proxy target cannot enable protection', (tester) async {
    await pumpPage(tester);
    await tester.tap(find.byType(CommonSwitch).first);
    await tester.pumpAndSettle();
    expect(container.read(appSettingProvider).dnsProtection.enabled, isFalse);
  });

  testWidgets('valid preferences toggle without claiming the guard is ready', (
    tester,
  ) async {
    container
        .read(appSettingProvider.notifier)
        .update(
          (s) => s.copyWith(
            dnsProtection: const DnsProtectionProps(proxyTarget: 'HK-01'),
          ),
        );
    await pumpPage(tester);
    await tester.tap(find.byType(CommonSwitch).first);
    await tester.pumpAndSettle();
    expect(container.read(appSettingProvider).dnsProtection.enabled, isTrue);
    expect(
      find.text(currentAppLocalizations.dnsProtectionRestricted),
      findsOneWidget,
    );
    expect(
      find.text(currentAppLocalizations.dnsProtectionActive),
      findsNothing,
    );
    await tester.tap(find.byType(CommonSwitch).first);
    await tester.pumpAndSettle();
    expect(container.read(appSettingProvider).dnsProtection.enabled, isFalse);
  });
}
