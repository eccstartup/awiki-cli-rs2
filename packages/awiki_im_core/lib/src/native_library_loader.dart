import 'dart:ffi';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

enum AwikiImCoreLibrarySource { open, process }

final class AwikiImCoreLibrarySelection {
  const AwikiImCoreLibrarySelection.open(this.path)
    : source = AwikiImCoreLibrarySource.open;

  const AwikiImCoreLibrarySelection.process()
    : source = AwikiImCoreLibrarySource.process,
      path = null;

  final AwikiImCoreLibrarySource source;
  final String? path;
}

AwikiImCoreLibrarySelection resolveAwikiImCoreLibrary({
  required String operatingSystem,
  String? macOsDylibPath,
  String? macOsBundledDylibPath,
}) {
  switch (operatingSystem) {
    case 'android':
    case 'linux':
      return const AwikiImCoreLibrarySelection.open('libawiki_im_core.so');
    case 'windows':
      return const AwikiImCoreLibrarySelection.open('awiki_im_core.dll');
    case 'macos':
      final configuredPath = macOsDylibPath?.trim();
      if (configuredPath != null && configuredPath.isNotEmpty) {
        return AwikiImCoreLibrarySelection.open(configuredPath);
      }
      final bundledPath = macOsBundledDylibPath?.trim();
      if (bundledPath != null && bundledPath.isNotEmpty) {
        return AwikiImCoreLibrarySelection.open(bundledPath);
      }
      return const AwikiImCoreLibrarySelection.process();
    case 'ios':
      return const AwikiImCoreLibrarySelection.process();
    default:
      throw UnsupportedError(
        'Unsupported platform for awiki_im_core native library: '
        '$operatingSystem.',
      );
  }
}

/// Resolves a Core dylib shipped inside the running macOS app bundle.
///
/// Production builds link Core into the Runner, so bundles without the dylib
/// keep using process lookup. Bundles that package the dylib load it relative
/// to `Contents/MacOS`, so moving the app does not break Core loading.
String? resolveBundledMacOsDylibPath({
  required String resolvedExecutable,
  required bool Function(String path) exists,
}) {
  const marker = '/Contents/MacOS/';
  final index = resolvedExecutable.lastIndexOf(marker);
  if (index <= 0) {
    return null;
  }
  final bundlePath = resolvedExecutable.substring(0, index);
  final candidate = '$bundlePath/Contents/Frameworks/libawiki_im_core.dylib';
  return exists(candidate) ? candidate : null;
}

DynamicLibrary loadAwikiImCoreLibrary() {
  final selection = resolveAwikiImCoreLibrary(
    operatingSystem: Platform.operatingSystem,
    macOsDylibPath: _configuredMacOsDylibPath(),
    macOsBundledDylibPath: _bundledMacOsDylibPath(),
  );
  return switch (selection.source) {
    AwikiImCoreLibrarySource.open => DynamicLibrary.open(selection.path!),
    AwikiImCoreLibrarySource.process => DynamicLibrary.process(),
  };
}

ExternalLibrary loadAwikiImCoreExternalLibrary() {
  final selection = resolveAwikiImCoreLibrary(
    operatingSystem: Platform.operatingSystem,
    macOsDylibPath: _configuredMacOsDylibPath(),
    macOsBundledDylibPath: _bundledMacOsDylibPath(),
  );
  return switch (selection.source) {
    AwikiImCoreLibrarySource.open => ExternalLibrary.open(selection.path!),
    AwikiImCoreLibrarySource.process =>
      ExternalLibrary.process(iKnowHowToUseIt: true),
  };
}

String? _configuredMacOsDylibPath() {
  final value = Platform.environment['AWIKI_IM_CORE_DYLIB']?.trim();
  if (value == null || value.isEmpty) {
    return null;
  }
  return value;
}

String? _bundledMacOsDylibPath() {
  if (!Platform.isMacOS) {
    return null;
  }
  return resolveBundledMacOsDylibPath(
    resolvedExecutable: Platform.resolvedExecutable,
    exists: (path) => File(path).existsSync(),
  );
}
