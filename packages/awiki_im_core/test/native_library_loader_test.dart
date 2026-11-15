import 'package:awiki_im_core/src/native_library_loader.dart';
import 'package:test/test.dart';

void main() {
  test('Windows resolves the packaged x64 DLL by its stable filename', () {
    final selection = resolveAwikiImCoreLibrary(operatingSystem: 'windows');

    expect(selection.source, AwikiImCoreLibrarySource.open);
    expect(selection.path, 'awiki_im_core.dll');
  });

  test('Android and Linux keep their existing shared library filename', () {
    for (final operatingSystem in ['android', 'linux']) {
      final selection = resolveAwikiImCoreLibrary(
        operatingSystem: operatingSystem,
      );

      expect(selection.source, AwikiImCoreLibrarySource.open);
      expect(selection.path, 'libawiki_im_core.so');
    }
  });

  test('Apple platforms keep process loading and the macOS override', () {
    final macOs = resolveAwikiImCoreLibrary(operatingSystem: 'macos');
    final iOs = resolveAwikiImCoreLibrary(operatingSystem: 'ios');
    final override = resolveAwikiImCoreLibrary(
      operatingSystem: 'macos',
      macOsDylibPath: '  /tmp/libawiki_im_core.dylib  ',
    );

    expect(macOs.source, AwikiImCoreLibrarySource.process);
    expect(iOs.source, AwikiImCoreLibrarySource.process);
    expect(override.source, AwikiImCoreLibrarySource.open);
    expect(override.path, '/tmp/libawiki_im_core.dylib');
  });

  test('macOS loads a Core dylib packaged inside the app bundle', () {
    final selection = resolveAwikiImCoreLibrary(
      operatingSystem: 'macos',
      macOsBundledDylibPath:
          ' /Applications/AWikiMe.app/Contents/Frameworks/libawiki_im_core.dylib ',
    );

    expect(selection.source, AwikiImCoreLibrarySource.open);
    expect(
      selection.path,
      '/Applications/AWikiMe.app/Contents/Frameworks/libawiki_im_core.dylib',
    );
  });

  test('an explicit macOS dylib override wins over the bundled dylib', () {
    final selection = resolveAwikiImCoreLibrary(
      operatingSystem: 'macos',
      macOsDylibPath: '/tmp/custom/libawiki_im_core.dylib',
      macOsBundledDylibPath:
          '/Applications/AWikiMe.app/Contents/Frameworks/libawiki_im_core.dylib',
    );

    expect(selection.source, AwikiImCoreLibrarySource.open);
    expect(selection.path, '/tmp/custom/libawiki_im_core.dylib');
  });

  test('bundled dylib resolution follows the executable bundle layout', () {
    final existing = <String>{
      '/tmp/AWikiMe.app/Contents/Frameworks/libawiki_im_core.dylib',
    };

    expect(
      resolveBundledMacOsDylibPath(
        resolvedExecutable: '/tmp/AWikiMe.app/Contents/MacOS/AWikiMe',
        exists: existing.contains,
      ),
      '/tmp/AWikiMe.app/Contents/Frameworks/libawiki_im_core.dylib',
    );
    expect(
      resolveBundledMacOsDylibPath(
        resolvedExecutable: '/tmp/flutter_tester',
        exists: existing.contains,
      ),
      isNull,
    );
    expect(
      resolveBundledMacOsDylibPath(
        resolvedExecutable: '/tmp/Other.app/Contents/MacOS/Other',
        exists: existing.contains,
      ),
      isNull,
    );
  });

  test('unsupported operating systems fail before native loading', () {
    expect(
      () => resolveAwikiImCoreLibrary(operatingSystem: 'fuchsia'),
      throwsA(isA<UnsupportedError>()),
    );
  });
}
