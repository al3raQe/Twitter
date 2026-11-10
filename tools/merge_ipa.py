"""Assemble the compiled test libraries locally; Sideloadly signs the result."""
import argparse
import re
import tempfile
import hashlib
import json
import plistlib
import stat
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / '.tools/python-packages'))
import lief

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description="Merge the tested LTR tweak into a decrypted Twitter/X IPA for Sideloadly.")
parser.add_argument("--input", required=True, type=Path)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
SOURCE = args.input.resolve()
LIBS = ROOT / 'prebuilt/sideload'
(ROOT / '.build-temp').mkdir(exist_ok=True)
STAGE = Path(tempfile.mkdtemp(prefix='ipa-', dir=ROOT / '.build-temp'))
with zipfile.ZipFile(SOURCE) as source_zip:
    candidates = [n for n in source_zip.namelist() if re.fullmatch(r'Payload/[^/]+\.app/Info\.plist', n)]
    if len(candidates) != 1:
        parser.error('Expected exactly one main application inside Payload.')
    metadata = plistlib.loads(source_zip.read(candidates[0]))
    if metadata.get('CFBundleIdentifier') != 'com.atebits.Tweetie2':
        parser.error('Input must be the original Twitter/X application.')
    APP = candidates[0][:-len('Info.plist')]
version = re.sub(r'[^a-zA-Z0-9._-]', '_', str(metadata.get('CFBundleShortVersionString', 'unknown')))
OUTPUT = (args.output or ROOT / 'outputs' / f'Twitter-{version}-LTR-Sideloadly.ipa').resolve()
if SOURCE == OUTPUT or OUTPUT.exists():
    parser.error('Output already exists or equals input; choose a new --output path.')
NAMES = ('zxPluginsInject.dylib', 'libbhFLEX.dylib', 'BHTwitter.dylib')
SUBSTRATE = ROOT / 'vendor/CydiaSubstrate.framework'
manifest = json.loads((LIBS / 'sha256.json').read_text())
for name, expected in manifest.items():
    with (LIBS / name).open('rb') as data:
        if hashlib.file_digest(data, 'sha256').hexdigest() != expected:
            raise ValueError(f'Prebuilt resource checksum mismatch: {name}')
SUBSTRATE_PATH = '@rpath/CydiaSubstrate.framework/CydiaSubstrate'

STAGE.mkdir(parents=True, exist_ok=True)
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
replacements = {}
for name in NAMES:
    fat = lief.MachO.parse(str(LIBS / name))
    assert fat and len(fat), f'Missing or invalid library: {name}'
    for binary in fat:
        for dep in binary.libraries:
            if dep.command == lief.MachO.LoadCommand.TYPE.ID_DYLIB:
                dep.name = '@rpath/' + name
            elif 'substrate.' in dep.name.lower():
                dep.name = SUBSTRATE_PATH
            elif dep.command != lief.MachO.LoadCommand.TYPE.ID_DYLIB:
                for other in NAMES:
                    if dep.name.endswith('/' + other):
                        dep.name = '@rpath/' + other
    patched = STAGE / name
    fat.write(str(patched))
    replacements[APP + 'Frameworks/' + name] = patched
    check = lief.MachO.parse(str(patched))
    for binary in check:
        for dep in binary.libraries:
            assert not dep.name.startswith('/Library/'), dep.name

with zipfile.ZipFile(SOURCE) as src:
    info = plistlib.loads(src.read(APP + 'Info.plist'))
    assert info['CFBundleIdentifier'] == 'com.atebits.Tweetie2'
    main_path = APP + info['CFBundleExecutable']
    original = STAGE / 'main-original'
    original.write_bytes(src.read(main_path))
    main = lief.MachO.parse(str(original))
    for binary in main:
        if binary.has_encryption_info and binary.encryption_info.crypt_id:
            raise ValueError('The input application is encrypted; provide a decrypted IPA.')
        if '@executable_path/Frameworks' not in {r.path for r in binary.rpaths}:
            binary.add(lief.MachO.RPathCommand.create('@executable_path/Frameworks'))
        for name in NAMES:
            load = '@rpath/' + name
            assert load not in {d.name for d in binary.libraries}, f'Already injected: {load}'
            binary.add(lief.MachO.DylibCommand.weak_lib(load))
    patched = STAGE / 'Twitter'
    main.write(str(patched))
    replacements[main_path] = patched
    checked = lief.MachO.parse(str(patched))
    for binary in checked:
        assert all('@rpath/' + n in {d.name for d in binary.libraries} for n in NAMES)
        # Retain embedded entitlement data for Sideloadly's re-signing pass.
        # Sideloadly supplies the installation signature.

    for directory, destination in (
        (LIBS / 'BHTwitter.bundle', APP + 'BHTwitter.bundle/'),
        (SUBSTRATE, APP + 'Frameworks/CydiaSubstrate.framework/'),
        (LIBS / 'OpenTwitterSafariExtension.appex', APP + 'PlugIns/OpenTwitterSafariExtension.appex/'),
    ):
        assert directory.is_dir(), directory
        for path in directory.rglob('*'):
            if path.is_file():
                replacements[destination + path.relative_to(directory).as_posix()] = path

    with zipfile.ZipFile(OUTPUT, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as out:
        for entry in src.infolist():
            if entry.filename in replacements:
                continue
            # Match the project's sideload build: omit the Watch companion.
            if entry.filename.startswith(tuple(APP + p for p in ('Watch/', 'WatchKit/', 'com.apple.WatchPlaceholder/'))):
                continue
            with src.open(entry) as inp, out.open(entry, 'w') as dest:
                import shutil
                shutil.copyfileobj(inp, dest, 1024 * 1024)
        for name, path in replacements.items():
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o755) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(entry, path.read_bytes())

with zipfile.ZipFile(OUTPUT) as result:
    assert result.testzip() is None
    assert len(result.namelist()) == len(set(result.namelist()))
    assert all(name in result.namelist() for name in replacements)

print(json.dumps({'output': str(OUTPUT), 'bytes': OUTPUT.stat().st_size,
                  'sha256': hashlib.file_digest(OUTPUT.open('rb'), 'sha256').hexdigest(),
                  'commit': (LIBS / 'commit.txt').read_text().strip()}, indent=2))
