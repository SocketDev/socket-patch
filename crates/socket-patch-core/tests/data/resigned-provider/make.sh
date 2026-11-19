#!/usr/bin/env bash
# Rebuild upstream.jar and served.jar: a jar jarsigner signed, and the same
# jar with org/example/B.class changed, upstream's signature files dropped
# and jarsigner run again under the alias SOCKET (what the patch service's
# re-signing of a patched security provider produces). Needs a JDK
# (jar, keytool, jarsigner) and python3; the keys are throwaway, so the
# jars differ from the committed ones in their signature blocks only.
#
#   ./make.sh <empty work dir>
set -euo pipefail
work=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
cd "$work"
mkdir -p src/org/example home
printf '\xca\xfe\xba\xbe class A' > src/org/example/A.class
printf '\xca\xfe\xba\xbe class B, vulnerable' > src/org/example/B.class
printf '\xca\xfe\xba\xbe class C' > src/org/example/C.class
printf 'provider notice\n' > src/NOTICE.txt
printf 'Implementation-Title: example-provider\nImplementation-Version: 1.0\n' > manifest.txt
home="-J-Duser.home=$work/home"
jar "$home" --create --file upstream.jar --manifest manifest.txt -C src .
for alias in upstream socket; do
  keytool "$home" -genkeypair -alias "$alias" -keyalg RSA -keysize 2048 \
    -dname "CN=$alias test key" -validity 36500 \
    -keystore ks.p12 -storetype PKCS12 -storepass changeit
done
sign() {
  jarsigner "$home" -keystore ks.p12 -storepass changeit -digestalg SHA-256 "$@"
}
sign -sigfile UPSTREAM upstream.jar upstream
python3 - <<'PY'
import zipfile
src = zipfile.ZipFile('upstream.jar')
out = zipfile.ZipFile('served.jar', 'w', zipfile.ZIP_DEFLATED)
for info in src.infolist():
    if info.filename.startswith('META-INF/UPSTREAM.'):
        continue
    data = src.read(info.filename)
    if info.filename == 'org/example/B.class':
        data = b'\xca\xfe\xba\xbe class B, fixed'
    out.writestr(info, data)
out.close()
PY
sign -sigfile SOCKET served.jar socket
jarsigner "$home" -verify served.jar
cp upstream.jar served.jar "$here/"
