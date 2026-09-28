# NuGet signing and verification when vendoring a patched same-id+version nupkg

**Headline:** once we change a package we have to drop its `.signature.p7s`. Keeping it fails restore with NU3008, even on Linux with no special settings. Dropping it works under the default policy but fails under `require` with NU3004. Signing, or not signing, never changes the lock `contentHash`. That means we can sign with a Socket certificate and keep lock pinning as it is.

Setup: .NET SDK 8.0.131 on Linux. Each experiment had a fresh HOME, NUGET_PACKAGES and NUGET_HTTP_CACHE_PATH under `exp/<name>/`. The test package was Newtonsoft.Json 13.0.3 from nuget.org, which is author-signed and carries the nuget.org repository countersignature. The "patch" appends bytes to `lib/net6.0/Newtonsoft.Json.dll`. Restores used a single local folder feed (`<clear/>`) with `RestorePackagesWithLockFile`.

## Environment
- **VERIFIED:** signature verification is on by default on Linux with SDK 8. `dotnet nuget verify` prints `X.509 certificate chain validation will use the fallback certificate bundle at '/usr/lib/dotnet/sdk/8.0.131/trustedroots/codesignctl.pem'`. A tampered signed package fails restore with no env var or config set.
- **VERIFIED:** the certificate revocation servers can't be reached from here. Genuine packages only get NU3018/NU3028 `RevocationStatusUnknown` warnings, even in `require` mode.
- **VERIFIED:** timestamp.digicert.com returns HTTP 403 through the proxy, so I could not test timestamped signing.

## (a) Keeping vs dropping `.signature.p7s` (default mode, `accept`)
- **VERIFIED:** modified dll with the signature kept fails: `error NU3008: ... The package integrity check failed. The package has changed since it was signed.`
- **VERIFIED:** re-zipping with no content change and the signature kept also fails with NU3008. The signature covers the zip bytes, not just the file contents.
- **VERIFIED:** modified dll with the signature dropped installs cleanly, with no warnings.
- **VERIFIED:** `DOTNET_NUGET_SIGNATURE_VERIFICATION=false` turns verification off entirely. The tampered, still-signed package then installs.
- **VERIFIED:** if the signature entry has non-zero external file attributes (Python `zipfile` writes `0o600<<16` by default), restore only warns (`NU3005: The package signature file entry is invalid ... 'external file attributes' has an invalid value (25165824)`) and installs the package as if it were unsigned.

## (b) `require` mode (enterprise setup)
The config was `signatureValidationMode=require` plus a `<trustedSigners><repository name="nuget.org" serviceIndex="https://api.nuget.org/v3/index.json">` entry with the three nuget.org repository certificate fingerprints (SHA256 `0E5F38F5…`, `5A2901D6…`, `1F4B311D…`).

- **VERIFIED:** the genuine package installs even from a local folder feed. Repository trust is tied to the certificate, not the source URL.
- **VERIFIED:** the unsigned patched package fails: `error NU3004: ... signatureValidationMode is set to require, so packages are allowed only if signed by trusted signers; however, this package is unsigned.`
- **VERIFIED:** the patched package with the upstream signature kept fails with NU3008.
- **VERIFIED:** `DOTNET_NUGET_SIGNATURE_VERIFICATION=false` overrides `require`, and the unsigned package installs.
- **VERIFIED:** config precedence. With `require` in the user-level `~/.nuget/NuGet/NuGet.Config` and `accept` in the repo's `nuget.config`, the unsigned package installs, so a repo config can weaken the policy. With `require` at user level only, it fails with NU3004.
- **VERIFIED:** `trustedSigners` add up across config levels. The user level had `require` plus the nuget.org `<repository>`; the repo level added only an `<author>`. Both the Socket-signed patched package and genuine nuget.org packages installed.
- **VERIFIED:** if the global packages folder already holds the extracted patched package, restore succeeds under `require` with no check at all. Signatures are only verified when a package is extracted into that folder.
- **DOCS:** `require` mode has no per-package or per-source exemption. `trustedSigners` entries are per certificate: an `<author>` fingerprint, or a `<repository>` fingerprint with optional `<owners>`. `allowUntrustedRoot` only relaxes chain building for a listed certificate; it does not let unsigned packages through.

## (c) Signing with a self-signed certificate (`dotnet nuget sign`)
I made the certificate with `openssl req -x509` (extended key use codeSigning, key use digitalSignature) and exported it to a pfx.

- **VERIFIED:** signing works on Linux in about 1.1 s with exit code 0. `dotnet nuget sign moddrop.nupkg --certificate-path cert.pfx --certificate-password pw -o signed` warns NU3002 (no timestamper), NU3042 (root not in the codesignctl.pem bundle) and `NU3018: UntrustedRoot: self-signed certificate`.
- **VERIFIED:** restore results for the signed patched package:

| Config | Result |
|---|---|
| Default `accept`, nothing trusted | Installs, with warnings NU3018 ("signing certificate is not trusted by the trust provider"), NU3027 (not timestamped) and NU3042 |
| `require` + `<author>` fingerprint, `allowUntrustedRoot="false"` | `error NU3018` |
| `require` + `<author>` fingerprint, `allowUntrustedRoot="true"` | Installs, only a NU3027 warning |
| `require`, no `<author>` | `error NU3018` plus `error NU3034: This package is signed but not by a trusted signer` |

- **VERIFIED:** re-signing a package that still has the upstream signature fails without `--overwrite` (`NU3001: The package already contains a signature`). With `--overwrite` it succeeds and installs under `require` with the author trusted.
- **VERIFIED:** `dotnet nuget sign` writes a valid signature entry even when the input zip has Python-style attributes.
- **VERIFIED (from `--help`):** the CLI can only create author signatures, so we cannot make a repository signature like nuget.org's. **DOCS:** repository signing exists only in the NuGet.Packaging API.
- **DOCS:** a signature without a timestamp stops being valid when the certificate expires.
- **Cost:** about a second per package, and no system trust store changes are needed. The user does have to add one `<author>` entry with `allowUntrustedRoot="true"` if they use `require`.

## (d) `dotnet nuget verify --all` (all VERIFIED)
- Unsigned: `error: NU3004: The package is not signed.` (exit 1)
- Modified with the upstream signature kept: prints `Signature type: Author` and `Signature type: Repository`, then `error: NU3008` (exit 1).
- Self-signed: `error: NU3018 ... not trusted by the trust provider` (exit 1). `--certificate-fingerprint` alone does not change that. With `--configfile` pointing at a config that has the `<author allowUntrustedRoot="true">` entry, it exits 0 with only a NU3027 warning.
- Genuine: `Successfully verified package`, with revocation warnings.

## (e) Global packages folder metadata and `contentHash`
- **VERIFIED:** the package's folder holds `.nupkg.metadata` (`{version:2, contentHash, source}`), `<id>.<ver>.nupkg.sha512`, a byte-identical copy of the nupkg, and an extracted `.signature.p7s`. The metadata records nothing about the signer.
- **VERIFIED: the lock `contentHash` does not depend on the signature file.** This corrects the assumption in the brief.
  - For signed packages, `contentHash` is the SHA-512 of the archive with the `.signature.p7s` entry removed from both the file data and the central directory, and the end-of-archive record offsets and counts adjusted. My `signed_content_hash.py` reproduces the upstream `HrC5BXdl…zQ==` exactly.
  - That differs from SHA-512 of the whole file (`mbJSvHfR…kg==`), which is what `.nupkg.sha512` stores.
  - The unsigned patched package, the Socket-signed one and the re-signed one all produce the same `contentHash` (`Lb2f3WlJ…`), equal to SHA-512 of the unsigned file.
  - `dotnet nuget sign` appends the signature and leaves every other byte unchanged. Swapping signed and unsigned files passes `--locked-mode`.
- **VERIFIED:** when the global packages folder already has upstream and the lock pins the patched hash, `--locked-mode` fails with `error NU1403: Package content hash validation failed`. Without a lock file, restore silently uses upstream and writes the upstream hash into the new lock.

## (f) Zip layout and packaging metadata files (all VERIFIED; unsigned packages in `accept` mode all installed)
- These variants all restored fine:
  - `.psmdcp` removed, even though `_rels/.rels` still points to it
  - `_rels/.rels` and `.psmdcp` both removed
  - `[Content_Types].xml` removed
  - all three removed
  - a new file with an extension not listed in `[Content_Types].xml` (`.patchmeta`, extracted to `lib/net6.0/`)
  - entries in reverse order
  - all entries stored without compression
- The version with all three files removed, then self-signed, installed under `require`. The console app built with `-m:1`, ran, and the copied dll ended with the patch marker.
- The global packages folder never contains `[Content_Types].xml`, `_rels` or `.psmdcp`.
- Every layout change produced a different `contentHash`, so the repack must be deterministic for the hash to be reproducible.
- **DOCS:** other tools that read these files the Office-document way (older `nuget.exe push`, Package Explorer) may still expect them. Keeping them, and adding a `Default` entry for any new extension, costs nothing.

## Implications for each vendoring mechanism
1. **Same id+version, unsigned (current approach).**
   - Works under `accept`. Always fails under `require` (NU3004), with no per-package exemption.
   - The upstream `.signature.p7s` must always be removed (NU3008). A hand-written signature entry with non-zero attributes is silently treated as unsigned.
   - The lock pin, plain SHA-512 of the file, is correct for unsigned packages.
   - The main risk is a collision with an existing copy in the global packages folder (NU1403 in locked mode, silently using upstream otherwise). That comes from reusing id+version, not from signing.
2. **Same id+version, signed by Socket or a repo-local author certificate.**
   - The lock hash is unaffected, and signing is cheap.
   - Under `accept` the only cost is warnings: NU3018/NU3042 go away only if the certificate chains to a root in the SDK bundle, and NU3027 goes away only with a timestamp.
   - Under `require` the user needs one `<author>` entry with `allowUntrustedRoot="true"` for a self-signed certificate. It can go in the repo's `nuget.config` because it merges with the enterprise-level `trustedSigners`. This is the setup to document for enterprises.
   - A self-signed or repo-local key is only as trustworthy as whoever can write to the repo.
   - A CA-issued Socket code-signing certificate with a timestamp would remove `allowUntrustedRoot` and the warnings. Signing could happen on Socket's server, because the signature does not affect the lock hash. We cannot reproduce the nuget.org repository signature.
3. **Pre-filling the global packages folder or a fallback folder.** This skips verification even under `require`, which means it quietly gets around enterprise policy. We should not document it.
4. **A renamed id or new version (e.g. `13.0.3-socket.1`).** The signing situation is the same (unsigned fails NU3004 under `require` unless Socket-signed), but it removes the global-folder and lock collisions. This is inferred, not run.
5. **Overrides we should not recommend.** `DOTNET_NUGET_SIGNATURE_VERIFICATION=false` and a repo-level `signatureValidationMode=accept` both work, but both quietly weaken an organization's policy. The tool should detect an effective `require` and fail with a clear message pointing to the `<author>` instruction.

Everything is in `<scratch>/research/signing/`:
- `FINDINGS.md` — full notes with commands and output
- `env.sh`, `run.sh` — setup and restore scripts
- `repack.py` — rebuilds the test packages
- `signed_content_hash.py` — the signed-package hash calculation
- `cert/` — the test certificate
- `v/`, `signed*/` — the package variants
- `exp/<name>/` — one folder per experiment