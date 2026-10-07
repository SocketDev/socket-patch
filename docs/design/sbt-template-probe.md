# sbt owned-file template probe (spec §0.2.5 cases a–j, §1.1)

Status: **gate passes** (plus one later V change, item 8 below, verified by the real-sbt suites). Every applicable case passes on every applicable version with the final templates in this directory. Two cases changed the design (V's check and its installer, see "Changes vs spec §1.1"), and case i was rejected on evidence. The bytes here are frozen for `formats/sbt/owned_file.rs`.

Probe date 2026-10-02. Docker `eclipse-temurin:8-jdk` ran 0.13.18, 1.2.8 and 1.3.13; `eclipse-temurin:17-jdk` ran 1.9.9, 1.13.0 and 2.0.9. Every run used `--rm -m 2g`, one container at a time, through `/private/tmp/claude-501/sbt-job.sh`. The sbt runner is the 1.13.0 launcher script. A Java `HttpsServer` on `https://localhost:8443` mimics `patch.socket.dev` URL shapes (`/patch-registry/maven/<token>/<uuid>/maven2/<rel>`), with a self-signed cert imported into the JDK cacerts. The token selects the variant: `good`; `tamper` (evil commons-lang3 jar); `slow` (sleeps 200 s before answering).

## Files

| Path (under `tpl-probe/final/`) | What |
|---|---|
| `hosted-013.sbt.tpl`, `hosted-1.sbt.tpl`, `hosted-2.sbt.tpl` | `socket-patch.sbt`, by line. Only `@ROWS@` and `@OVERRIDES@` remain as placeholders |
| `vendored-013.sbt.tpl`, `vendored-1.sbt.tpl`, `vendored-2.sbt.tpl` | `socket-patch-vendor.sbt`, by line |
| `examples/{hosted,vendored}-{013,1,2}.*.sbt` | Concrete renders with 2 pins (commons-lang3 3.11 and commons-text 1.9). These exact bytes ran as cases b (hosted) and c (vendored) on all six versions |
| `harness/render.py` | Reference renderer: one shared body plus a per-line installer. The Rust renderer must be byte-identical to it |
| `harness/{mkfix.py,drive.sh,dock.sh,run-all.sh,summ.py,Server.java}` | Fixture builder, in-container driver, docker wrapper and server |
| `harness/summary-v2.txt` | Raw results for the final templates (full matrix, then PASS2 `h5 h6 e3`, then PASS3 CRLF) |
| `harness/summary-v1.txt` | Raw results for the spec-draft template (evidence for the changes) |

Per-run logs are in `tpl-probe/out/<ver>/<case>.log` (final templates) and `tpl-probe/out-v1/<ver>/<case>.log` (spec draft).

The probe scratch (`tpl-probe/`) is not in the repository. The six 2-pin examples, plus 1-pin renders from `harness/render.py`, are committed as golden fixtures in `crates/socket-patch-core/tests/fixtures/sbt/owned_file/` (`<mode>-<line>-<n>pin.sbt`), and `formats/sbt/owned_file.rs` asserts its output against them byte for byte.

## Generator shape

There is one shared body. Per mode, the only differences are the constants in the table below, plus the hosted-only `.gitignore` line. Per line, only two things differ:
- the `@ID@Rows` setting line: `@ID@Rows in Global := @ID@Pins` on 0.13, `Global / @ID@Rows := @ID@Pins` on 1.x and 2.x;
- the 5-line `onLoad` installer at the end of the file. 0.13 uses `in` syntax and `x.append`; 1.x uses slash syntax and `appendWithoutSession`; 2.x is 1.x with `Def.uncached(...)` around the update wrapper. On 0.13 and 1.x the installer also moves socket-patch's resolvers (`socket-patch`, `socket-patch-vendor`) to the front of every project's `externalResolvers` (see "Offline resolution on sbt 1.0–1.2"); sbt 2 keeps the appended `resolvers +=` order.

`harness/render.py` is the source of truth. `render.py templates DIR` writes the six `.tpl` files.

| Constant | Hosted | Vendored |
|---|---|---|
| `@CMD@` | `get` | `vendor` |
| `@ID@` | `socketPatchHosted` | `socketPatchVendor` |
| `@DIR@` (inside the path literal `".socket/@DIR@/maven2"`) | `sbt-hosted` | `vendor` |
| resolver name | `socket-patch` | `socket-patch-vendor` |
| `.gitignore` line (after `val repo`) | present | absent: no line at all, not a blank line |
| file name | `socket-patch.sbt` | `socket-patch-vendor.sbt` |

The `onLoad` installer hardcodes the two row-key labels `socketPatchHostedRows` and `socketPatchVendorRows` in both modes. The marker label `socketPatchApplied` is shared by both modes.

**Line endings.** The renderer emits `\n`, then replaces every `\n` with `\r\n` when the existing file used CRLF. The `"*\n"` inside the `.gitignore` literal is a Scala escape in the source, so it is unaffected. A CRLF render of both files at once passed on all six versions (case r). The file ends with `}\n`.

## Line grammars (for the strict `parse`)

Values are validated before rendering (spec §1.1 `validate_values`), so the literals below never need escaping.

**Row** (2 per pin, pom then jar; pins sorted by `(group, artifact, sv)`):
```
^  \("(?<g>[A-Za-z0-9_.-]+)", "(?<a>[A-Za-z0-9_.-]+)", "(?<sv>[A-Za-z0-9_.+-]+)", "(?<rel>[A-Za-z0-9_.+/-]+)", "(?<sha>[0-9a-f]{64})", "(?<src>(https?://[A-Za-z0-9._~:/%+-]+)?)"\)(?<comma>,?) // socket-patch (?<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$
```
- `comma` is `,` on every row except the last row of the block.
- `rel` = `<g with . -> />/<a>/<sv>/<a>-<sv>.pom`, or `.jar` for the second row.
- `sv` = `<base>-socket.<first 8 hex of uuid>`.
- Hosted: `src` = `index_url + "/" + rel`. Vendored: `src` is `""`.

**Override** (1 per pin, same order):
```
^  dependencyOverrides \+= "(?<g>...)" % "(?<a>...)" % "(?<sv>...)"(?<comma>,?) // socket-patch (?<uuid>...) deps=(?<deps>[0-9a-f]{8})$
```
- `comma` is `,` on every override line except the last.
- It is `%`, never `%%`, and never `++= Seq`.
- **Zero pins are never rendered**: the file is deleted instead.

Every other line must equal the template line byte for byte (after CRLF→LF normalisation). The fixed header line is `// Generated by socket-patch. Do not edit; re-run \`socket-patch <cmd>\`.`

## Results (final templates)

PASS means the expected outcome below. All six versions ran each case unless the row says otherwise.

| # | Case | Expected | 0.13.18 | 1.2.8 | 1.3.13 | 1.9.9 | 1.13.0 | 2.0.9 |
|---|---|---|---|---|---|---|---|---|
| b | Hosted, 2 pins, row/override comments and trailing commas; first load downloads pom+jar ×2 (`reqs=4`), rerun makes 0 requests | both PATCHED, exit 0; `c` has no commons dependency | PASS | PASS | PASS | PASS | PASS | PASS |
| t | Hosted, server serves a tampered jar | load fails `socket-patch: <url> served sha256 …, pinned …` | PASS | PASS | PASS | PASS | PASS | PASS |
| c | Vendored, 2 pins, resolver `socket-patch-vendor`, file `socket-patch-vendor.sbt`; then tree jar tampered | PATCHED; then load fails `has sha256 …, pinned …` | PASS | PASS | PASS | PASS | PASS | PASS |
| d | Hosted (lang3) + vendored (text) at once | both PATCHED, lang3 from `.socket/sbt-hosted`, text from `.socket/vendor` | PASS | PASS | PASS | PASS | PASS | PASS |
| d-tamperL3 / d-tamperTX | As d, post-load tamper of each mode's jar (the shared V must cover both files' pins) | `(a / update) socket-patch: g:a:sv resolved to … not pinned` | PASS | PASS | PASS | PASS | PASS | PASS |
| a | V content check: tamper the in-repo jar after the load-time check (TOCTOU via a `tamperL3`/`tamperTX` command), vendored and hosted | update fails in V | PASS | PASS | PASS | PASS | PASS | PASS |
| e1 | Hosted, server stalls (read timeout 120 s); 0.13.18 and 2.0.9 only (plain JDK code) | load fails after ~125 s with `cannot download <url> (java.net.SocketTimeoutException: Read timed out)`; 0 `.part` left | PASS | – | – | – | – | PASS |
| e2 | Hosted, unroutable host (connect timeout 30 s); 0.13.18 and 2.0.9 only | fails after ~34 s with `connect timed out`; 0 `.part` left | PASS | – | – | – | – | PASS |
| e (temp) | `createTempFile` in the target directory + `finally tmp.delete()` | `parts=0` after every run (b, e1, e2) | PASS | PASS | PASS | PASS | PASS | PASS |
| f | Hosted writes `.socket/sbt-hosted/.gitignore` = `*\n` (`od`: `*  \n`) | exact bytes | PASS | PASS | PASS | PASS | PASS | PASS |
| g3 | X3: `ThisBuild / resolvers += Resolver.mavenLocal` with an evil suffixed GAV in `~/.m2` | V fails `resolved to /root/.m2/… with sha256 … not pinned` | PASS | PASS | PASS | PASS | PASS | PASS |
| g4 | X4: evil suffixed GAV in `~/.ivy2/local` (default first resolver) | V fails `resolved to /root/.ivy2/local/…` | PASS | PASS | PASS | PASS | PASS | PASS |
| g4i | X4 with Ivy (`useCoursier := false` on 1.3+; n/a on 2.0.9) | same | PASS | PASS | PASS | PASS | PASS | n/a |
| g1 | X1 on Ivy, vendored: A resolves; B = a copy; B runs; A's jar tampered; B runs; A deleted; B runs | B-good PASS (uses A's pinned bytes); B-afterAtamper V fails; B-afterArm PASS from B's own tree | PASS | PASS | PASS | PASS | PASS | n/a (no Ivy) |
| g1k | X1 on the line's default resolver | Ivy lines as g1; Coursier lines read B's own tree, so A's tamper is irrelevant (PATCHED) | PASS | PASS | PASS | PASS | PASS | PASS |
| h1 | `ThisBuild / dependencyOverrides := Seq.empty` in `zz.sbt` | if `zz.sbt` loads after ours, V fails `a resolves …:1.9, expected 1.9-socket…`; if before, ours wins (PATCHED) | PASS (ours wins: `.sbt` order is `zz.sbt,build.sbt,socket-patch.sbt`) | PASS (same) | PASS (same) | PASS (V fails) | PASS (V fails) | PASS (V fails) |
| h2 | Project-scoped `a / dependencyOverrides := Seq.empty` (shadows ThisBuild whatever the file order) | V fails `a resolves org.apache.commons:commons-text:1.9, expected 1.9-socket.12345678` | PASS | PASS | PASS | PASS | PASS | PASS |
| h3 | Project-scoped `a / resolvers := Seq.empty` | fails closed: Ivy `unresolved dependency … 1.9-socket… not found`; Coursier `not found` | PASS | PASS | PASS | PASS | PASS | PASS |
| h4 | Competing `a / dependencyOverrides += …commons-lang3 % 3.12.0` | V fails `a resolves …:3.12.0, expected 3.11-socket.abcdef12` | PASS | PASS | PASS | PASS | PASS | PASS |
| h5 | Interactive `set ThisBuild / dependencyOverrides := Seq.empty` | sbt reapplies, but ours stays effective (PATCHED). Safe; V did not need to fire | PASS (safe) | PASS (safe) | PASS (safe) | PASS (safe) | PASS (safe) | PASS (safe) |
| h6 | `reload`, then `set version := "9"`, then post-load tamper | V still installed after reload and set: update fails | PASS | PASS | PASS | PASS | PASS | PASS |
| i | Per-checkout resolver name (`socket-patch-vendor-<hex(path)>`) stops X1 | **rejected.** `ivydata-*.properties` records `resolver=sbt-chain`, not our resolver's name, so the name never reaches Ivy's cache key. With the name, B still used A's origin (g1p ≡ g1 on 0.13.18, 1.2.8, 1.3.13, 1.9.9, 1.13.0). V's content check closes X1 instead | FAIL→rejected | same | same | same | same | n/a |
| j | Ivy (0.13.18, 1.2.8 default; 1.3.13, 1.9.9, 1.13.0 with `useCoursier := false`): where resolved artifacts live | in place under `<checkout>/.socket/…/maven2/…` (Ivy uses the `file:` origin, no cache copy), or another checkout's origin (see g1). V is therefore content-based on every line, not path-based | in place | in place | in place | in place | in place | n/a (no Ivy) |
| r | CRLF render of both files at once (57/57 lines CRLF) | both PATCHED | PASS | PASS | PASS | PASS | PASS | PASS |

The concurrency sub-case of e (e3: two concurrent first loads of one checkout) **could not be exercised through sbt**, and this is not a template issue:
- sbt ≥1.4 refuses the second instance: `BootServerSocket … Address already in use`, exit 2 (1.13.0).
- 0.13.18 races on its own compiled `.sbt` definitions: `not found: object $7d60…`.

The template-side guarantee is structural: `createTempFile` names are unique, the atomic same-directory move happens only after the sha256 matches, and `finally tmp.delete()` runs. `parts=0` held after every run, including failures.

Log references, under `tpl-probe/out/<ver>/`:
- b: `b.log`, `b-rerun.log`
- t: `t.log`
- c: `c.log`, `c-tamper.log`
- d: `d.log`, `d-tamperL3.log`, `d-tamperTX.log`
- a: `a.log`, `a-hosted.log`
- e: `e1.log`, `e2.log`, `e3-{1,2}.log`
- g: `g3.log`, `g4.log`, `g4i.log`, `g1{,p,k}-{A,B-good,B-afterAtamper,B-afterArm}.log`
- h: `h1.log` … `h6.log`
- j: `j.log`
- r: `r.log`

The f and ivydata checks are inline in `summary.txt`.

## Changes vs the spec §1.1 draft (and why)

1. **V checks content, not location.** The draft V failed when any artifact path was outside `<root>/.socket/@DIR@/maven2`.
   - Run on Ivy (draft template, `out-v1`), that made every legitimate second checkout fail: case g1-B-good on 0.13.18, 1.2.8 and 1.3.13. Ivy serves the first checkout's `file:` origin from `~/.ivy2/cache`, and case i shows that no resolver name avoids this.
   - The final V instead requires that every artifact file of a pinned, non-evicted module has a sha256 equal to one of that GA's pinned rows (pom or jar), and that `revision == sv`.
   - This is location-independent. It still fails closed on X1 (another checkout tampered), X3 (mavenLocal), X4 (ivy-local) and TOCTOU, because the bytes differ from the pin. It also rejects any extra artifact an attacker publishes under the pinned GAV.
   - Message: `<g>:<a>:<sv> resolved to <file> with sha256 <got>, which is not pinned (tampered, or from ivy-local, mavenLocal or another checkout); delete it and run sbt update`.
   - The `<project> resolves <g>:<a>:<rev>, expected <sv>; …` message is unchanged from the spec.
2. **One shared V for both files.** With the draft's per-file installers, hosted + vendored present together (case d) **looped forever** in `onLoad` on 0.13.18, 1.2.8 and 1.3.13 (`out-v1/<ver>/d.log`: endless `Set current project to root`). Each `appendWithoutSession` rebuilds from `session.original` and drops the other file's appended wrapper and marker, so each hook re-fires the other.
   - Fix: both files declare `SettingKey[Boolean]("socketPatchApplied")` (same label, so same key: VBP) and publish their rows as a static `Global / @ID@Rows := @ID@Pins`, which survives rebuilds.
   - Whichever installer runs first appends one wrapper per project that verifies the union of `socketPatchHostedRows` and `socketPatchVendorRows`, looked up by label.
   - The second installer then sees the marker and returns. d-tamperL3 and d-tamperTX prove that both files' pins are enforced on all six lines.
3. **Resolver name stays constant** (`socket-patch` / `socket-patch-vendor`). Case i rejected the per-checkout name (see the table). `@RESOLVER@` is not computed.
4. **Download hardening:**
   - `URLConnection` with connect timeout 30 s and read timeout 120 s;
   - `createTempFile("socket-patch", ".part", dir)`;
   - the whole download sits in `try { … } finally tmp.delete()`;
   - `IOException` is mapped to `socket-patch: cannot download <url> (<exception>)` instead of a raw stack trace (e1, e2).
5. **`.gitignore` line is a plain statement,** `val gitignore = …; if (!gitignore.isFile) { repo.mkdirs(); Files.write(…, "*\n".getBytes) }`, not the draft's `{ … }` block. A `{` block on the line after `val repo = f(x)` is parsed by Scala as a block argument to `f(x)`.
6. **`repo` is computed inline** (`new java.io.File(baseDirectory.value, ".socket/@DIR@/maven2").getCanonicalFile`) rather than with `/` segments, so no `RichFile` implicit is needed on any line. `@DIRSEGS@` therefore becomes the single path literal.
7. **Helpers are top-level, `@ID@`-prefixed defs/vals** (`@ID@Pins`, `@ID@Rows`, `@ID@Applied`, `@ID@Fail`, `@ID@Sha256`, `@ID@Verify`). `.sbt` top-level definitions are shared across the root's `.sbt` files, so unprefixed names would collide when both files are present.

8. **V checks what the build declares (added after the probe).** The build-wide `dependencyOverrides +=` forces `sv` whatever version a project declares, so V's revision check alone passed a build that had bumped the pinned GA (the override made the resolved revision `sv`): a silent downgrade. V now also takes each project's `allDependencies` and fails when a dependency names a pinned GA (`%` artifact equal, or a `%%` / `%%%` name the pinned artifact extends with `_`) at a version newer than the pin's base by its leading numbers (`@ID@Newer`, the same rule as `formats::sbt::build::numeric_newer`); dynamic versions (`+`, ranges, `latest.*`) are not compared, and an older declared version is fine (evicted by the base anyway). Message: `<project> declares <g>:<a>:<rev> but socket-patch forces <sv> (a downgrade); roll the patch back, or declare <base>`. The installers pass `(p / allDependencies).value` (`(allDependencies in p).value` on 0.13). Verified with the real-sbt suites on all six lines (`sbt_hosted_declared_bump_fails_closed`, `sbt_vendor_declared_bump_fails_closed`, and every existing hosted / vendored capstone over the new bytes), not by re-running this probe harness; the golden fixtures were regenerated from the new template.

## Offline resolution on sbt 1.0–1.2

Probe date 2026-10-02 (pass 4), same setup as above. Harness: `tpl-probe-v3/` (a copy of `harness/` whose `render.py` carries the new 0.13 / 1.x installer, `drive2.sh` case `o`); per-run logs in `tpl-probe-v3/out/`.

**Problem.** Both generated files append their `file:` resolver (`resolvers +=`), so it comes after sbt's default repositories. Coursier (1.3+, 2.x) treats an unreachable repository as a miss and moves on; Ivy on 1.0–1.2 aborts the resolution of the suffixed version on the first repository that fails with a connection error. With the network down and the pinned module not yet in `~/.ivy2/cache` (a fresh machine or CI cache, a fresh clone), 1.2.8 failed `unresolved dependency: org.apache.commons#commons-text;1.9-socket.12345678 … repo1.maven.org … ConnectException`, vendored and hosted alike. 0.13.18 already resolved it.

**Change.** The 0.13 and 1.x installers append, per project, beside the `update` wrapper:

```scala
p / externalResolvers := { val (ours, rest) = (p / externalResolvers).value.partition(r => r.name == "socket-patch" || r.name == "socket-patch-vendor"); ours ++ rest }
```

(`externalResolvers in p` on 0.13). `externalResolvers` is project-scoped by default, so it cannot be set from `inThisBuild`; the installer already has every project ref. The `resolvers +=` block, and with it the load-time tree check and the hosted download, are unchanged. The reorder names both resolvers, so whichever file's installer runs (the shared `socketPatchApplied` marker) orders both. A build that drops ours (`a / resolvers := Seq.empty`, h3) still fails closed: there is nothing to move.

**Case o** warms the build online, deletes `target/` and every `*socket*` entry of `~/.ivy2/cache`, then resolves with every outbound connection refused (`-Dhttp(s).proxyHost=127.0.0.1 -Dhttp(s).proxyPort=9`).

| Case | Template | 0.13.18 | 1.2.8 | 1.3.13 | 1.9.9 | 1.13.0 | 2.0.9 |
|---|---|---|---|---|---|---|---|
| o-offline (vendored) | previous (control) | PATCHED | **fails** (`unresolved dependency … ConnectException`) | – | – | – | – |
| oh-offline (hosted, after the first load downloaded) | previous (control) | PATCHED | **fails** (same) | – | – | – | – |
| o-offline | prepend | PATCHED | PATCHED | PATCHED | PATCHED | PATCHED | PATCHED (2.x template unchanged) |
| oh-offline | prepend | PATCHED | PATCHED | PATCHED | PATCHED | PATCHED | PATCHED |

**Full case set re-run** with the prepend installer on 0.13.18, 1.2.8, 1.3.13, 1.9.9 and 1.13.0 (b, t, c, d, d-tamperL3/TX, a, a-hosted, g3, g4, g4i, g1, g1k, h1–h6, j, r): every case keeps its outcome from the table above, except two that change for the better:

- **g3 (mavenLocal) and g4 / g4i (ivy-local)** now resolve PATCHED instead of failing in V: our resolver is consulted first, so the poisoned copy is never chosen. Both outcomes are safe; V still guards every other origin.
- g1 (Ivy second checkout) is unchanged: Ivy still serves checkout B from A's cached origin while A exists (`resolver=sbt-chain` in `ivydata`), V still fails B after A's jar is tampered, and B resolves its own tree once A is gone.

The new bytes are the golden fixtures in `crates/socket-patch-core/tests/fixtures/sbt/owned_file/` (the probe's 2-pin renders are byte-identical to them). A file rendered by an earlier build fails the strict parse as modified; sbt support has not shipped, so no migration is kept.

## Notes for the implementers (L3/L4/VEX)

- `.sbt` load order is not reliably alphabetical across lines: `zz.sbt,build.sbt,socket-patch.sbt` on 0.13.18 and 1.2.8 (logged), `build.sbt,socket-patch.sbt,zz.sbt` on 1.9.9 (logged); 1.3.13 behaved like 0.13 (ours won) but does not log the order. The fail-closed guarantee therefore rests on V, not on file order. Build-source refusals (`redirect_sbt_overrides_assignment` and friends) remain useful as early, explained errors.
- The interactive `set ThisBuild / dependencyOverrides := …` (h5) does not displace ours: sbt reapplies settings and ours stays effective. Nothing to handle.
- V runs only in `update`, so `updateClassifiers` and `updateSbtClassifiers` are not wrapped. Sources and javadoc jars of a pinned GAV don't exist in our repo anyway.
- The hosted `src` URL, which contains the token, appears in error messages. It is already in the committed file, so this exposes nothing new.
- The server-side `.sha1` is never consulted. Hosted needs only `<rel>` for pom and jar to be fetchable from `index_url`.
