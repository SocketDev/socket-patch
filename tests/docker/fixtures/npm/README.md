# npm fixture

Synthetic patch for `pkg:npm/minimist@1.2.2` used by the Docker-driven e2e
test at `tests/docker_e2e_npm.rs`.

The fixture serves a "patch" that completely replaces `package/index.js`
with the bytes in `blobs/<after_hash>`. The test uses `--force` to skip the
beforeHash check (we don't bother synthesizing a believable beforeHash —
the goal is to validate the install + scan + apply dispatch end to end,
not to test the hash-verification logic which is already covered by
`apply_invariants.rs`).

To regenerate after editing the patched-content marker:

```sh
echo -n '<new content>' > /tmp/patched
# git-sha256 = sha256("blob N\0" + content)
printf 'blob %s\0' "$(wc -c < /tmp/patched)" | cat - /tmp/patched | shasum -a 256
# rename blobs/<hash> + update api-responses.json
```
