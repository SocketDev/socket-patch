import sys, base64, hashlib, json

proj = sys.argv[1]
rel = ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz"
spec = "file:" + rel

# integrity computed from the actual vendored tarball (what the tool would do)
with open(f"{proj}/{rel}", "rb") as f:
    integ = "sha512-" + base64.b64encode(hashlib.sha512(f.read()).digest()).decode()

# 1) package.json: add pnpm.overrides
with open(f"{proj}/package.json") as f:
    pkg = json.load(f)
pkg["pnpm"] = {"overrides": {"left-pad@1.3.0": spec}}
with open(f"{proj}/package.json", "w") as f:
    json.dump(pkg, f, indent=2)
    f.write("\n")

# 2) pnpm-lock.yaml surgical text edits
with open(f"{proj}/pnpm-lock.yaml") as f:
    lock = f.read()

# a) insert overrides: section after the settings block
lock = lock.replace(
    "  excludeLinksFromLockfile: false\n\nimporters:",
    f"  excludeLinksFromLockfile: false\n\noverrides:\n  left-pad@1.3.0: {spec}\n\nimporters:",
    1)

# b) importer: direct dep specifier+version -> file: spec
lock = lock.replace(
    "      left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n",
    f"      left-pad:\n        specifier: {spec}\n        version: {spec}\n",
    1)

# c) packages: entry rekeyed; resolution gets patched integrity + tarball; version field; no deprecated
lock = lock.replace(
    "  left-pad@1.3.0:\n"
    "    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}\n"
    "    deprecated: use String.prototype.padStart()\n",
    f"  left-pad@{spec}:\n"
    f"    resolution: {{integrity: {integ}, tarball: {spec}}}\n"
    f"    version: 1.3.0\n",
    1)

# d) snapshots: consumer dep ref + rekeyed snapshot
lock = lock.replace("      left-pad: 1.3.0\n", f"      left-pad: {spec}\n", 1)
lock = lock.replace("  left-pad@1.3.0: {}\n", f"  left-pad@{spec}: {{}}\n", 1)

with open(f"{proj}/pnpm-lock.yaml", "w") as f:
    f.write(lock)
print("edited", proj, "integrity:", integ)
