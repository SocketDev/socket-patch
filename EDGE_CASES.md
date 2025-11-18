# Socket-Patch Setup Command: Edge Case Analysis

This document provides a comprehensive analysis of all edge cases handled by the `socket-patch setup` command.

## Detection Logic

The setup command detects if a postinstall script is already configured by checking if the string contains `'socket-patch apply'`. This substring match is intentionally lenient to recognize various valid formats.

## Edge Cases

### 1. No scripts field at all

**Input:**
```json
{
  "name": "test",
  "version": "1.0.0"
}
```

**Behavior:** ✅ Creates scripts field and adds postinstall

**Output:**
```json
{
  "name": "test",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "npx @socketsecurity/socket-patch apply"
  }
}
```

---

### 2. Scripts field exists but no postinstall

**Input:**
```json
{
  "scripts": {
    "test": "jest",
    "build": "tsc"
  }
}
```

**Behavior:** ✅ Adds postinstall to existing scripts object

**Output:**
```json
{
  "scripts": {
    "test": "jest",
    "build": "tsc",
    "postinstall": "npx @socketsecurity/socket-patch apply"
  }
}
```

---

### 2a. Postinstall is null

**Input:**
```json
{
  "scripts": {
    "postinstall": null
  }
}
```

**Behavior:** ✅ Treats as missing, adds socket-patch command

**Output:**
```json
{
  "scripts": {
    "postinstall": "npx @socketsecurity/socket-patch apply"
  }
}
```

---

### 2b. Postinstall is empty string

**Input:**
```json
{
  "scripts": {
    "postinstall": ""
  }
}
```

**Behavior:** ✅ Replaces empty string with socket-patch command

**Output:**
```json
{
  "scripts": {
    "postinstall": "npx @socketsecurity/socket-patch apply"
  }
}
```

---

### 2c. Postinstall is whitespace only

**Input:**
```json
{
  "scripts": {
    "postinstall": "   \n\t   "
  }
}
```

**Behavior:** ✅ Treats as empty, adds socket-patch command

**Output:**
```json
{
  "scripts": {
    "postinstall": "npx @socketsecurity/socket-patch apply"
  }
}
```

---

### 3. Postinstall exists but missing socket-patch setup

**Input:**
```json
{
  "scripts": {
    "postinstall": "echo 'Running postinstall tasks'"
  }
}
```

**Behavior:** ✅ Prepends socket-patch before existing script

**Output:**
```json
{
  "scripts": {
    "postinstall": "npx @socketsecurity/socket-patch apply && echo 'Running postinstall tasks'"
  }
}
```

**Rationale:** Socket-patch runs first to apply security patches before other setup tasks. Uses `&&` to ensure existing script only runs if patching succeeds.

---

### 4a. socket-patch apply without npx

**Input:**
```json
{
  "scripts": {
    "postinstall": "socket-patch apply"
  }
}
```

**Behavior:** ✅ Recognized as configured, no changes

**Rationale:** Valid if socket-patch is installed as a dependency. The substring `'socket-patch apply'` is present.

---

### 4b. npx socket-patch apply (without @socketsecurity/)

**Input:**
```json
{
  "scripts": {
    "postinstall": "npx socket-patch apply"
  }
}
```

**Behavior:** ✅ Recognized as configured, no changes

**Rationale:** Valid format. The substring `'socket-patch apply'` is present.

---

### 4c. Canonical format: npx @socketsecurity/socket-patch apply

**Input:**
```json
{
  "scripts": {
    "postinstall": "npx @socketsecurity/socket-patch apply"
  }
}
```

**Behavior:** ✅ Recognized as configured, no changes

**Rationale:** This is the recommended canonical format.

---

### 4d. pnpm socket-patch apply

**Input:**
```json
{
  "scripts": {
    "postinstall": "pnpm socket-patch apply"
  }
}
```

**Behavior:** ✅ Recognized as configured, no changes

**Rationale:** Valid format for pnpm users. The substring `'socket-patch apply'` is present.

---

### 4e. yarn socket-patch apply

**Input:**
```json
{
  "scripts": {
    "postinstall": "yarn socket-patch apply"
  }
}
```

**Behavior:** ✅ Recognized as configured, no changes

**Rationale:** Valid format for yarn users. The substring `'socket-patch apply'` is present.

---

### 4f. node_modules/.bin/socket-patch apply (direct path)

**Input:**
```json
{
  "scripts": {
    "postinstall": "node_modules/.bin/socket-patch apply"
  }
}
```

**Behavior:** ✅ Recognized as configured, no changes

**Rationale:** Valid format using direct path. The substring `'socket-patch apply'` is present.

---

### 4g. socket apply (main Socket CLI - DIFFERENT command)

**Input:**
```json
{
  "scripts": {
    "postinstall": "socket apply"
  }
}
```

**Behavior:** ⚠️ NOT recognized as configured, adds socket-patch

**Output:**
```json
{
  "scripts": {
    "postinstall": "npx @socketsecurity/socket-patch apply && socket apply"
  }
}
```

**Rationale:** `socket apply` is a DIFFERENT command from the main Socket CLI. The substring `'socket-patch apply'` is NOT present. Socket-patch should be added separately.

---

### 4h. socket-patch list (wrong subcommand)

**Input:**
```json
{
  "scripts": {
    "postinstall": "socket-patch list"
  }
}
```

**Behavior:** ⚠️ NOT recognized as configured, adds socket-patch apply

**Output:**
```json
{
  "scripts": {
    "postinstall": "npx @socketsecurity/socket-patch apply && socket-patch list"
  }
}
```

**Rationale:** `socket-patch list` is a different subcommand. The substring `'socket-patch apply'` is NOT present (missing "apply"). Socket-patch apply should be added.

---

### 4i. socket-patch apply with flags

**Input:**
```json
{
  "scripts": {
    "postinstall": "npx @socketsecurity/socket-patch apply --silent"
  }
}
```

**Behavior:** ✅ Recognized as configured, no changes

**Rationale:** Valid format with flags. The substring `'socket-patch apply'` is present.

---

### 4j. socket-patch apply in middle of script chain

**Input:**
```json
{
  "scripts": {
    "postinstall": "echo start && socket-patch apply && echo done"
  }
}
```

**Behavior:** ✅ Recognized as configured, no changes

**Rationale:** Socket-patch is already in the chain. The substring `'socket-patch apply'` is present.

---

### 4k. socket-patch apply at end of chain

**Input:**
```json
{
  "scripts": {
    "postinstall": "npm run prepare && socket-patch apply"
  }
}
```

**Behavior:** ✅ Recognized as configured, no changes

**Rationale:** Socket-patch is already present. The substring `'socket-patch apply'` is present.

**Note:** While this is recognized, it's not ideal since patches won't be applied before the prepare script runs. However, we don't modify it to avoid breaking existing setups.

---

### 5. Postinstall with invalid data types

#### 5a. Number instead of string

**Input:**
```json
{
  "scripts": {
    "postinstall": 123
  }
}
```

**Behavior:** ✅ Treated as not configured, adds socket-patch

**Rationale:** Invalid type is coerced or ignored. Setup adds proper string command.

#### 5b. Array instead of string

**Input:**
```json
{
  "scripts": {
    "postinstall": ["echo", "hello"]
  }
}
```

**Behavior:** ✅ Treated as not configured, adds socket-patch

**Rationale:** Invalid type. Setup adds proper string command.

#### 5c. Object instead of string

**Input:**
```json
{
  "scripts": {
    "postinstall": { "command": "echo hello" }
  }
}
```

**Behavior:** ✅ Treated as not configured, adds socket-patch

**Rationale:** Invalid type. Setup adds proper string command.

---

### 6. Malformed JSON

**Input:**
```
{ name: "test", invalid json }
```

**Behavior:** ❌ Throws error: "Invalid package.json: failed to parse JSON"

**Rationale:** Cannot process malformed JSON. User must fix the JSON first.

---

## Summary Table

| Scenario | Contains `'socket-patch apply'`? | Behavior |
|----------|----------------------------------|----------|
| No scripts field | ❌ | Add scripts + postinstall |
| Scripts exists, no postinstall | ❌ | Add postinstall |
| Postinstall is null/undefined/empty | ❌ | Add socket-patch command |
| Postinstall has other command | ❌ | Prepend socket-patch |
| `socket-patch apply` | ✅ | Skip (already configured) |
| `npx socket-patch apply` | ✅ | Skip (already configured) |
| `npx @socketsecurity/socket-patch apply` | ✅ | Skip (already configured) |
| `pnpm/yarn socket-patch apply` | ✅ | Skip (already configured) |
| `node_modules/.bin/socket-patch apply` | ✅ | Skip (already configured) |
| `socket-patch apply --flags` | ✅ | Skip (already configured) |
| In script chain with `socket-patch apply` | ✅ | Skip (already configured) |
| `socket apply` (main CLI) | ❌ | Add socket-patch apply |
| `socket-patch list` (wrong subcommand) | ❌ | Add socket-patch apply |
| Invalid data types | ❌ | Add socket-patch command |
| Malformed JSON | N/A | Throw error |

## Testing

All edge cases are tested in:
- **Unit tests:** `submodules/socket-patch/src/package-json/detect.test.ts`
- **E2E tests:** `workspaces/api-v0/e2e-tests/tests/59_socket-patch-setup.js`

Run tests:
```bash
# Unit tests
cd submodules/socket-patch
npm test

# E2E tests
pnpm --filter @socketsecurity/api-v0 run test e2e-tests/tests/59_socket-patch-setup.js
```
