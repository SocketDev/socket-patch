import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  isPostinstallConfigured,
  generateUpdatedPostinstall,
  updatePackageJsonContent,
} from './detect.js'

describe('isPostinstallConfigured', () => {
  describe('Edge Case 1: No scripts field at all', () => {
    it('should detect as not configured when scripts field is missing', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
      assert.equal(result.currentScript, '')
    })
  })

  describe('Edge Case 2: Scripts field exists but no postinstall', () => {
    it('should detect as not configured when postinstall is missing', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          test: 'jest',
          build: 'tsc',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
      assert.equal(result.currentScript, '')
    })

    it('should detect as not configured when postinstall is null', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: null,
        },
      }

      const result = isPostinstallConfigured(packageJson as any)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
      assert.equal(result.currentScript, '')
    })

    it('should detect as not configured when postinstall is undefined', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: undefined,
        },
      }

      const result = isPostinstallConfigured(packageJson as any)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
      assert.equal(result.currentScript, '')
    })

    it('should detect as not configured when postinstall is empty string', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: '',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
      assert.equal(result.currentScript, '')
    })

    it('should detect as not configured when postinstall is whitespace only', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: '   \t\n  ',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
      assert.equal(result.currentScript, '   \t\n  ')
    })
  })

  describe('Edge Case 3: Postinstall exists but missing socket-patch setup', () => {
    it('should detect as not configured when postinstall has different command', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'echo "Running postinstall"',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
      assert.equal(result.currentScript, 'echo "Running postinstall"')
    })

    it('should detect as not configured with complex existing script', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'npm run build && npm run prepare && echo done',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
    })
  })

  describe('Edge Case 4: Postinstall has socket-patch but not exact format', () => {
    it('should detect socket-patch apply without npx as configured', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'socket-patch apply',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(
        result.configured,
        true,
        'socket-patch apply should be recognized',
      )
      assert.equal(result.needsUpdate, false)
    })

    it('should detect npx socket-patch apply (without @socketsecurity/) as configured', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'npx socket-patch apply',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(
        result.configured,
        true,
        'npx socket-patch apply should be recognized',
      )
      assert.equal(result.needsUpdate, false)
    })

    it('should detect canonical format npx @socketsecurity/socket-patch apply', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'npx @socketsecurity/socket-patch apply',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(result.configured, true)
      assert.equal(result.needsUpdate, false)
    })

    it('should detect pnpm socket-patch apply as configured', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'pnpm socket-patch apply',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(
        result.configured,
        true,
        'pnpm socket-patch apply should be recognized',
      )
      assert.equal(result.needsUpdate, false)
    })

    it('should detect yarn socket-patch apply as configured', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'yarn socket-patch apply',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(
        result.configured,
        true,
        'yarn socket-patch apply should be recognized',
      )
      assert.equal(result.needsUpdate, false)
    })

    it('should detect node_modules/.bin/socket-patch apply as configured', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'node_modules/.bin/socket-patch apply',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(result.configured, true)
      assert.equal(result.needsUpdate, false)
    })

    it('should NOT detect socket apply (main Socket CLI) as configured', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'socket apply',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(
        result.configured,
        false,
        'socket apply (main CLI) should NOT be recognized',
      )
      assert.equal(result.needsUpdate, true)
    })

    it('should NOT detect socket-patch without apply subcommand', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'socket-patch list',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(
        result.configured,
        false,
        'socket-patch list should NOT be recognized',
      )
      assert.equal(result.needsUpdate, true)
    })

    it('should detect socket-patch apply with additional flags', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 'npx @socketsecurity/socket-patch apply --silent',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(result.configured, true)
      assert.equal(result.needsUpdate, false)
    })

    it('should detect socket-patch apply in complex script chain', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall:
            'echo "Starting" && socket-patch apply && echo "Complete"',
        },
      }

      const result = isPostinstallConfigured(packageJson)

      assert.equal(result.configured, true)
      assert.equal(result.needsUpdate, false)
    })
  })

  describe('Edge Case 5: Invalid or malformed data', () => {
    it('should handle malformed JSON gracefully', () => {
      const malformedJson = '{ name: "test", invalid }'

      const result = isPostinstallConfigured(malformedJson)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
      assert.equal(result.currentScript, '')
    })

    it('should handle non-string postinstall value', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: 123,
        },
      }

      const result = isPostinstallConfigured(packageJson as any)

      // Should coerce to string or handle gracefully
      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
    })

    it('should handle array postinstall value', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: ['echo', 'hello'],
        },
      }

      const result = isPostinstallConfigured(packageJson as any)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
    })

    it('should handle object postinstall value', () => {
      const packageJson = {
        name: 'test',
        version: '1.0.0',
        scripts: {
          postinstall: { command: 'echo hello' },
        },
      }

      const result = isPostinstallConfigured(packageJson as any)

      assert.equal(result.configured, false)
      assert.equal(result.needsUpdate, true)
    })
  })
})

describe('generateUpdatedPostinstall', () => {
  it('should create command for empty string', () => {
    const result = generateUpdatedPostinstall('')
    assert.equal(result, 'npx @socketsecurity/socket-patch apply')
  })

  it('should create command for whitespace-only string', () => {
    const result = generateUpdatedPostinstall('   \n\t  ')
    assert.equal(result, 'npx @socketsecurity/socket-patch apply')
  })

  it('should prepend to existing script', () => {
    const result = generateUpdatedPostinstall('echo "Hello"')
    assert.equal(
      result,
      'npx @socketsecurity/socket-patch apply && echo "Hello"',
    )
  })

  it('should preserve existing script with socket-patch', () => {
    const existing = 'socket-patch apply && echo "Done"'
    const result = generateUpdatedPostinstall(existing)
    assert.equal(result, existing, 'Should not modify if already present')
  })

  it('should preserve npx @socketsecurity/socket-patch apply', () => {
    const existing = 'npx @socketsecurity/socket-patch apply'
    const result = generateUpdatedPostinstall(existing)
    assert.equal(result, existing)
  })

  it('should prepend to script with socket apply (main CLI)', () => {
    const existing = 'socket apply'
    const result = generateUpdatedPostinstall(existing)
    assert.equal(
      result,
      'npx @socketsecurity/socket-patch apply && socket apply',
      'Should add socket-patch even if socket apply is present',
    )
  })
})

describe('updatePackageJsonContent', () => {
  it('should add scripts field when missing', () => {
    const content = JSON.stringify({
      name: 'test',
      version: '1.0.0',
    })

    const result = updatePackageJsonContent(content)

    assert.equal(result.modified, true)
    const updated = JSON.parse(result.content)
    assert.ok(updated.scripts)
    assert.equal(
      updated.scripts.postinstall,
      'npx @socketsecurity/socket-patch apply',
    )
  })

  it('should add postinstall to existing scripts', () => {
    const content = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: {
        test: 'jest',
        build: 'tsc',
      },
    })

    const result = updatePackageJsonContent(content)

    assert.equal(result.modified, true)
    const updated = JSON.parse(result.content)
    assert.equal(
      updated.scripts.postinstall,
      'npx @socketsecurity/socket-patch apply',
    )
    assert.equal(updated.scripts.test, 'jest', 'Should preserve other scripts')
    assert.equal(updated.scripts.build, 'tsc', 'Should preserve other scripts')
  })

  it('should prepend to existing postinstall', () => {
    const content = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: {
        postinstall: 'echo "Setup complete"',
      },
    })

    const result = updatePackageJsonContent(content)

    assert.equal(result.modified, true)
    assert.equal(result.oldScript, 'echo "Setup complete"')
    assert.equal(
      result.newScript,
      'npx @socketsecurity/socket-patch apply && echo "Setup complete"',
    )
  })

  it('should not modify when already configured', () => {
    const content = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: {
        postinstall: 'npx @socketsecurity/socket-patch apply',
      },
    })

    const result = updatePackageJsonContent(content)

    assert.equal(result.modified, false)
    assert.equal(result.content, content)
  })

  it('should throw error for invalid JSON', () => {
    const content = '{ invalid json }'

    assert.throws(
      () => updatePackageJsonContent(content),
      /Invalid package\.json/,
    )
  })

  it('should handle empty postinstall by replacing it', () => {
    const content = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: {
        postinstall: '',
      },
    })

    const result = updatePackageJsonContent(content)

    assert.equal(result.modified, true)
    const updated = JSON.parse(result.content)
    assert.equal(
      updated.scripts.postinstall,
      'npx @socketsecurity/socket-patch apply',
    )
  })

  it('should handle whitespace-only postinstall', () => {
    const content = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: {
        postinstall: '   \n\t   ',
      },
    })

    const result = updatePackageJsonContent(content)

    assert.equal(result.modified, true)
    const updated = JSON.parse(result.content)
    assert.equal(
      updated.scripts.postinstall,
      'npx @socketsecurity/socket-patch apply',
    )
  })

  it('should preserve JSON formatting', () => {
    const content = JSON.stringify(
      {
        name: 'test',
        version: '1.0.0',
      },
      null,
      2,
    )

    const result = updatePackageJsonContent(content)

    assert.equal(result.modified, true)
    // Check that formatting is preserved (2 space indent)
    assert.ok(result.content.includes('  "name"'))
    assert.ok(result.content.includes('  "scripts"'))
  })
})
