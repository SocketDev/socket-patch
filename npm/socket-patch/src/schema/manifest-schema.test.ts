import { describe, it } from 'node:test'
import * as assert from 'node:assert/strict'
import { PatchManifestSchema, PatchRecordSchema } from './manifest-schema.js'

describe('PatchManifestSchema', () => {
  it('should validate a well-formed manifest', () => {
    const manifest = {
      patches: {
        'npm:simplehttpserver@0.0.6': {
          uuid: '550e8400-e29b-41d4-a716-446655440000',
          exportedAt: '2024-01-01T00:00:00Z',
          files: {
            'node_modules/simplehttpserver/index.js': {
              beforeHash: 'abc123',
              afterHash: 'def456',
            },
          },
          vulnerabilities: {
            'GHSA-jrhj-2j3q-xf3v': {
              cves: ['CVE-2024-0001'],
              summary: 'Path traversal vulnerability',
              severity: 'high',
              description: 'Allows reading arbitrary files',
            },
          },
          description: 'Fix path traversal',
          license: 'MIT',
          tier: 'free',
        },
      },
    }

    const result = PatchManifestSchema.safeParse(manifest)
    assert.ok(result.success, 'Valid manifest should parse successfully')
    assert.equal(
      Object.keys(result.data.patches).length,
      1,
      'Should have one patch entry',
    )
  })

  it('should validate a manifest with multiple patches', () => {
    const manifest = {
      patches: {
        'npm:pkg-a@1.0.0': {
          uuid: '550e8400-e29b-41d4-a716-446655440001',
          exportedAt: '2024-01-01T00:00:00Z',
          files: {
            'node_modules/pkg-a/lib/index.js': {
              beforeHash: 'aaa',
              afterHash: 'bbb',
            },
          },
          vulnerabilities: {},
          description: 'Patch A',
          license: 'MIT',
          tier: 'free',
        },
        'npm:pkg-b@2.0.0': {
          uuid: '550e8400-e29b-41d4-a716-446655440002',
          exportedAt: '2024-02-01T00:00:00Z',
          files: {
            'node_modules/pkg-b/src/main.js': {
              beforeHash: 'ccc',
              afterHash: 'ddd',
            },
          },
          vulnerabilities: {
            'GHSA-xxxx-yyyy-zzzz': {
              cves: [],
              summary: 'Some vuln',
              severity: 'medium',
              description: 'A medium severity vulnerability',
            },
          },
          description: 'Patch B',
          license: 'Apache-2.0',
          tier: 'paid',
        },
      },
    }

    const result = PatchManifestSchema.safeParse(manifest)
    assert.ok(result.success, 'Multi-patch manifest should parse successfully')
    assert.equal(Object.keys(result.data.patches).length, 2)
  })

  it('should validate an empty manifest', () => {
    const manifest = { patches: {} }
    const result = PatchManifestSchema.safeParse(manifest)
    assert.ok(result.success, 'Empty patches should be valid')
  })

  it('should reject a manifest missing the patches field', () => {
    const result = PatchManifestSchema.safeParse({})
    assert.ok(!result.success, 'Missing patches should fail')
  })

  it('should reject a manifest with invalid patch record', () => {
    const manifest = {
      patches: {
        'npm:bad@1.0.0': {
          // missing uuid, exportedAt, files, vulnerabilities, description, license, tier
        },
      },
    }
    const result = PatchManifestSchema.safeParse(manifest)
    assert.ok(!result.success, 'Invalid patch record should fail')
  })

  it('should reject a patch with invalid uuid', () => {
    const record = {
      uuid: 'not-a-valid-uuid',
      exportedAt: '2024-01-01T00:00:00Z',
      files: {},
      vulnerabilities: {},
      description: 'Test',
      license: 'MIT',
      tier: 'free',
    }
    const result = PatchRecordSchema.safeParse(record)
    assert.ok(!result.success, 'Invalid UUID should fail')
  })

  it('should reject non-object input', () => {
    assert.ok(!PatchManifestSchema.safeParse(null).success)
    assert.ok(!PatchManifestSchema.safeParse('string').success)
    assert.ok(!PatchManifestSchema.safeParse(42).success)
    assert.ok(!PatchManifestSchema.safeParse([]).success)
  })
})
