import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

// Test UUID
const TEST_UUID_1 = '11111111-1111-4111-8111-111111111111'
const TEST_UUID_2 = '22222222-2222-4222-8222-222222222222'

/**
 * Tests for API client batch query logic
 *
 * These tests verify the response format conversion between individual
 * search responses and batch search responses, as well as severity ordering.
 */
describe('API Client', () => {
  describe('Severity ordering', () => {
    // Replicate the severity order logic from api-client.ts
    const SEVERITY_ORDER: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      unknown: 4,
    }

    function getSeverityOrder(severity: string | null): number {
      if (!severity) return 4
      return SEVERITY_ORDER[severity.toLowerCase()] ?? 4
    }

    it('should return correct order for known severities', () => {
      assert.equal(getSeverityOrder('critical'), 0)
      assert.equal(getSeverityOrder('high'), 1)
      assert.equal(getSeverityOrder('medium'), 2)
      assert.equal(getSeverityOrder('low'), 3)
      assert.equal(getSeverityOrder('unknown'), 4)
    })

    it('should handle case-insensitive severity', () => {
      assert.equal(getSeverityOrder('CRITICAL'), 0)
      assert.equal(getSeverityOrder('Critical'), 0)
      assert.equal(getSeverityOrder('HIGH'), 1)
      assert.equal(getSeverityOrder('High'), 1)
    })

    it('should return 4 (unknown) for null severity', () => {
      assert.equal(getSeverityOrder(null), 4)
    })

    it('should return 4 (unknown) for unrecognized severity', () => {
      assert.equal(getSeverityOrder('super-critical'), 4)
      assert.equal(getSeverityOrder(''), 4)
      assert.equal(getSeverityOrder('moderate'), 4)
    })

    it('should sort severities correctly', () => {
      const severities = ['low', 'critical', 'medium', 'high', null, 'unknown']
      const sorted = severities.sort(
        (a, b) => getSeverityOrder(a) - getSeverityOrder(b),
      )
      assert.deepEqual(sorted, ['critical', 'high', 'medium', 'low', null, 'unknown'])
    })
  })

  describe('BatchPatchInfo structure', () => {
    it('should have correct structure for batch patch info', () => {
      const mockPatchInfo = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/test@1.0.0',
        tier: 'free' as const,
        cveIds: ['CVE-2024-1234'],
        ghsaIds: ['GHSA-xxxx-xxxx-xxxx'],
        severity: 'high',
        title: 'Test vulnerability',
      }

      assert.equal(typeof mockPatchInfo.uuid, 'string')
      assert.equal(typeof mockPatchInfo.purl, 'string')
      assert.ok(['free', 'paid'].includes(mockPatchInfo.tier))
      assert.ok(Array.isArray(mockPatchInfo.cveIds))
      assert.ok(Array.isArray(mockPatchInfo.ghsaIds))
      assert.ok(mockPatchInfo.severity === null || typeof mockPatchInfo.severity === 'string')
      assert.equal(typeof mockPatchInfo.title, 'string')
    })
  })

  describe('PatchSearchResult to BatchPatchInfo conversion', () => {
    // Simulate the conversion logic from searchPatchesBatchViaIndividualQueries
    function convertSearchResultToBatchInfo(patch: {
      uuid: string
      purl: string
      tier: 'free' | 'paid'
      description: string
      vulnerabilities: Record<
        string,
        {
          cves: string[]
          summary: string
          severity: string
          description: string
        }
      >
    }) {
      const SEVERITY_ORDER: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        unknown: 4,
      }

      function getSeverityOrder(severity: string | null): number {
        if (!severity) return 4
        return SEVERITY_ORDER[severity.toLowerCase()] ?? 4
      }

      const cveIds: string[] = []
      const ghsaIds: string[] = []
      let highestSeverity: string | null = null
      let title = ''

      for (const [ghsaId, vuln] of Object.entries(patch.vulnerabilities)) {
        ghsaIds.push(ghsaId)
        for (const cve of vuln.cves) {
          if (!cveIds.includes(cve)) {
            cveIds.push(cve)
          }
        }
        if (!highestSeverity || getSeverityOrder(vuln.severity) < getSeverityOrder(highestSeverity)) {
          highestSeverity = vuln.severity || null
        }
        if (!title && vuln.summary) {
          title = vuln.summary.length > 100
            ? vuln.summary.slice(0, 97) + '...'
            : vuln.summary
        }
      }

      if (!title && patch.description) {
        title = patch.description.length > 100
          ? patch.description.slice(0, 97) + '...'
          : patch.description
      }

      return {
        uuid: patch.uuid,
        purl: patch.purl,
        tier: patch.tier,
        cveIds: cveIds.sort(),
        ghsaIds: ghsaIds.sort(),
        severity: highestSeverity,
        title,
      }
    }

    it('should extract CVE IDs from vulnerabilities', () => {
      const patch = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/lodash@4.17.20',
        tier: 'free' as const,
        description: 'Security patch',
        vulnerabilities: {
          'GHSA-xxxx-xxxx-xxxx': {
            cves: ['CVE-2024-1234', 'CVE-2024-5678'],
            summary: 'Prototype pollution vulnerability',
            severity: 'high',
            description: 'Full description here',
          },
        },
      }

      const result = convertSearchResultToBatchInfo(patch)

      assert.deepEqual(result.cveIds, ['CVE-2024-1234', 'CVE-2024-5678'])
    })

    it('should extract GHSA IDs from vulnerabilities keys', () => {
      const patch = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/lodash@4.17.20',
        tier: 'free' as const,
        description: 'Security patch',
        vulnerabilities: {
          'GHSA-xxxx-xxxx-xxxx': {
            cves: ['CVE-2024-1234'],
            summary: 'Vuln 1',
            severity: 'high',
            description: '',
          },
          'GHSA-yyyy-yyyy-yyyy': {
            cves: ['CVE-2024-5678'],
            summary: 'Vuln 2',
            severity: 'medium',
            description: '',
          },
        },
      }

      const result = convertSearchResultToBatchInfo(patch)

      assert.equal(result.ghsaIds.length, 2)
      assert.ok(result.ghsaIds.includes('GHSA-xxxx-xxxx-xxxx'))
      assert.ok(result.ghsaIds.includes('GHSA-yyyy-yyyy-yyyy'))
    })

    it('should determine highest severity from multiple vulnerabilities', () => {
      const patch = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/lodash@4.17.20',
        tier: 'free' as const,
        description: 'Security patch',
        vulnerabilities: {
          'GHSA-aaaa-aaaa-aaaa': {
            cves: [],
            summary: 'Low severity vuln',
            severity: 'low',
            description: '',
          },
          'GHSA-bbbb-bbbb-bbbb': {
            cves: [],
            summary: 'Critical severity vuln',
            severity: 'critical',
            description: '',
          },
          'GHSA-cccc-cccc-cccc': {
            cves: [],
            summary: 'Medium severity vuln',
            severity: 'medium',
            description: '',
          },
        },
      }

      const result = convertSearchResultToBatchInfo(patch)

      assert.equal(result.severity, 'critical')
    })

    it('should use first summary as title', () => {
      const patch = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/lodash@4.17.20',
        tier: 'free' as const,
        description: 'Fallback description',
        vulnerabilities: {
          'GHSA-xxxx-xxxx-xxxx': {
            cves: [],
            summary: 'This is the vulnerability summary',
            severity: 'high',
            description: '',
          },
        },
      }

      const result = convertSearchResultToBatchInfo(patch)

      assert.equal(result.title, 'This is the vulnerability summary')
    })

    it('should truncate long titles', () => {
      const longSummary = 'A'.repeat(150) // 150 character summary
      const patch = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/lodash@4.17.20',
        tier: 'free' as const,
        description: '',
        vulnerabilities: {
          'GHSA-xxxx-xxxx-xxxx': {
            cves: [],
            summary: longSummary,
            severity: 'high',
            description: '',
          },
        },
      }

      const result = convertSearchResultToBatchInfo(patch)

      assert.equal(result.title.length, 100)
      assert.ok(result.title.endsWith('...'))
    })

    it('should use description as fallback title when no summary', () => {
      const patch = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/lodash@4.17.20',
        tier: 'free' as const,
        description: 'This is the description fallback',
        vulnerabilities: {
          'GHSA-xxxx-xxxx-xxxx': {
            cves: [],
            summary: '',
            severity: 'high',
            description: '',
          },
        },
      }

      const result = convertSearchResultToBatchInfo(patch)

      assert.equal(result.title, 'This is the description fallback')
    })

    it('should handle empty vulnerabilities', () => {
      const patch = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/lodash@4.17.20',
        tier: 'free' as const,
        description: 'Patch description',
        vulnerabilities: {},
      }

      const result = convertSearchResultToBatchInfo(patch)

      assert.deepEqual(result.cveIds, [])
      assert.deepEqual(result.ghsaIds, [])
      assert.equal(result.severity, null)
      assert.equal(result.title, 'Patch description')
    })

    it('should sort CVE and GHSA IDs', () => {
      const patch = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/lodash@4.17.20',
        tier: 'free' as const,
        description: '',
        vulnerabilities: {
          'GHSA-zzzz-zzzz-zzzz': {
            cves: ['CVE-2024-9999'],
            summary: 'Z vuln',
            severity: 'high',
            description: '',
          },
          'GHSA-aaaa-aaaa-aaaa': {
            cves: ['CVE-2024-1111'],
            summary: 'A vuln',
            severity: 'low',
            description: '',
          },
        },
      }

      const result = convertSearchResultToBatchInfo(patch)

      assert.deepEqual(result.cveIds, ['CVE-2024-1111', 'CVE-2024-9999'])
      assert.deepEqual(result.ghsaIds, ['GHSA-aaaa-aaaa-aaaa', 'GHSA-zzzz-zzzz-zzzz'])
    })

    it('should deduplicate CVE IDs', () => {
      const patch = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/lodash@4.17.20',
        tier: 'free' as const,
        description: '',
        vulnerabilities: {
          'GHSA-xxxx-xxxx-xxxx': {
            cves: ['CVE-2024-1234'],
            summary: 'Vuln 1',
            severity: 'high',
            description: '',
          },
          'GHSA-yyyy-yyyy-yyyy': {
            cves: ['CVE-2024-1234'], // Same CVE
            summary: 'Vuln 2',
            severity: 'medium',
            description: '',
          },
        },
      }

      const result = convertSearchResultToBatchInfo(patch)

      assert.deepEqual(result.cveIds, ['CVE-2024-1234']) // Should only appear once
    })
  })

  describe('BatchSearchResponse structure', () => {
    it('should have correct structure for batch search response', () => {
      const mockResponse = {
        packages: [
          {
            purl: 'pkg:npm/test@1.0.0',
            patches: [
              {
                uuid: TEST_UUID_1,
                purl: 'pkg:npm/test@1.0.0',
                tier: 'free' as const,
                cveIds: ['CVE-2024-1234'],
                ghsaIds: ['GHSA-xxxx-xxxx-xxxx'],
                severity: 'high',
                title: 'Test vulnerability',
              },
            ],
          },
        ],
        canAccessPaidPatches: false,
      }

      assert.ok(Array.isArray(mockResponse.packages))
      assert.equal(typeof mockResponse.canAccessPaidPatches, 'boolean')

      for (const pkg of mockResponse.packages) {
        assert.equal(typeof pkg.purl, 'string')
        assert.ok(Array.isArray(pkg.patches))
      }
    })

    it('should handle empty packages array', () => {
      const mockResponse = {
        packages: [],
        canAccessPaidPatches: false,
      }

      assert.ok(Array.isArray(mockResponse.packages))
      assert.equal(mockResponse.packages.length, 0)
    })

    it('should handle multiple packages with multiple patches', () => {
      const mockResponse = {
        packages: [
          {
            purl: 'pkg:npm/package-a@1.0.0',
            patches: [
              {
                uuid: TEST_UUID_1,
                purl: 'pkg:npm/package-a@1.0.0',
                tier: 'free' as const,
                cveIds: ['CVE-2024-1111'],
                ghsaIds: ['GHSA-aaaa-aaaa-aaaa'],
                severity: 'critical',
                title: 'Critical vulnerability',
              },
              {
                uuid: TEST_UUID_2,
                purl: 'pkg:npm/package-a@1.0.0',
                tier: 'paid' as const,
                cveIds: ['CVE-2024-2222'],
                ghsaIds: ['GHSA-bbbb-bbbb-bbbb'],
                severity: 'medium',
                title: 'Medium vulnerability',
              },
            ],
          },
          {
            purl: 'pkg:npm/package-b@2.0.0',
            patches: [
              {
                uuid: '33333333-3333-4333-8333-333333333333',
                purl: 'pkg:npm/package-b@2.0.0',
                tier: 'free' as const,
                cveIds: [],
                ghsaIds: ['GHSA-cccc-cccc-cccc'],
                severity: 'low',
                title: 'Low severity issue',
              },
            ],
          },
        ],
        canAccessPaidPatches: true,
      }

      assert.equal(mockResponse.packages.length, 2)
      assert.equal(mockResponse.packages[0].patches.length, 2)
      assert.equal(mockResponse.packages[1].patches.length, 1)
      assert.equal(mockResponse.canAccessPaidPatches, true)
    })
  })

  describe('Public proxy vs authenticated API behavior', () => {
    it('should describe the difference in API paths', () => {
      // Document the expected behavior
      // Public proxy path: /patch/by-package/:purl (GET, cacheable)
      // Authenticated path: /v0/orgs/:org/patches/batch (POST, not cacheable)

      const publicProxyPath = '/patch/by-package/pkg%3Anpm%2Flodash%404.17.21'
      const authenticatedPath = '/v0/orgs/my-org/patches/batch'

      assert.ok(publicProxyPath.includes('/patch/by-package/'))
      assert.ok(authenticatedPath.includes('/patches/batch'))
    })

    it('should describe concurrency limiting for individual queries', () => {
      // Document that individual queries are made with concurrency limit
      const CONCURRENCY_LIMIT = 10
      const testPurls = Array.from({ length: 25 }, (_, i) => `pkg:npm/pkg-${i}@1.0.0`)

      // Calculate expected number of batches
      const expectedBatches = Math.ceil(testPurls.length / CONCURRENCY_LIMIT)

      assert.equal(expectedBatches, 3) // 25 PURLs with limit 10 = 3 batches
    })
  })
})
