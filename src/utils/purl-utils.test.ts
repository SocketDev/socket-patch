import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  stripPurlQualifiers,
  isPyPIPurl,
  isNpmPurl,
  parsePyPIPurl,
} from './purl-utils.js'

describe('purl-utils', () => {
  describe('stripPurlQualifiers', () => {
    it('should remove query string qualifiers', () => {
      assert.equal(
        stripPurlQualifiers('pkg:pypi/requests@2.28.0?artifact_id=abc'),
        'pkg:pypi/requests@2.28.0',
      )
    })

    it('should return unchanged if no qualifiers', () => {
      assert.equal(
        stripPurlQualifiers('pkg:pypi/requests@2.28.0'),
        'pkg:pypi/requests@2.28.0',
      )
    })
  })

  describe('isPyPIPurl', () => {
    it('should return true for pypi PURL', () => {
      assert.equal(isPyPIPurl('pkg:pypi/requests@2.28.0'), true)
    })

    it('should return false for npm PURL', () => {
      assert.equal(isPyPIPurl('pkg:npm/lodash@4.17.21'), false)
    })
  })

  describe('isNpmPurl', () => {
    it('should return true for npm PURL', () => {
      assert.equal(isNpmPurl('pkg:npm/@scope/pkg@1.0.0'), true)
    })

    it('should return false for pypi PURL', () => {
      assert.equal(isNpmPurl('pkg:pypi/requests@2.28.0'), false)
    })
  })

  describe('parsePyPIPurl', () => {
    it('should extract name and version', () => {
      const result = parsePyPIPurl('pkg:pypi/requests@2.28.0')
      assert.deepEqual(result, { name: 'requests', version: '2.28.0' })
    })

    it('should strip qualifiers first', () => {
      const result = parsePyPIPurl('pkg:pypi/requests@2.28.0?artifact_id=abc')
      assert.deepEqual(result, { name: 'requests', version: '2.28.0' })
    })

    it('should return null for npm PURL', () => {
      assert.equal(parsePyPIPurl('pkg:npm/lodash@4.17.21'), null)
    })

    it('should return null for PURL without version', () => {
      assert.equal(parsePyPIPurl('pkg:pypi/requests'), null)
    })
  })
})
