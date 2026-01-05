/**
 * RAGLOX Frontend API Integration Tests
 * These tests verify that the frontend can properly communicate with the backend API
 */

import { describe, it, expect, beforeAll } from 'vitest'

const API_BASE = 'http://localhost:8000'

describe('Backend API Health', () => {
  it('should return healthy status', async () => {
    const response = await fetch(`${API_BASE}/health`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.status).toBe('healthy')
  })

  it('should return API info from root endpoint', async () => {
    const response = await fetch(`${API_BASE}/`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.name).toBe('RAGLOX')
    expect(data.version).toBe('3.0.0')
  })
})

describe('Mission API', () => {
  let testMissionId: string

  it('should list missions', async () => {
    const response = await fetch(`${API_BASE}/api/v1/missions`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(Array.isArray(data)).toBe(true)
  })

  it('should create a new mission', async () => {
    const missionData = {
      name: 'Frontend Test Mission',
      description: 'Testing from frontend',
      scope: ['192.168.1.0/24'],
      goals: ['reconnaissance']
    }

    const response = await fetch(`${API_BASE}/api/v1/missions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(missionData)
    })
    
    expect(response.status).toBe(201)
    const data = await response.json()
    expect(data.mission_id).toBeDefined()
    expect(data.status).toBe('created')
    testMissionId = data.mission_id
  })

  it('should get mission details', async () => {
    if (!testMissionId) {
      console.log('Skipping - no mission ID')
      return
    }

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.mission_id).toBe(testMissionId)
    expect(data.name).toBe('Frontend Test Mission')
  })

  it('should start a mission', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/start`, {
      method: 'POST'
    })
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.status).toBe('running')
  })

  it('should pause a mission', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/pause`, {
      method: 'POST'
    })
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.status).toBe('paused')
  })

  it('should resume a mission', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/resume`, {
      method: 'POST'
    })
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.status).toBe('running')
  })

  it('should stop a mission', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/stop`, {
      method: 'POST'
    })
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.status).toBe('stopped')
  })
})

describe('Knowledge Base API', () => {
  it('should get knowledge stats', async () => {
    const response = await fetch(`${API_BASE}/api/v1/knowledge/stats`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.total_techniques).toBeGreaterThan(0)
    expect(data.total_rx_modules).toBeGreaterThan(0)
  })

  it('should list techniques', async () => {
    const response = await fetch(`${API_BASE}/api/v1/knowledge/techniques?limit=10`)
    expect(response.status).toBe(200)
    const data = await response.json()
    // Response is { items: [...] } format
    expect(data.items).toBeDefined()
    expect(Array.isArray(data.items)).toBe(true)
  })

  it('should list tactics', async () => {
    const response = await fetch(`${API_BASE}/api/v1/knowledge/tactics`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(Array.isArray(data)).toBe(true)
    expect(data.length).toBeGreaterThan(0)
  })

  it('should search modules', async () => {
    const response = await fetch(`${API_BASE}/api/v1/knowledge/search?q=credential&limit=10`)
    expect(response.status).toBe(200)
    const data = await response.json()
    // Response is an array directly
    expect(Array.isArray(data)).toBe(true)
  })
})

describe('Nuclei Templates API', () => {
  it('should list nuclei templates', async () => {
    const response = await fetch(`${API_BASE}/api/v1/knowledge/nuclei/templates?limit=10`)
    expect(response.status).toBe(200)
    const data = await response.json()
    // Response is { items: [...] } format
    expect(data.items).toBeDefined()
    expect(Array.isArray(data.items)).toBe(true)
  })

  it('should get critical templates', async () => {
    const response = await fetch(`${API_BASE}/api/v1/knowledge/nuclei/critical?limit=5`)
    expect(response.status).toBe(200)
    const data = await response.json()
    // Response is an array directly
    expect(Array.isArray(data)).toBe(true)
  })
})
