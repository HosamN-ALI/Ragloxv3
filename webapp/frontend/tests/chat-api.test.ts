/**
 * RAGLOX Chat API Tests
 * Tests for chat and approval workflow endpoints
 */

import { describe, it, expect } from 'vitest'

const API_BASE = 'http://localhost:8000'

describe('Chat API', () => {
  let testMissionId: string

  // Create a mission for chat tests
  it('should create mission for chat testing', async () => {
    const missionData = {
      name: 'Chat Test Mission',
      scope: ['10.0.0.0/24'],
      goals: ['test']
    }

    const response = await fetch(`${API_BASE}/api/v1/missions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(missionData)
    })
    
    expect(response.status).toBe(201)
    const data = await response.json()
    testMissionId = data.mission_id
    expect(testMissionId).toBeDefined()
  })

  it('should send chat message', async () => {
    if (!testMissionId) return

    const chatData = {
      content: 'What is the mission status?'
    }

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(chatData)
    })
    
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.id).toBeDefined()
    expect(data.role).toBeDefined()
    expect(data.content).toBe('What is the mission status?')
  })

  it('should get chat history', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/chat`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(Array.isArray(data)).toBe(true)
  })

  it('should get chat history with limit', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/chat?limit=5`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(Array.isArray(data)).toBe(true)
    expect(data.length).toBeLessThanOrEqual(5)
  })

  it('should reject invalid chat message (empty content)', async () => {
    if (!testMissionId) return

    const chatData = {
      content: ''
    }

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(chatData)
    })
    
    expect(response.status).toBe(422)
  })
})

describe('Approvals API', () => {
  let testMissionId: string

  it('should create mission for approvals testing', async () => {
    const missionData = {
      name: 'Approvals Test Mission',
      scope: ['172.16.0.0/16'],
      goals: ['data_exfil']
    }

    const response = await fetch(`${API_BASE}/api/v1/missions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(missionData)
    })
    
    expect(response.status).toBe(201)
    const data = await response.json()
    testMissionId = data.mission_id
  })

  it('should list pending approvals (empty for new mission)', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/approvals`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(Array.isArray(data)).toBe(true)
    // New mission should have no pending approvals
    expect(data.length).toBe(0)
  })

  it('should return 404 for non-existent action approval', async () => {
    if (!testMissionId) return

    const fakeActionId = '00000000-0000-0000-0000-000000000001'
    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/approve/${fakeActionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_comment: 'Test approval' })
    })
    
    expect(response.status).toBe(404)
  })

  it('should return 404 for non-existent action rejection', async () => {
    if (!testMissionId) return

    const fakeActionId = '00000000-0000-0000-0000-000000000002'
    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/reject/${fakeActionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rejection_reason: 'Test rejection' })
    })
    
    expect(response.status).toBe(404)
  })
})

describe('Mission Data Endpoints', () => {
  let testMissionId: string

  it('should create mission for data testing', async () => {
    const missionData = {
      name: 'Data Test Mission',
      scope: ['192.168.100.0/24'],
      goals: ['reconnaissance']
    }

    const response = await fetch(`${API_BASE}/api/v1/missions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(missionData)
    })
    
    expect(response.status).toBe(201)
    const data = await response.json()
    testMissionId = data.mission_id
  })

  it('should list targets (empty for new mission)', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/targets`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(Array.isArray(data)).toBe(true)
  })

  it('should list vulnerabilities (empty for new mission)', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/vulnerabilities`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(Array.isArray(data)).toBe(true)
  })

  it('should list credentials (empty for new mission)', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/credentials`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(Array.isArray(data)).toBe(true)
  })

  it('should list sessions (empty for new mission)', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/sessions`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(Array.isArray(data)).toBe(true)
  })

  it('should get mission stats', async () => {
    if (!testMissionId) return

    const response = await fetch(`${API_BASE}/api/v1/missions/${testMissionId}/stats`)
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.targets_discovered).toBeDefined()
    expect(data.vulns_found).toBeDefined()
    expect(data.creds_harvested).toBeDefined()
  })
})
