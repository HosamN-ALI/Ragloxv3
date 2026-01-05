/**
 * E2E Workflow Tests for RAGLOX Frontend
 * Tests complete user workflows through the API
 */
import { describe, it, expect, beforeAll } from 'vitest';

const API_BASE = process.env.VITE_API_BASE_URL || 'http://localhost:8000';

describe('Complete Mission Workflow E2E', () => {
  let missionId: string;
  
  it('should complete full mission lifecycle: create → start → pause → resume → stop', async () => {
    // Step 1: Create Mission
    const createResponse = await fetch(`${API_BASE}/api/v1/missions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'E2E Test Mission',
        description: 'End-to-end workflow test',
        scope: ['192.168.1.0/24'],
        goals: ['reconnaissance', 'domain_admin'],
        constraints: { stealth: true }
      })
    });
    
    expect(createResponse.status).toBe(201);
    const createData = await createResponse.json();
    expect(createData.mission_id).toBeDefined();
    missionId = createData.mission_id;
    expect(createData.status).toBe('created');
    
    // Step 2: Start Mission
    const startResponse = await fetch(`${API_BASE}/api/v1/missions/${missionId}/start`, {
      method: 'POST'
    });
    
    expect(startResponse.status).toBe(200);
    const startData = await startResponse.json();
    expect(startData.status).toBe('running');
    
    // Step 3: Pause Mission
    const pauseResponse = await fetch(`${API_BASE}/api/v1/missions/${missionId}/pause`, {
      method: 'POST'
    });
    
    expect(pauseResponse.status).toBe(200);
    const pauseData = await pauseResponse.json();
    expect(pauseData.status).toBe('paused');
    
    // Step 4: Resume Mission
    const resumeResponse = await fetch(`${API_BASE}/api/v1/missions/${missionId}/resume`, {
      method: 'POST'
    });
    
    expect(resumeResponse.status).toBe(200);
    const resumeData = await resumeResponse.json();
    expect(resumeData.status).toBe('running');
    
    // Step 5: Stop Mission
    const stopResponse = await fetch(`${API_BASE}/api/v1/missions/${missionId}/stop`, {
      method: 'POST'
    });
    
    expect(stopResponse.status).toBe(200);
    const stopData = await stopResponse.json();
    expect(stopData.status).toBe('stopped');
    
    // Step 6: Verify final state
    const getResponse = await fetch(`${API_BASE}/api/v1/missions/${missionId}`);
    expect(getResponse.status).toBe(200);
    const finalData = await getResponse.json();
    expect(finalData.status).toBe('stopped');
  });
  
  it('should handle chat interaction during mission', async () => {
    // Create a new mission for chat test
    const createResponse = await fetch(`${API_BASE}/api/v1/missions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Chat E2E Test Mission',
        scope: ['10.0.0.0/24'],
        goals: ['reconnaissance']
      })
    });
    
    const { mission_id } = await createResponse.json();
    
    // Start mission
    await fetch(`${API_BASE}/api/v1/missions/${mission_id}/start`, {
      method: 'POST'
    });
    
    // Send multiple chat messages
    const messages = ['status', 'help', 'What is the current progress?'];
    
    for (const content of messages) {
      const chatResponse = await fetch(`${API_BASE}/api/v1/missions/${mission_id}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });
      
      expect(chatResponse.status).toBe(200);
      const chatData = await chatResponse.json();
      expect(chatData.id).toBeDefined();
      expect(chatData.content).toBeDefined();
    }
    
    // Verify chat history contains all messages
    const historyResponse = await fetch(`${API_BASE}/api/v1/missions/${mission_id}/chat`);
    expect(historyResponse.status).toBe(200);
    const history = await historyResponse.json();
    
    // Should have at least the messages we sent (plus responses)
    expect(history.length).toBeGreaterThanOrEqual(messages.length);
    
    // Cleanup
    await fetch(`${API_BASE}/api/v1/missions/${mission_id}/stop`, {
      method: 'POST'
    });
  });
  
  it('should handle approval workflow', async () => {
    // Create a mission
    const createResponse = await fetch(`${API_BASE}/api/v1/missions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Approval E2E Test Mission',
        scope: ['172.16.0.0/16'],
        goals: ['data_exfil']
      })
    });
    
    const { mission_id } = await createResponse.json();
    
    // Check pending approvals
    const approvalsResponse = await fetch(`${API_BASE}/api/v1/missions/${mission_id}/approvals`);
    expect(approvalsResponse.status).toBe(200);
    const approvals = await approvalsResponse.json();
    expect(Array.isArray(approvals)).toBe(true);
    
    // Cleanup
    await fetch(`${API_BASE}/api/v1/missions/${mission_id}/stop`, {
      method: 'POST'
    });
  });
});

describe('Knowledge Base Integration E2E', () => {
  it('should search and retrieve techniques', async () => {
    // Get stats first
    const statsResponse = await fetch(`${API_BASE}/api/v1/knowledge/stats`);
    expect(statsResponse.status).toBe(200);
    const stats = await statsResponse.json();
    expect(stats.total_techniques).toBeGreaterThan(0);
    
    // List techniques - API returns {items: [...]}
    const techniquesResponse = await fetch(`${API_BASE}/api/v1/knowledge/techniques?limit=5`);
    expect(techniquesResponse.status).toBe(200);
    const techniquesData = await techniquesResponse.json();
    expect(techniquesData.items).toBeDefined();
    expect(Array.isArray(techniquesData.items)).toBe(true);
    expect(techniquesData.items.length).toBeGreaterThan(0);
    
    // Get specific technique if available - use 'id' not 'technique_id'
    if (techniquesData.items.length > 0) {
      const techniqueId = techniquesData.items[0].id;
      const detailResponse = await fetch(`${API_BASE}/api/v1/knowledge/techniques/${techniqueId}`);
      expect(detailResponse.status).toBe(200);
      const detail = await detailResponse.json();
      expect(detail.id).toBe(techniqueId);
    }
  });
  
  it('should search modules by tactic', async () => {
    // API returns {items: [...]}
    const response = await fetch(`${API_BASE}/api/v1/knowledge/modules?tactic=TA0006&limit=10`);
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.items).toBeDefined();
    expect(Array.isArray(data.items)).toBe(true);
  });
  
  it('should retrieve nuclei templates by severity', async () => {
    // Test both: /nuclei/critical shortcut and /nuclei/severity/{severity} endpoint
    
    // Test critical shortcut endpoint
    const criticalResponse = await fetch(`${API_BASE}/api/v1/knowledge/nuclei/critical?limit=5`);
    expect(criticalResponse.status).toBe(200);
    const criticalData = await criticalResponse.json();
    expect(Array.isArray(criticalData)).toBe(true);
    
    // Test severity parameter endpoint for high
    const highResponse = await fetch(`${API_BASE}/api/v1/knowledge/nuclei/severity/high?limit=5`);
    expect(highResponse.status).toBe(200);
    const highData = await highResponse.json();
    expect(Array.isArray(highData)).toBe(true);
  });
});

describe('Error Handling E2E', () => {
  it('should handle invalid mission ID gracefully', async () => {
    const response = await fetch(`${API_BASE}/api/v1/missions/invalid-uuid`);
    expect(response.status).toBe(422);
  });
  
  it('should handle non-existent mission', async () => {
    const fakeUUID = '00000000-0000-0000-0000-000000000000';
    const response = await fetch(`${API_BASE}/api/v1/missions/${fakeUUID}`);
    expect(response.status).toBe(404);
  });
  
  it('should validate mission creation payload', async () => {
    // Missing required fields
    const response = await fetch(`${API_BASE}/api/v1/missions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    expect(response.status).toBe(422);
  });
  
  it('should validate chat message content', async () => {
    // Create a mission first
    const createResponse = await fetch(`${API_BASE}/api/v1/missions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Validation Test',
        scope: ['192.168.1.0/24'],
        goals: ['recon']
      })
    });
    
    const { mission_id } = await createResponse.json();
    
    // Empty content
    const emptyResponse = await fetch(`${API_BASE}/api/v1/missions/${mission_id}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: '' })
    });
    expect(emptyResponse.status).toBe(422);
    
    // Missing content
    const missingResponse = await fetch(`${API_BASE}/api/v1/missions/${mission_id}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    expect(missingResponse.status).toBe(422);
    
    // Cleanup
    await fetch(`${API_BASE}/api/v1/missions/${mission_id}/stop`, {
      method: 'POST'
    });
  });
});

describe('Concurrent Operations E2E', () => {
  it('should handle multiple missions simultaneously', async () => {
    const missionNames = ['Concurrent Mission 1', 'Concurrent Mission 2', 'Concurrent Mission 3'];
    
    // Create multiple missions in parallel
    const createPromises = missionNames.map(name => 
      fetch(`${API_BASE}/api/v1/missions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          scope: ['10.0.0.0/24'],
          goals: ['reconnaissance']
        })
      }).then(r => r.json())
    );
    
    const missions = await Promise.all(createPromises);
    expect(missions.length).toBe(3);
    
    // Start all missions in parallel
    const startPromises = missions.map(m => 
      fetch(`${API_BASE}/api/v1/missions/${m.mission_id}/start`, {
        method: 'POST'
      }).then(r => r.json())
    );
    
    const startResults = await Promise.all(startPromises);
    startResults.forEach(result => {
      expect(result.status).toBe('running');
    });
    
    // Stop all missions
    const stopPromises = missions.map(m => 
      fetch(`${API_BASE}/api/v1/missions/${m.mission_id}/stop`, {
        method: 'POST'
      })
    );
    
    await Promise.all(stopPromises);
    
    // List missions and verify they exist
    const listResponse = await fetch(`${API_BASE}/api/v1/missions`);
    expect(listResponse.status).toBe(200);
    const allMissions = await listResponse.json();
    expect(allMissions.length).toBeGreaterThanOrEqual(3);
  });
});
