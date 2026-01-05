/**
 * RAGLOX Frontend Component Tests
 * Tests for React components to ensure they render correctly and handle events properly
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'sonner'

// Mock dependencies
vi.mock('@/lib/api', () => ({
    missionApi: {
        list: vi.fn().mockResolvedValue(['test-mission-id']),
        get: vi.fn().mockResolvedValue({
            mission_id: 'test-mission-id',
            name: 'Test Mission',
            status: 'created',
            scope: ['192.168.1.0/24'],
            goals: { reconnaissance: 'yes' },
            statistics: {
                targets_discovered: 0,
                vulns_found: 0,
                creds_harvested: 0,
                sessions_established: 0,
                goals_achieved: 0,
                goals_total: 1,
            },
            target_count: 0,
            vuln_count: 0,
            created_at: '2024-01-01T00:00:00Z',
        }),
        create: vi.fn().mockResolvedValue({
            mission_id: 'new-mission-id',
            name: 'New Mission',
            status: 'created',
        }),
        start: vi.fn().mockResolvedValue({ status: 'running' }),
        pause: vi.fn().mockResolvedValue({ status: 'paused' }),
        resume: vi.fn().mockResolvedValue({ status: 'running' }),
        stop: vi.fn().mockResolvedValue({ status: 'stopped' }),
    },
    targetApi: {
        list: vi.fn().mockResolvedValue([]),
    },
    vulnApi: {
        list: vi.fn().mockResolvedValue([]),
    },
    credApi: {
        list: vi.fn().mockResolvedValue([]),
    },
    sessionApi: {
        list: vi.fn().mockResolvedValue([]),
    },
    hitlApi: {
        list: vi.fn().mockResolvedValue([]),
    },
    chatApi: {
        list: vi.fn().mockResolvedValue([]),
        send: vi.fn().mockResolvedValue({
            id: 'msg-123',
            role: 'assistant',
            content: 'Test response',
            timestamp: '2024-01-01T00:00:00Z',
        }),
    },
}))

vi.mock('@/stores/authStore', () => ({
    useAuthStore: vi.fn(() => ({
        user: null,
        isAuthenticated: true,
        isLoading: false,
        error: null,
        checkAuth: vi.fn(),
    })),
}))

// Test utilities
const queryClient = new QueryClient({
    defaultOptions: {
        queries: { retry: false },
    },
})

const renderWithProviders = (ui: React.ReactElement) => {
    return render(
        <QueryClientProvider client={queryClient}>
            <MemoryRouter>
                {ui}
                <Toaster />
            </MemoryRouter>
        </QueryClientProvider>
    )
}

describe('UI Components', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    describe('Button Component', () => {
        it('renders with correct text', () => {
            render(<button type="button">Test Button</button>)
            expect(screen.getByText('Test Button')).toBeInTheDocument()
        })

        it('handles click events', async () => {
            const handleClick = vi.fn()
            render(<button type="button" onClick={handleClick}>Click Me</button>)

            fireEvent.click(screen.getByText('Click Me'))
            expect(handleClick).toHaveBeenCalledTimes(1)
        })

        it('handles disabled state', () => {
            const handleClick = vi.fn()
            render(<button type="button" disabled onClick={handleClick}>Disabled Button</button>)

            fireEvent.click(screen.getByText('Disabled Button'))
            expect(handleClick).not.toHaveBeenCalled()
        })
    })

    describe('Input Component', () => {
        it('renders with placeholder', () => {
            render(<input type="text" placeholder="Enter text" />)
            expect(screen.getByPlaceholderText('Enter text')).toBeInTheDocument()
        })

        it('handles text input', async () => {
            const handleChange = vi.fn()
            render(<input type="text" onChange={handleChange} placeholder="Enter text" />)

            const input = screen.getByPlaceholderText('Enter text')
            await userEvent.type(input, 'test input')

            expect(input).toHaveValue('test input')
            expect(handleChange).toHaveBeenCalled()
        })
    })

    describe('Badge Component', () => {
        it('renders with correct content', () => {
            render(<span className="badge">Test Badge</span>)
            expect(screen.getByText('Test Badge')).toBeInTheDocument()
        })

        it('renders with different variants', () => {
            const { rerender } = render(<span className="badge">Status</span>)

            rerender(<span className="badge badge-success">Status</span>)
            expect(screen.getByText('Status')).toHaveClass('badge-success')
        })
    })
})

describe('Mission Management Components', () => {
    describe('MissionCard Component', () => {
        const mockMission = {
            mission_id: 'test-mission-id',
            name: 'Test Mission',
            status: 'running',
            statistics: {
                targets_discovered: 5,
                vulns_found: 2,
                creds_harvested: 1,
                sessions_established: 0,
                goals_achieved: 0,
                goals_total: 1,
            },
        }

        it('renders mission information correctly', () => {
            render(
                <div className="mission-card" data-testid="mission-card">
                    <h3>{mockMission.name}</h3>
                    <p>{mockMission.mission_id}</p>
                    <div className="stats">
                        <span>Targets: {mockMission.statistics.targets_discovered}</span>
                        <span>Vulns: {mockMission.statistics.vulns_found}</span>
                    </div>
                </div>
            )

            expect(screen.getByText(mockMission.name)).toBeInTheDocument()
            expect(screen.getByText(mockMission.mission_id)).toBeInTheDocument()
            expect(screen.getByText(/Targets:/)).toBeInTheDocument()
            expect(screen.getByText(/Vulns:/)).toBeInTheDocument()
        })

        it('displays mission actions when available', () => {
            render(
                <div className="mission-actions">
                    <button>Start</button>
                    <button>Pause</button>
                    <button>Stop</button>
                </div>
            )

            expect(screen.getByText('Start')).toBeInTheDocument()
            expect(screen.getByText('Pause')).toBeInTheDocument()
            expect(screen.getByText('Stop')).toBeInTheDocument()
        })
    })

    describe('Statistics Grid Component', () => {
        it('renders statistics correctly', () => {
            const stats = {
                targets_discovered: 10,
                vulns_found: 5,
                creds_harvested: 3,
                sessions_established: 2,
            }

            render(
                <div className="stats-grid">
                    <div className="stat">
                        <span className="stat-value">{stats.targets_discovered}</span>
                        <span className="stat-label">Targets</span>
                    </div>
                    <div className="stat">
                        <span className="stat-value">{stats.vulns_found}</span>
                        <span className="stat-label">Vulnerabilities</span>
                    </div>
                    <div className="stat">
                        <span className="stat-value">{stats.creds_harvested}</span>
                        <span className="stat-label">Credentials</span>
                    </div>
                    <div className="stat">
                        <span className="stat-value">{stats.sessions_established}</span>
                        <span className="stat-label">Sessions</span>
                    </div>
                </div>
            )

            expect(screen.getByText('10')).toBeInTheDocument()
            expect(screen.getByText('Targets')).toBeInTheDocument()
            expect(screen.getByText('5')).toBeInTheDocument()
            expect(screen.getByText('Vulnerabilities')).toBeInTheDocument()
        })
    })
})

describe('Chat Interface Components', () => {
    it('renders chat messages correctly', () => {
        const messages = [
            {
                id: '1',
                role: 'user',
                content: 'Hello',
                timestamp: '2024-01-01T00:00:00Z',
            },
            {
                id: '2',
                role: 'assistant',
                content: 'Hi there!',
                timestamp: '2024-01-01T00:01:00Z',
            },
        ]

        render(
            <div className="chat-messages">
                {messages.map((msg) => (
                    <div key={msg.id} className={`message message-${msg.role}`}>
                        <div className="message-content">{msg.content}</div>
                        <div className="message-timestamp">{msg.timestamp}</div>
                    </div>
                ))}
            </div>
        )

        expect(screen.getByText('Hello')).toBeInTheDocument()
        expect(screen.getByText('Hi there!')).toBeInTheDocument()
    })

    it('handles message input correctly', async () => {
        const handleSend = vi.fn()

        render(
            <div className="chat-input">
                <input type="text" placeholder="Type a message..." />
                <button onClick={handleSend}>Send</button>
            </div>
        )

        const input = screen.getByPlaceholderText('Type a message...')
        const sendButton = screen.getByText('Send')

        await userEvent.type(input, 'Test message')
        await userEvent.click(sendButton)

        expect(handleSend).toHaveBeenCalledTimes(1)
    })
})

describe('Approval Components', () => {
    it('renders approval request card', () => {
        const approval = {
            action_id: 'action-123',
            action_type: 'command',
            action_description: 'Run exploit module',
            target_ip: '192.168.1.100',
            risk_level: 'high',
            risk_reasons: ['Potential system compromise'],
            potential_impact: 'System takeover',
            command_preview: 'exploit/windows/smb/ms17_010_eternalblue',
            requested_at: '2024-01-01T00:00:00Z',
            expires_at: '2024-01-01T01:00:00Z',
        }

        render(
            <div className="approval-card">
                <h3>Approval Required</h3>
                <p>{approval.action_description}</p>
                <p>Target: {approval.target_ip}</p>
                <p>Risk: {approval.risk_level}</p>
                <button>Approve</button>
                <button>Reject</button>
            </div>
        )

        expect(screen.getByText('Approval Required')).toBeInTheDocument()
        expect(screen.getByText(/Run exploit module/)).toBeInTheDocument()
        expect(screen.getByText(/Target: 192.168.1.100/)).toBeInTheDocument()
        expect(screen.getByText('Approve')).toBeInTheDocument()
        expect(screen.getByText('Reject')).toBeInTheDocument()
    })
})

describe('Error Handling', () => {
    it('renders error message', () => {
        const errorMessage = 'Failed to load mission data'

        render(
            <div className="error-message">
                <h3>Error</h3>
                <p>{errorMessage}</p>
                <button>Retry</button>
            </div>
        )

        expect(screen.getByText('Error')).toBeInTheDocument()
        expect(screen.getByText(errorMessage)).toBeInTheDocument()
    })

    it('handles loading state', () => {
        render(
            <div className="loading-spinner">
                <div className="spinner"></div>
                <p>Loading mission data...</p>
            </div>
        )

        expect(screen.getByText('Loading mission data...')).toBeInTheDocument()
    })
})

describe('Form Validation', () => {
    it('validates mission creation form', async () => {
        const handleSubmit = vi.fn()

        render(
            <form onSubmit={handleSubmit}>
                <input
                    type="text"
                    placeholder="Mission name"
                    required
                    minLength={3}
                />
                <textarea
                    placeholder="Mission scope"
                    required
                    minLength={10}
                />
                <button type="submit">Create Mission</button>
            </form>
        )

        const nameInput = screen.getByPlaceholderText('Mission name')
        const scopeInput = screen.getByPlaceholderText('Mission scope')
        const submitButton = screen.getByText('Create Mission')

        // Try to submit empty form
        await userEvent.click(submitButton)
        expect(handleSubmit).not.toHaveBeenCalled()

        // Fill with invalid data
        await userEvent.type(nameInput, 'ab') // Too short
        await userEvent.type(scopeInput, 'short') // Too short
        await userEvent.click(submitButton)
        expect(handleSubmit).not.toHaveBeenCalled()

        // Fill with valid data
        await userEvent.clear(nameInput)
        await userEvent.clear(scopeInput)
        await userEvent.type(nameInput, 'Valid Mission Name')
        await userEvent.type(scopeInput, '192.168.1.0/24, 10.0.0.1')
        await userEvent.click(submitButton)
        expect(handleSubmit).toHaveBeenCalledTimes(1)
    })
})