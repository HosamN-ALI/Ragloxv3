// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - WebSocket Hook
// Auto-reconnecting WebSocket connection management
// ═══════════════════════════════════════════════════════════════

import { useEffect, useRef, useCallback } from 'react'
import { useEventStore } from '@/stores/eventStore'
import type { WebSocketMessage } from '@/types'

const WS_URL = '/ws'
const INITIAL_RECONNECT_DELAY = 1000
const MAX_RECONNECT_DELAY = 30000
const RECONNECT_MULTIPLIER = 1.5
const PING_INTERVAL = 30000

interface UseWebSocketOptions {
  missionId?: string
  autoConnect?: boolean
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const { missionId, autoConnect = true } = options
  
  const wsRef = useRef<WebSocket | null>(null)
  const pingIntervalRef = useRef<number | null>(null)
  const reconnectTimeoutRef = useRef<number | null>(null)
  const reconnectDelayRef = useRef(INITIAL_RECONNECT_DELAY)
  const shouldReconnectRef = useRef(true)
  const isConnectingRef = useRef(false)
  
  const {
    wsState,
    setConnectionStatus,
    incrementReconnectAttempts,
    resetReconnectAttempts,
    processWebSocketMessage,
  } = useEventStore()
  
  // Build WebSocket URL
  const getWsUrl = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    
    // If missionId is provided, connect to mission-specific endpoint
    if (missionId) {
      return `${protocol}//${host}/ws/missions/${missionId}`
    }
    
    // Otherwise connect to global WebSocket
    return `${protocol}//${host}${WS_URL}`
  }, [missionId])
  
  // Clear ping interval
  const clearPingInterval = useCallback(() => {
    if (pingIntervalRef.current !== null) {
      clearInterval(pingIntervalRef.current)
      pingIntervalRef.current = null
    }
  }, [])
  
  // Clear reconnect timeout
  const clearReconnectTimeout = useCallback(() => {
    if (reconnectTimeoutRef.current !== null) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
  }, [])
  
  // Start ping interval
  const startPingInterval = useCallback(() => {
    clearPingInterval()
    pingIntervalRef.current = window.setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'ping' }))
      }
    }, PING_INTERVAL)
  }, [clearPingInterval])
  
  // Connect to WebSocket (declared as ref to avoid circular deps)
  const connectRef = useRef<() => void>(() => {})
  
  // Schedule reconnection
  const scheduleReconnect = useCallback(() => {
    if (!shouldReconnectRef.current) return
    
    setConnectionStatus('reconnecting')
    incrementReconnectAttempts()
    
    const delay = reconnectDelayRef.current
    console.log(`[WebSocket] Reconnecting in ${delay}ms...`)
    
    reconnectTimeoutRef.current = window.setTimeout(() => {
      connectRef.current()
    }, delay)
    
    // Increase delay for next attempt (exponential backoff)
    reconnectDelayRef.current = Math.min(
      reconnectDelayRef.current * RECONNECT_MULTIPLIER,
      MAX_RECONNECT_DELAY
    )
  }, [setConnectionStatus, incrementReconnectAttempts])
  
  // Connect to WebSocket
  const connect = useCallback(() => {
    // Prevent duplicate connections
    if (isConnectingRef.current || wsRef.current?.readyState === WebSocket.OPEN) {
      return
    }
    
    // Clean up existing connection
    if (wsRef.current) {
      wsRef.current.close()
    }
    
    isConnectingRef.current = true
    clearReconnectTimeout()
    setConnectionStatus('connecting')
    shouldReconnectRef.current = true
    
    const url = getWsUrl()
    console.log('[WebSocket] Connecting to:', url)
    
    const ws = new WebSocket(url)
    wsRef.current = ws
    
    ws.onopen = () => {
      console.log('[WebSocket] Connected')
      isConnectingRef.current = false
      setConnectionStatus('connected')
      resetReconnectAttempts()
      reconnectDelayRef.current = INITIAL_RECONNECT_DELAY
      startPingInterval()
    }
    
    ws.onmessage = (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data)
        processWebSocketMessage(message)
      } catch (err) {
        console.error('[WebSocket] Failed to parse message:', err)
      }
    }
    
    ws.onerror = (error) => {
      console.error('[WebSocket] Error:', error)
      isConnectingRef.current = false
      setConnectionStatus('disconnected', 'Connection error')
    }
    
    ws.onclose = (event) => {
      console.log('[WebSocket] Closed:', event.code, event.reason)
      isConnectingRef.current = false
      clearPingInterval()
      wsRef.current = null
      
      // Don't reconnect if intentionally closed (code 1000)
      if (event.code !== 1000 && shouldReconnectRef.current) {
        console.log('[WebSocket] Will attempt reconnection...')
        scheduleReconnect()
      } else {
        setConnectionStatus('disconnected')
      }
    }
  }, [
    getWsUrl,
    setConnectionStatus,
    resetReconnectAttempts,
    processWebSocketMessage,
    clearReconnectTimeout,
    clearPingInterval,
    startPingInterval,
    scheduleReconnect,
  ])
  
  // Update connectRef when connect changes
  useEffect(() => {
    connectRef.current = connect
  }, [connect])
  
  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    shouldReconnectRef.current = false
    clearReconnectTimeout()
    clearPingInterval()
    
    if (wsRef.current) {
      wsRef.current.close(1000, 'User disconnected')
      wsRef.current = null
    }
    
    setConnectionStatus('disconnected')
  }, [clearReconnectTimeout, clearPingInterval, setConnectionStatus])
  
  // Send message
  const send = useCallback((data: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
      return true
    }
    console.warn('[WebSocket] Cannot send - not connected')
    return false
  }, [])
  
  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect) {
      // Small delay to allow React StrictMode double-mount to settle
      const timer = setTimeout(() => {
        connect()
      }, 100)
      
      return () => {
        clearTimeout(timer)
        disconnect()
      }
    }
    
    return () => {
      disconnect()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoConnect])
  
  // Reconnect when missionId changes
  useEffect(() => {
    if (wsRef.current && missionId) {
      disconnect()
      connect()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [missionId])
  
  return {
    isConnected: wsState.status === 'connected',
    status: wsState.status,
    reconnectAttempts: wsState.reconnectAttempts,
    error: wsState.error,
    connect,
    disconnect,
    send,
  }
}
