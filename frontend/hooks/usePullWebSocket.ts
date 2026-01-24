"use client";

import { useEffect, useRef, useState, useCallback } from "react";

export interface PullRequest {
  agent_id: string;
  registry_id?: string;
  images: Array<{
    image: string;
  }>;
}

export interface PullProgress {
  type: "progress";
  image: string;
  status: "queued" | "pulling" | "extracting" | "complete" | "error";
  current?: number;
  total?: number;
  progress?: number; // 0-100
  layer?: string;
  message?: string;
}

export interface PullErrorMessage {
  type: "error";
  image?: string;
  error: string;
}

export interface PullCompleteMessage {
  type: "complete";
  total_images: number;
  successful: number;
  failed: number;
}

export type PullMessage = PullProgress | PullErrorMessage | PullCompleteMessage;

export interface UsePullWebSocketOptions {
  onProgress?: (progress: PullProgress) => void;
  onError?: (error: PullErrorMessage) => void;
  onComplete?: (complete: PullCompleteMessage) => void;
  onConnectionChange?: (connected: boolean) => void;
}

export interface UsePullWebSocketReturn {
  connected: boolean;
  connecting: boolean;
  error: string | null;
  connect: () => void;
  startPull: (request: PullRequest) => void;
  disconnect: () => void;
}

export function usePullWebSocket(options: UsePullWebSocketOptions = {}): UsePullWebSocketReturn {
  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const mountedRef = useRef(true);

  // Store callbacks in refs to avoid dependency issues
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const connect = useCallback(() => {
    // Don't connect if already connected or connecting
    if (wsRef.current?.readyState === WebSocket.OPEN || wsRef.current?.readyState === WebSocket.CONNECTING) {
      return;
    }

    setConnecting(true);
    setError(null);

    // Use the API base URL for WebSocket
    const apiBase = process.env.NEXT_PUBLIC_API_URL || "/api/v1";
    let wsUrl: string;

    if (apiBase.startsWith("http")) {
      // Absolute URL - convert to WebSocket
      wsUrl = apiBase.replace(/^http/, "ws").replace(/\/api\/v1$/, "") + "/api/v1/pulls/ws";
    } else {
      // Relative URL - use current host
      const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      wsUrl = `${wsProtocol}//${window.location.host}/api/v1/pulls/ws`;
    }

    const token = localStorage.getItem("access_token");
    if (token) {
      wsUrl += `?token=${encodeURIComponent(token)}`;
    }

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        setConnected(true);
        setConnecting(false);
        setError(null);
        optionsRef.current.onConnectionChange?.(true);
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;

        try {
          const message: PullMessage = JSON.parse(event.data);

          switch (message.type) {
            case "progress":
              optionsRef.current.onProgress?.(message);
              break;
            case "error":
              optionsRef.current.onError?.(message);
              break;
            case "complete":
              optionsRef.current.onComplete?.(message);
              break;
          }
        } catch (err) {
          console.error("Failed to parse WebSocket message:", err);
        }
      };

      ws.onerror = () => {
        if (!mountedRef.current) return;
        setConnecting(false);
      };

      ws.onclose = (event) => {
        if (!mountedRef.current) return;
        setConnected(false);
        setConnecting(false);
        wsRef.current = null;
        optionsRef.current.onConnectionChange?.(false);

        if (!event.wasClean) {
          setError("WebSocket connection failed. The pull endpoint may not be available.");
        }
      };
    } catch (err) {
      setError("Failed to create WebSocket connection");
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setConnected(false);
    setConnecting(false);
  }, []);

  const startPull = useCallback((request: PullRequest) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      // Auto-connect if not connected
      connect();
      // Queue the pull request after connection
      let attempts = 0;
      const maxAttempts = 50; // 5 seconds max wait
      const checkAndSend = () => {
        attempts++;
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify(request));
        } else if (attempts < maxAttempts) {
          setTimeout(checkAndSend, 100);
        } else {
          optionsRef.current.onError?.({ type: "error", error: "Failed to connect to pull service" });
        }
      };
      setTimeout(checkAndSend, 100);
      return;
    }

    wsRef.current.send(JSON.stringify(request));
  }, [connect]);

  // Cleanup on unmount
  useEffect(() => {
    mountedRef.current = true;

    return () => {
      mountedRef.current = false;
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, []);

  return {
    connected,
    connecting,
    error,
    connect,
    startPull,
    disconnect,
  };
}
