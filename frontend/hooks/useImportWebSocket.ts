"use client";

import { useEffect, useRef, useState, useCallback } from "react";

export interface ImportRequest {
  agent_id: string;
  container_id: string;
  method: "docker_secrets" | "env_vars";
  secrets: Record<string, string>;
}

export interface ImportProgress {
  type: "progress";
  step: "creating_secrets" | "preparing" | "stopping_container" | "recreating_container" | "starting_container" | "verifying";
  status: "pending" | "in_progress" | "complete" | "error";
  progress: number; // 0-100
  message?: string;
}

export interface ImportErrorMessage {
  type: "error";
  step?: string;
  error: string;
}

export interface ImportCompleteMessage {
  type: "complete";
  success: boolean;
  new_container_id?: string;
  secrets_count: number;
  message?: string;
}

export type ImportMessage = ImportProgress | ImportErrorMessage | ImportCompleteMessage;

export interface UseImportWebSocketOptions {
  onProgress?: (progress: ImportProgress) => void;
  onError?: (error: ImportErrorMessage) => void;
  onComplete?: (complete: ImportCompleteMessage) => void;
  onConnectionChange?: (connected: boolean) => void;
}

export interface UseImportWebSocketReturn {
  connected: boolean;
  connecting: boolean;
  error: string | null;
  connect: () => void;
  startImport: (request: ImportRequest) => void;
  disconnect: () => void;
}

export function useImportWebSocket(options: UseImportWebSocketOptions = {}): UseImportWebSocketReturn {
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
      wsUrl = apiBase.replace(/^http/, "ws").replace(/\/api\/v1$/, "") + "/api/v1/imports/ws";
    } else {
      // Relative URL - use current host
      const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      wsUrl = `${wsProtocol}//${window.location.host}/api/v1/imports/ws`;
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
          const message: ImportMessage = JSON.parse(event.data);

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
          setError("WebSocket connection failed. The import endpoint may not be available.");
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

  const startImport = useCallback((request: ImportRequest) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      // Auto-connect if not connected
      connect();
      // Queue the import request after connection
      let attempts = 0;
      const maxAttempts = 50; // 5 seconds max wait
      const checkAndSend = () => {
        attempts++;
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify(request));
        } else if (attempts < maxAttempts) {
          setTimeout(checkAndSend, 100);
        } else {
          optionsRef.current.onError?.({ type: "error", error: "Failed to connect to import service" });
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
    startImport,
    disconnect,
  };
}
