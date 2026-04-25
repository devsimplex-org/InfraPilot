"use client";

import { useEffect, useRef, useState, useCallback } from "react";

export interface ScanRequest {
  action: "scan" | "sbom" | "both";
  images: Array<{
    image: string;
    image_digest?: string;
    image_tag?: string;
  }>;
}

export interface ScanProgress {
  type: "progress";
  image: string;
  stage: "queued" | "pulling" | "scanning" | "analyzing" | "complete" | "error";
  progress?: number; // 0-100
  message?: string;
}

export interface ScanResultMessage {
  type: "scan_result";
  image: string;
  scan_id: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_count: number;
  fixable_count: number;
  scan_duration_ms?: number;
}

export interface SBOMResultMessage {
  type: "sbom_result";
  image: string;
  sbom_id: string;
  total_packages: number;
  os_packages: number;
  library_packages: number;
}

export interface ErrorMessage {
  type: "error";
  image?: string;
  error: string;
  code?: string;
}

export interface CompleteMessage {
  type: "complete";
  total_images: number;
  successful: number;
  failed: number;
}

export type ScanMessage =
  | ScanProgress
  | ScanResultMessage
  | SBOMResultMessage
  | ErrorMessage
  | CompleteMessage;

export interface UseScanWebSocketOptions {
  onProgress?: (progress: ScanProgress) => void;
  onScanResult?: (result: ScanResultMessage) => void;
  onSBOMResult?: (result: SBOMResultMessage) => void;
  onError?: (error: ErrorMessage) => void;
  onComplete?: (complete: CompleteMessage) => void;
  onConnectionChange?: (connected: boolean) => void;
}

export interface UseScanWebSocketReturn {
  connected: boolean;
  connecting: boolean;
  error: string | null;
  connect: () => void;
  startScan: (request: ScanRequest) => void;
  disconnect: () => void;
}

export function useScanWebSocket(options: UseScanWebSocketOptions = {}): UseScanWebSocketReturn {
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
      wsUrl = apiBase.replace(/^http/, "ws").replace(/\/api\/v1$/, "") + "/api/v1/scans/ws";
    } else {
      // Relative URL - use current host
      const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      wsUrl = `${wsProtocol}//${window.location.host}/api/v1/scans/ws`;
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
          const message: ScanMessage = JSON.parse(event.data);

          switch (message.type) {
            case "progress":
              optionsRef.current.onProgress?.(message);
              break;
            case "scan_result":
              optionsRef.current.onScanResult?.(message);
              break;
            case "sbom_result":
              optionsRef.current.onSBOMResult?.(message);
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

        // Set error message if connection was never established
        if (!event.wasClean) {
          setError("WebSocket connection failed. The scan endpoint may not be available.");
        }
      };
    } catch (err) {
      setError("Failed to create WebSocket connection");
      setConnecting(false);
    }
  }, []); // No dependencies - stable function

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setConnected(false);
    setConnecting(false);
  }, []); // No dependencies - stable function

  const startScan = useCallback((request: ScanRequest) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      // Auto-connect if not connected
      connect();
      // Queue the scan request after connection
      let attempts = 0;
      const maxAttempts = 50; // 5 seconds max wait
      const checkAndSend = () => {
        attempts++;
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify(request));
        } else if (attempts < maxAttempts) {
          setTimeout(checkAndSend, 100);
        } else {
          optionsRef.current.onError?.({ type: "error", error: "Failed to connect to scan service" });
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
    startScan,
    disconnect,
  };
}
