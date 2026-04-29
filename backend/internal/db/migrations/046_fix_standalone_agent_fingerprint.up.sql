-- Fix standalone agent: set fingerprint = 'standalone' where it is blank.
-- This ensures the embedded agent can send heartbeats via the fingerprint-based endpoint.
UPDATE agents
SET fingerprint = 'standalone'
WHERE id = '00000000-0000-0000-0000-000000000001'
  AND (fingerprint IS NULL OR fingerprint = '');
