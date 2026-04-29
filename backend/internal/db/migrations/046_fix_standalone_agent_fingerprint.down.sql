UPDATE agents
SET fingerprint = ''
WHERE id = '00000000-0000-0000-0000-000000000001'
  AND fingerprint = 'standalone';
