-- Add skip_scanning column to stacks table
ALTER TABLE stacks ADD COLUMN IF NOT EXISTS skip_scanning BOOLEAN DEFAULT FALSE;
