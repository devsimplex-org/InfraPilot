-- Remove skip_scanning column from stacks table
ALTER TABLE stacks DROP COLUMN IF EXISTS skip_scanning;
