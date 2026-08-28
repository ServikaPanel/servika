-- The chain's decided level (warning or critical) is stored, not derived from
-- the confidence. The causality model decoupled the two: a chain reaches
-- critical on a causal link OR a full ordered kill chain of three or more
-- stages, so one confidence value can be either level (85 is critical for a
-- causal ordered two-stage chain, and a warning for an independent unordered
-- four-stage one). The list endpoint reads this column instead of recomputing a
-- level it cannot reconstruct from the stored stages and confidence.
ALTER TABLE av_chains
  ADD COLUMN level VARCHAR(16) NOT NULL DEFAULT 'warning' AFTER confidence;
