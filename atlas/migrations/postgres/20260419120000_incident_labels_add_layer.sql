-- Add `layer` column to incident_labels distinguishing DNS-level IOCs
-- from URL-level IOCs. See docs/zero-second-detection-eval.md for rationale:
-- URL-path IOCs (urlhaus, threatfox) cannot be reproduced by a DNS-layer
-- detector when the FQDN is an abuse-hosting domain (github.com, discord
-- CDN). Backfill existing rows accordingly.

ALTER TABLE incident_labels
    ADD COLUMN IF NOT EXISTS layer TEXT NOT NULL DEFAULT 'dns';

ALTER TABLE incident_labels
    DROP CONSTRAINT IF EXISTS incident_labels_layer_check;

ALTER TABLE incident_labels
    ADD CONSTRAINT incident_labels_layer_check CHECK (layer IN ('dns', 'url'));

UPDATE incident_labels
   SET layer = 'url'
 WHERE source IN ('urlhaus', 'threatfox')
   AND layer = 'dns';

CREATE INDEX IF NOT EXISTS idx_incident_labels_layer ON incident_labels (layer);
