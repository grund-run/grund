-- Domain setup observations outlive workers and page refreshes. DNS recovery
-- gets its own short lease, independent of the five-minute ACME attempt.
-- Existing CA retry deadlines remain a lower bound when DNS recovers.
CREATE FUNCTION grund_domain_setup_waiting() RETURNS jsonb
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT jsonb_agg(jsonb_build_object('name', name, 'state', 'waiting', 'detail', '',
                                      'checked_at', NULL, 'next_retry_at', NULL) ORDER BY step_order)
    FROM unnest(ARRAY['dns_record', 'edge_reachable', 'certificate_requested',
                      'challenge_passed', 'certificate_issued', 'serving_https'])
         WITH ORDINALITY AS names(name, step_order)
$$;

CREATE FUNCTION grund_domain_setup_step(steps jsonb, step_index integer, state text,
                                       detail text, checked_at timestamptz, next_retry_at timestamptz)
RETURNS jsonb LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT jsonb_set(steps, ARRAY[step_index::text],
        (steps -> step_index) || jsonb_build_object('state', state, 'detail', detail,
                      'checked_at', checked_at, 'next_retry_at', next_retry_at))
$$;

CREATE TABLE grund_domain_setup (
    organisation_id UUID NOT NULL,
    domain_id UUID PRIMARY KEY REFERENCES grund_domains(domain_id) ON DELETE CASCADE,
    generation UUID NOT NULL DEFAULT gen_random_uuid(),
    steps jsonb NOT NULL DEFAULT grund_domain_setup_waiting()
        CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) = 6),
    next_check_at timestamptz,
    requested bigint NOT NULL DEFAULT 0,
    leased_request bigint,
    leased_by UUID,
    leased_until timestamptz,
    recovery_pending boolean NOT NULL DEFAULT false,
    recovered_failure_at timestamptz,
    CHECK ((leased_by IS NULL) = (leased_until IS NULL))
);
CREATE INDEX grund_domain_setup_due_idx ON grund_domain_setup(next_check_at, organisation_id, domain_id)
    WHERE next_check_at IS NOT NULL;

ALTER TABLE grund_certificates ADD COLUMN retry_not_before timestamptz;
-- Old rows blended local backoff with Retry-After. Their existing deadline is
-- retained because the CA's part cannot be reconstructed safely.
UPDATE grund_certificates SET retry_not_before = next_attempt_at WHERE last_error IS NOT NULL;

INSERT INTO grund_domain_setup(organisation_id, domain_id, next_check_at, recovery_pending)
SELECT organisation_id, domain_id, CASE WHEN state = 'bound' THEN clock_timestamp() END, state = 'bound'
FROM grund_domains;

-- Historical orders establish that a request happened. A valid completed order
-- establishes issuance and CA authorization, not that HTTPS currently serves it.
UPDATE grund_domain_setup s SET steps = grund_domain_setup_step(s.steps, 2, 'done',
    'An existing certificate order was recorded.', o.requested_at, NULL)
FROM (SELECT subject, min(created_at) AS requested_at FROM grund_acme_orders GROUP BY subject) o
WHERE o.subject = 'domain:' || s.domain_id::text
  AND EXISTS (SELECT 1 FROM grund_domains d WHERE d.domain_id = s.domain_id AND d.state = 'bound');
UPDATE grund_domain_setup s SET steps = grund_domain_setup_step(
    grund_domain_setup_step(s.steps, 3, 'done', 'The CA completed an existing order.', o.finished_at, NULL),
    4, 'done', 'An issued certificate is stored.', o.finished_at, NULL)
FROM (SELECT subject, max(finished_at) AS finished_at FROM grund_acme_orders
      WHERE status = 'valid' GROUP BY subject) o
JOIN grund_certificates c ON c.subject = o.subject AND c.chain_pem IS NOT NULL
WHERE o.subject = 'domain:' || s.domain_id::text
  AND EXISTS (SELECT 1 FROM grund_domains d WHERE d.domain_id = s.domain_id AND d.state = 'bound');
UPDATE grund_domain_setup s SET steps = grund_domain_setup_step(s.steps, 3, 'failed',
    'The CA could not validate the domain on the last attempt.', c.updated_at, c.next_attempt_at)
FROM grund_certificates c
WHERE c.subject = 'domain:' || s.domain_id::text
  AND c.chain_pem IS NULL AND c.last_error = 'authorization_failed'
  AND EXISTS (SELECT 1 FROM grund_domains d WHERE d.domain_id = s.domain_id AND d.state = 'bound');

CREATE FUNCTION grund_domain_setup_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO grund_domain_setup(organisation_id, domain_id, next_check_at)
        VALUES (NEW.organisation_id, NEW.domain_id,
                CASE WHEN NEW.state = 'bound' THEN clock_timestamp() END);
    ELSIF NEW.state IS DISTINCT FROM OLD.state OR NEW.app_id IS DISTINCT FROM OLD.app_id THEN
        UPDATE grund_domain_setup SET generation = gen_random_uuid(), leased_by = NULL,
            leased_until = NULL, leased_request = NULL, recovery_pending = false,
            next_check_at = CASE WHEN NEW.state = 'bound' THEN clock_timestamp() END,
            steps = CASE WHEN NEW.state = 'bound' AND OLD.state = 'bound' THEN
                grund_domain_setup_step(grund_domain_setup_step(grund_domain_setup_step(steps,
                    0, 'waiting', '', NULL, NULL), 1, 'waiting', '', NULL, NULL),
                    5, 'waiting', '', NULL, NULL)
                ELSE grund_domain_setup_waiting() END
        WHERE domain_id = NEW.domain_id;
        IF NEW.state <> 'bound' THEN
            UPDATE grund_certificates SET leased_by = NULL, leased_until = NULL
            WHERE subject = 'domain:' || NEW.domain_id::text;
        END IF;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER grund_domain_setup_binding_trigger AFTER INSERT OR UPDATE OF state, app_id
    ON grund_domains FOR EACH ROW EXECUTE FUNCTION grund_domain_setup_binding();
