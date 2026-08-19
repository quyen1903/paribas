CREATE FUNCTION identity.enforce_identity_subject_binding_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
        OR NEW.actor_type IS DISTINCT FROM OLD.actor_type
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'identity subject bindings are immutable';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_identity_subject_binding_immutability
BEFORE UPDATE ON identity.identity_accounts
FOR EACH ROW
EXECUTE FUNCTION identity.enforce_identity_subject_binding_immutability();
