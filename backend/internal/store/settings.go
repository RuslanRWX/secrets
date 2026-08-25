package store

import "context"

// Settings returns the installation row.
func (s *Store) Settings(ctx context.Context) (*Settings, error) {
	var out Settings
	err := s.pool.QueryRow(ctx,
		`SELECT initialized, instance_name, key_id, key_check FROM app_settings WHERE id = 1`,
	).Scan(&out.Initialized, &out.InstanceName, &out.KeyID, &out.KeyCheck)
	if err != nil {
		return nil, normalize(err)
	}

	return &out, nil
}

// MarkInitialized records the instance name and the master-key check value.
func (s *Store) MarkInitialized(ctx context.Context, instanceName, keyID string, keyCheck []byte) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE app_settings
		    SET initialized = TRUE, instance_name = $1, key_id = $2, key_check = $3, updated_at = now()
		  WHERE id = 1`,
		instanceName, keyID, keyCheck)

	return err
}
