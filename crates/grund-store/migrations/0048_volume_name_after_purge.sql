ALTER TABLE grund_volumes DROP CONSTRAINT grund_volumes_app_id_name_key;
CREATE UNIQUE INDEX grund_volumes_app_live_name_idx ON grund_volumes (app_id, name)
    WHERE status <> 'deleted';
