CREATE TABLE client_contract_versions (
    contract TEXT PRIMARY KEY NOT NULL,
    installed_at_schema_version INTEGER NOT NULL CHECK (installed_at_schema_version = 7)
) STRICT;

INSERT INTO client_contract_versions (contract, installed_at_schema_version)
VALUES ('client-domain-v1', 7);

PRAGMA user_version = 7;
