-- Active TCP stream slots belong to a precise supervised reservation.
-- No TTL reaping: an unknown worker must retain its capacity until the
-- existing audited offline recovery protocol confirms all tunnels stopped.
ALTER TABLE bandwidth_reservations ADD COLUMN connection_cap INTEGER CHECK(connection_cap BETWEEN 1 AND 65536);
CREATE TABLE connection_slots (
    id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
    reservation_id TEXT NOT NULL REFERENCES bandwidth_reservations(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL DEFAULT(unixepoch())
) STRICT;
CREATE INDEX connection_slots_reservation ON connection_slots(reservation_id);
