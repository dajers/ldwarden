CREATE TABLE venue (
    venue_code VARCHAR(24) PRIMARY KEY,
    label VARCHAR(70) NOT NULL,
    listed BOOLEAN NOT NULL,
    next_slot VARCHAR(40)
);

CREATE TABLE reservation (
    reservation_id VARCHAR(36) PRIMARY KEY,
    organizer_id VARCHAR(48) NOT NULL,
    venue_code VARCHAR(24) NOT NULL REFERENCES venue(venue_code),
    title VARCHAR(80) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'CANCELLED'))
);
