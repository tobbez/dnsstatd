DROP TABLE IF EXISTS dnsstatd_question;
DROP TABLE IF EXISTS dnsstatd_resource_record;
DROP TABLE IF EXISTS dnsstatd_response;

DROP TABLE IF EXISTS dnsstatd_failure;

/* One response packet */
CREATE TABLE dnsstatd_response (
	id BIGSERIAL PRIMARY KEY,

	hdrid INT,
	ts TIMESTAMP,
	rcode SMALLINT,
	aa BOOL,
	tc BOOL,
	rd BOOL,
	ra BOOL,

	client INET,
	server INET
);

/* Contains resource records from responses */
CREATE TABLE dnsstatd_resource_record (
	id BIGSERIAL PRIMARY KEY,
	response BIGINT NOT NULL REFERENCES dnsstatd_response (id) ON DELETE CASCADE,

	name TEXT,
	type INT,
	class INT,
	ttl BIGINT,
	rdata TEXT
);

/* Contains information from the question section in a responses */
CREATE TABLE dnsstatd_question (
	id BIGSERIAL PRIMARY KEY,
	response BIGINT NOT NULL REFERENCES dnsstatd_response (id) ON DELETE CASCADE,

	name TEXT,
	type INT,
	class INT
);

/* Used for logging packets that dnsstatd failed to parse */
CREATE TABLE dnsstatd_failure (
	id BIGSERIAL PRIMARY KEY,

	ts TIMESTAMP,
	error TEXT,
	packet TEXT
);
