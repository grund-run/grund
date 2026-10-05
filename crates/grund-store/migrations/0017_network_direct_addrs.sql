-- Where a member is reached directly, as its agent last reported it
-- (grund-docs design/network.md §5.2, a member's direct_addrs): bound uplink
-- addresses and those address discovery found, as IP:port. They go into the
-- signed list while fresh, so a member reaches another without a relay.
-- direct_addrs_at is when they were last reported: addresses older than
-- grund's freshness window are left out of the list.
ALTER TABLE grund_network_slots ADD COLUMN direct_addrs TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE grund_network_slots ADD COLUMN direct_addrs_at TIMESTAMPTZ;
