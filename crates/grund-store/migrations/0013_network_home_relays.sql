-- The relay a member is homed on, as its agent last reported it
-- (grund-docs design/network.md §5.2, a member's relay_url). It goes into
-- the signed list, so peers dial the member through that one relay rather
-- than every relay grund runs. Only one of grund's own relays is kept;
-- NULL when the member reported none.
ALTER TABLE grund_network_slots ADD COLUMN home_relay_url TEXT COLLATE "C";
