-- 3.3.5: normalize protocol identifiers in request_log and entry_hit_counters
-- Renames legacy protocol names to canonical identifiers:
--   dot → tls, doq → quic, doh → https, doh3 → http3, dod → dtls, doh-tlcp → http-tlcp

UPDATE request_log SET protocol = 'tls'        WHERE protocol = 'dot';
UPDATE request_log SET protocol = 'quic'       WHERE protocol = 'doq';
UPDATE request_log SET protocol = 'https'      WHERE protocol = 'doh';
UPDATE request_log SET protocol = 'http3'      WHERE protocol = 'doh3';
UPDATE request_log SET protocol = 'dtls'       WHERE protocol = 'dod';
UPDATE request_log SET protocol = 'http-tlcp'  WHERE protocol = 'doh-tlcp';

UPDATE entry_hit_counters SET protocol = 'tls'        WHERE protocol = 'dot';
UPDATE entry_hit_counters SET protocol = 'quic'       WHERE protocol = 'doq';
UPDATE entry_hit_counters SET protocol = 'https'      WHERE protocol = 'doh';
UPDATE entry_hit_counters SET protocol = 'http3'      WHERE protocol = 'doh3';
UPDATE entry_hit_counters SET protocol = 'dtls'       WHERE protocol = 'dod';
UPDATE entry_hit_counters SET protocol = 'http-tlcp'  WHERE protocol = 'doh-tlcp';
