//! How an IP packet travels in QUIC datagrams (network.md §6.4).
//!
//! A packet that fits the path's datagram limit goes whole, behind a 1-byte
//! header. One that does not is split in two, each part behind a 4-byte
//! header (kind, a 16-bit fragment id, the part's index), and the receiver
//! puts the halves back together or drops them after 50 ms. `grund0`'s MTU
//! is 1280, and the smallest datagram limit seen is 1162 bytes (the relay),
//! so two parts are always enough.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use bytes::{BufMut, Bytes, BytesMut};

/// How long the first half of a split packet waits for the second.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_millis(50);

const WHOLE: u8 = 0;
const PART: u8 = 1;
const PART_HEADER: usize = 4;

/// Frames packets into datagrams for one connection.
#[derive(Debug, Default)]
pub struct Framer {
    next_id: u16,
}

impl Framer {
    /// The datagrams that carry `packet` when the path takes at most
    /// `max_datagram` bytes: one, two, or none when even two parts cannot
    /// hold it.
    pub fn frame(&mut self, packet: &[u8], max_datagram: usize) -> Vec<Bytes> {
        if packet.len() < max_datagram {
            let mut d = BytesMut::with_capacity(packet.len() + 1);
            d.put_u8(WHOLE);
            d.put_slice(packet);
            return vec![d.freeze()];
        }
        let room = max_datagram.saturating_sub(PART_HEADER);
        if room == 0 || packet.len() > room * 2 {
            return Vec::new();
        }
        self.next_id = self.next_id.wrapping_add(1);
        [&packet[..room], &packet[room..]]
            .into_iter()
            .enumerate()
            .map(|(index, part)| {
                let mut d = BytesMut::with_capacity(part.len() + PART_HEADER);
                d.put_u8(PART);
                d.put_u16(self.next_id);
                d.put_u8(index as u8);
                d.put_slice(part);
                d.freeze()
            })
            .collect()
    }
}

/// Puts packets back together from one connection's datagrams.
#[derive(Debug, Default)]
pub struct Reassembler {
    waiting: HashMap<u16, (Instant, [Option<Bytes>; 2])>,
    expired: u64,
}

impl Reassembler {
    /// The packet a datagram completes, if any. `now` is passed in so tests
    /// can control time.
    pub fn push(&mut self, datagram: Bytes, now: Instant) -> Option<Bytes> {
        match *datagram.first()? {
            WHOLE => Some(datagram.slice(1..)),
            PART if datagram.len() > PART_HEADER => {
                let before = self.waiting.len();
                self.waiting
                    .retain(|_, (t, _)| now.duration_since(*t) < REASSEMBLY_TIMEOUT);
                self.expired += (before - self.waiting.len()) as u64;
                let id = u16::from_be_bytes([datagram[1], datagram[2]]);
                let index = (datagram[3] & 1) as usize;
                let entry = self.waiting.entry(id).or_insert((now, [None, None]));
                entry.1[index] = Some(datagram.slice(PART_HEADER..));
                if let [Some(a), Some(b)] = &entry.1 {
                    let mut whole = BytesMut::with_capacity(a.len() + b.len());
                    whole.put_slice(a);
                    whole.put_slice(b);
                    self.waiting.remove(&id);
                    Some(whole.freeze())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// How many half packets were dropped because the other half was late.
    pub fn expired(&self) -> u64 {
        self.expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    #[test]
    fn a_packet_that_fits_goes_whole() {
        let p = packet(1000);
        let ds = Framer::default().frame(&p, 1414);
        assert_eq!(ds.len(), 1);
        assert_eq!(
            Reassembler::default()
                .push(ds[0].clone(), Instant::now())
                .unwrap(),
            p
        );
    }

    #[test]
    fn a_1280_byte_packet_on_the_relays_1162_byte_limit_is_split_and_rejoined() {
        let p = packet(1280);
        let ds = Framer::default().frame(&p, 1162);
        assert_eq!(ds.len(), 2);
        assert!(ds.iter().all(|d| d.len() <= 1162));
        let mut r = Reassembler::default();
        let now = Instant::now();
        assert!(r.push(ds[1].clone(), now).is_none());
        assert_eq!(r.push(ds[0].clone(), now).unwrap(), p);
    }

    #[test]
    fn a_late_half_is_dropped() {
        let ds = Framer::default().frame(&packet(1280), 1162);
        let mut r = Reassembler::default();
        let now = Instant::now();
        assert!(r.push(ds[0].clone(), now).is_none());
        let later = now + REASSEMBLY_TIMEOUT + Duration::from_millis(1);
        let other = Framer { next_id: 40 }.frame(&packet(1280), 1162);
        assert!(r.push(other[0].clone(), later).is_none());
        assert_eq!(r.expired(), 1);
        assert!(r.push(ds[1].clone(), later).is_none());
    }

    #[test]
    fn a_packet_too_big_for_two_parts_is_not_sent() {
        assert!(Framer::default().frame(&packet(3000), 1162).is_empty());
    }
}
