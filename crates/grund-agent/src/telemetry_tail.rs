use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

use crate::{runtime::LogSource, telemetry_spool::Cursor};

pub(super) const MAX_LINE: usize = 8 * 1024;
const READ_PER_STREAM: usize = 64 * 1024;

pub(super) struct Line {
    pub body: String,
    pub truncated: bool,
    pub cursor: Cursor,
}

struct Pattern {
    bytes: Vec<u8>,
    prefix: Vec<usize>,
}

impl Pattern {
    fn new(bytes: Vec<u8>) -> Self {
        let mut prefix = vec![0; bytes.len()];
        for i in 1..bytes.len() {
            let mut n = prefix[i - 1];
            while n > 0 && bytes[i] != bytes[n] {
                n = prefix[n - 1];
            }
            if bytes[i] == bytes[n] {
                n += 1;
            }
            prefix[i] = n;
        }
        Self { bytes, prefix }
    }

    fn mask(&self, bytes: &[u8], mask: &mut [bool], reverse: bool) {
        let mut matched = 0;
        for i in 0..bytes.len() {
            let b = bytes[if reverse { bytes.len() - 1 - i } else { i }];
            while matched > 0 && b != self.bytes[matched] {
                matched = self.prefix[matched - 1];
            }
            if b == self.bytes[matched] {
                matched += 1;
            }
            if matched == self.bytes.len() {
                for index in i + 1 - matched..=i {
                    mask[if reverse {
                        bytes.len() - 1 - index
                    } else {
                        index
                    }] = true;
                }
                matched = self.prefix[matched - 1];
            }
        }
        for index in bytes.len() - matched..bytes.len() {
            mask[if reverse {
                bytes.len() - 1 - index
            } else {
                index
            }] = true;
        }
    }
}

pub(super) struct Redactor(Vec<(Pattern, Pattern)>);

impl Redactor {
    pub(super) fn new(values: &[crate::secrets::Cached]) -> Self {
        Self(
            values
                .iter()
                .filter(|secret| !secret.value.is_empty())
                .map(|secret| {
                    (
                        Pattern::new(secret.value.clone()),
                        Pattern::new(secret.value.iter().rev().copied().collect()),
                    )
                })
                .collect(),
        )
    }

    fn redact(&self, bytes: &[u8]) -> (String, bool) {
        let mut mask = vec![false; bytes.len()];
        for (forward, reverse) in &self.0 {
            forward.mask(bytes, &mut mask, false);
            reverse.mask(bytes, &mut mask, true);
        }
        let mut clean = Vec::with_capacity(bytes.len());
        let mut redacting = false;
        for (byte, masked) in bytes.iter().zip(mask) {
            if masked {
                if !redacting {
                    clean.extend_from_slice(b"[REDACTED]");
                }
            } else {
                clean.push(*byte);
            }
            redacting = masked;
        }
        let mut body = String::from_utf8_lossy(&clean).replace('\0', "\u{fffd}");
        let truncated = body.len() > MAX_LINE;
        if truncated {
            let mut end = MAX_LINE;
            while !body.is_char_boundary(end) {
                end -= 1;
            }
            body.truncate(end);
        }
        (body, truncated)
    }
}

pub(super) fn read(
    source: &LogSource,
    mut cursor: Cursor,
    redactor: &Redactor,
) -> anyhow::Result<(Vec<Line>, Cursor, u64)> {
    let mut files = Vec::with_capacity(source.paths.len());
    for path in &source.paths {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if metadata.is_file() {
            files.push((file, metadata));
        }
    }
    let at = files.iter().position(|(_, metadata)| {
        metadata.dev() == cursor.device && metadata.ino() == cursor.inode
    });
    let mut dropped = u64::from(cursor.inode != 0 && at.is_none());
    let mut lines = Vec::new();
    let mut remaining = READ_PER_STREAM;
    for (mut file, metadata) in files.into_iter().skip(at.unwrap_or(0)) {
        if cursor.device != metadata.dev() || cursor.inode != metadata.ino() {
            cursor.device = metadata.dev();
            cursor.inode = metadata.ino();
            cursor.offset = 0;
            cursor.resetting = false;
        }
        if cursor.offset > metadata.len() {
            cursor.offset = 0;
            cursor.skipping = false;
            dropped += 1;
        }
        file.seek(SeekFrom::Start(cursor.offset))?;
        let length = remaining.min(
            metadata
                .len()
                .saturating_sub(cursor.offset)
                .min(READ_PER_STREAM as u64) as usize,
        );
        let mut bytes = Vec::with_capacity(length);
        file.take(length as u64).read_to_end(&mut bytes)?;
        let count = bytes.len();
        remaining -= count;
        let mut start = 0;
        while start < bytes.len() {
            let end = bytes[start..]
                .iter()
                .position(|b| *b == b'\n')
                .map(|n| start + n);
            let boundary = end.unwrap_or(bytes.len());
            let length = boundary - start;
            if cursor.skipping {
                cursor.offset += (length + usize::from(end.is_some())) as u64;
                cursor.skipping = end.is_none();
            } else {
                let take = length.min(MAX_LINE);
                let (body, expanded) = redactor.redact(&bytes[start..start + take]);
                let truncated =
                    expanded || length > MAX_LINE || (end.is_none() && length == MAX_LINE);
                cursor.offset += (length + usize::from(end.is_some())) as u64;
                cursor.skipping = end.is_none() && length >= MAX_LINE;
                lines.push(Line {
                    body,
                    truncated,
                    cursor: cursor.clone(),
                });
            }
            start = boundary + usize::from(end.is_some());
            if lines.len() >= 128 {
                return Ok((lines, cursor, dropped));
            }
        }
        if remaining == 0 {
            break;
        }
    }
    Ok((lines, cursor, dropped))
}

pub(super) fn read_final(
    source: &LogSource,
    cursor: Cursor,
    redactor: &Redactor,
) -> anyhow::Result<(Vec<Line>, Cursor, u64)> {
    let mut files = Vec::new();
    for path in &source.paths {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if metadata.is_file() {
            files.push((file, metadata));
        }
    }
    let at = files
        .iter()
        .position(|(_, m)| m.dev() == cursor.device && m.ino() == cursor.inode);
    let missing = cursor.inode != 0 && at.is_none();
    let mut final_cursor = cursor.clone();
    if let Some((_, metadata)) = files.last() {
        final_cursor = Cursor {
            device: metadata.dev(),
            inode: metadata.ino(),
            offset: metadata.len(),
            ..Default::default()
        };
    }
    let mut budget = READ_PER_STREAM;
    let mut selected = Vec::new();
    let mut discarded = missing;
    for (file, metadata) in files.into_iter().skip(at.unwrap_or(0)).rev() {
        let start = if metadata.dev() == cursor.device
            && metadata.ino() == cursor.inode
            && cursor.offset <= metadata.len()
        {
            cursor.offset
        } else {
            0
        };
        let available = metadata.len().saturating_sub(start);
        let count = available.min(budget as u64) as usize;
        if available > count as u64 {
            discarded = true;
        }
        if count != 0 {
            selected.push((file, metadata, count));
            budget -= count;
        }
    }
    selected.reverse();
    let mut bytes = Vec::with_capacity(READ_PER_STREAM - budget);
    let mut positions = Vec::with_capacity(selected.len());
    for (mut file, metadata, count) in selected {
        let offset = metadata.len() - count as u64;
        file.seek(SeekFrom::Start(offset))?;
        let begin = bytes.len();
        file.take(count as u64).read_to_end(&mut bytes)?;
        positions.push((begin, bytes.len(), metadata.dev(), metadata.ino(), offset));
    }
    let mut start = 0;
    let mut records = usize::from(bytes.last().is_some_and(|b| *b != b'\n'));
    for (index, byte) in bytes.iter().enumerate().rev() {
        if *byte == b'\n' {
            if records >= 128 {
                start = index + 1;
                discarded = true;
                break;
            }
            records += 1;
        }
    }
    let mut lines = Vec::new();
    while start < bytes.len() {
        let newline = bytes[start..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| start + n);
        let end = newline.unwrap_or(bytes.len());
        let next = end + usize::from(newline.is_some());
        let count = (end - start).min(MAX_LINE);
        let (body, expanded) = redactor.redact(&bytes[start..start + count]);
        let (begin, _, device, inode, offset) = positions
            .iter()
            .find(|(_, finish, _, _, _)| next <= *finish)
            .ok_or_else(|| anyhow::anyhow!("final app output offset is unavailable"))?;
        let record_cursor = Cursor {
            device: *device,
            inode: *inode,
            offset: *offset + (next - *begin) as u64,
            ..Default::default()
        };
        lines.push(Line {
            body,
            truncated: expanded
                || end - start > MAX_LINE
                || (lines.is_empty() && (discarded || cursor.skipping)),
            cursor: record_cursor,
        });
        start = next;
    }
    Ok((lines, final_cursor, u64::from(discarded)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor(value: &[u8]) -> Redactor {
        Redactor::new(&[crate::secrets::Cached {
            name: "secret".into(),
            version: 1,
            value: value.to_vec(),
        }])
    }

    #[test]
    fn secrets_are_removed_even_when_capture_or_poll_splits_the_value() {
        let redact = redactor(b"supersecret");
        assert_eq!(redact.redact(b"value=supersecret!").0, "value=[REDACTED]!");
        assert_eq!(redact.redact(b"value=super").0, "value=[REDACTED]");
        assert_eq!(redact.redact(b"secret!").0, "[REDACTED]!");
        let mut bytes = vec![b'x'; MAX_LINE - 5];
        bytes.extend_from_slice(b"supersecret");
        assert!(!redact.redact(&bytes[..MAX_LINE]).0.contains("super"));
        assert_eq!(redactor(b"aba").redact(b"ababa").0, "[REDACTED]");
    }

    #[test]
    fn invalid_utf8_and_long_unterminated_lines_are_bounded_and_rotation_resumes() {
        let root = std::env::temp_dir().join(format!("grund-tail-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let current = root.join("stdout.0");
        std::fs::write(&current, vec![255; MAX_LINE + 100]).unwrap();
        let source = LogSource {
            stream: "stdout",
            paths: vec![root.join("stdout.1"), current.clone()],
        };
        let (lines, cursor, _) = read(&source, Cursor::default(), &redactor(b"secret")).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].truncated);
        assert!(lines[0].body.len() <= MAX_LINE);
        std::fs::rename(&current, root.join("stdout.1")).unwrap();
        std::fs::write(&current, b"continuation\nnew-line\n").unwrap();
        let (lines, _, _) = read(&source, cursor, &redactor(b"secret")).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].body, "new-line");
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn an_exact_limit_unterminated_record_reports_the_possible_discarded_continuation() {
        use std::io::Write;
        let root = std::env::temp_dir().join(format!("grund-tail-limit-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("stdout.0");
        std::fs::write(&path, vec![b'x'; MAX_LINE]).unwrap();
        let source = LogSource {
            stream: "stdout",
            paths: vec![path.clone()],
        };
        let redactor = Redactor::new(&[]);
        let (lines, cursor, _) = read(&source, Cursor::default(), &redactor).unwrap();
        assert!(lines[0].truncated);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"discarded continuation\nnext\n")
            .unwrap();
        let (lines, _, _) = read(&source, cursor, &redactor).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].body, "next");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn final_drain_prioritizes_shutdown_output_and_reports_discarded_backlog() {
        let root = std::env::temp_dir().join(format!("grund-tail-final-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("stdout.0");
        let mut bytes = vec![b'x'; READ_PER_STREAM * 2];
        bytes.extend_from_slice(b"\n");
        for _ in 0..1000 {
            bytes.extend_from_slice(b"line\n");
        }
        bytes.extend_from_slice(b"shutdown\n");
        std::fs::write(&path, &bytes).unwrap();
        let source = LogSource {
            stream: "stdout",
            paths: vec![path],
        };
        let redactor = Redactor::new(&[]);
        let (lines, cursor, dropped) = read_final(&source, Cursor::default(), &redactor).unwrap();
        assert_eq!(lines.len(), 128);
        assert_eq!(lines.last().unwrap().body, "shutdown");
        assert!(dropped > 0);
        assert_eq!(cursor.offset, bytes.len() as u64);
        assert!(read_final(&source, cursor, &redactor).unwrap().0.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
