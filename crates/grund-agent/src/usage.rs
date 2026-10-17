use std::{
    fs::File,
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

use grund_proto::grund::agent::v1::MachineUsage;

pub(crate) struct Sampler {
    previous: Option<([u64; 8], Instant)>,
    ticks_per_second: Option<u64>,
}

impl Sampler {
    pub(crate) fn new() -> Self {
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        Self {
            previous: None,
            ticks_per_second: u64::try_from(ticks).ok().filter(|ticks| *ticks > 0),
        }
    }

    pub(crate) fn sample(&mut self, data_dir: &Path) -> MachineUsage {
        let mut buffer = [0; 8192];
        let counters = read_proc("/proc/stat", &mut buffer[..1024], cpu_counters);
        let now = Instant::now();
        let cpu_millis = self.observe_cpu(counters, now);
        let memory_used_bytes = read_proc("/proc/meminfo", &mut buffer, memory_used);
        let uptime_seconds = read_proc("/proc/uptime", &mut buffer[..128], uptime);
        let disk = rustix::fs::statvfs(data_dir)
            .ok()
            .and_then(|stat| disk_bytes(stat.f_blocks, stat.f_bfree, stat.f_frsize));
        let mut usage = MachineUsage {
            cpu_millis,
            memory_used_bytes,
            disk_used_bytes: disk.map(|(_, used)| used),
            disk_total_bytes: disk.map(|(total, _)| total),
            uptime_seconds,
            agent_revision: env!("GRUND_BUILD_REVISION").chars().take(64).collect(),
            ..Default::default()
        };
        let now = chrono::Utc::now();
        let sampled_at = usage.sampled_at.get_or_insert_default();
        sampled_at.seconds = now.timestamp();
        sampled_at.nanos = now.timestamp_subsec_nanos() as i32;
        usage
    }

    fn observe_cpu(&mut self, counters: Option<[u64; 8]>, now: Instant) -> Option<u32> {
        let Some(current) = counters else {
            self.previous = None;
            return None;
        };
        let (previous, sampled) = self.previous.replace((current, now))?;
        cpu_delta(
            previous,
            current,
            now.checked_duration_since(sampled)?,
            self.ticks_per_second?,
        )
    }
}

fn read_proc<T>(path: &str, buffer: &mut [u8], parse: fn(&str) -> Option<T>) -> Option<T> {
    read_bounded(File::open(path).ok()?, buffer, parse)
}

fn read_bounded<T>(
    mut file: impl Read,
    buffer: &mut [u8],
    parse: fn(&str) -> Option<T>,
) -> Option<T> {
    let mut length = 0;
    while length < buffer.len() {
        let count = file.read(&mut buffer[length..]).ok()?;
        if count == 0 {
            break;
        }
        length += count;
    }
    let text = std::str::from_utf8(&buffer[..length]).ok()?;
    let (complete, _) = text.rsplit_once('\n')?;
    parse(complete)
}

fn cpu_counters(text: &str) -> Option<[u64; 8]> {
    let mut fields = text.lines().next()?.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let mut counters = [0; 8];
    for counter in &mut counters {
        *counter = fields.next()?.parse().ok()?;
    }
    Some(counters)
}

fn cpu_delta(
    previous: [u64; 8],
    current: [u64; 8],
    elapsed: Duration,
    ticks_per_second: u64,
) -> Option<u32> {
    let mut busy = 0_u128;
    for (index, (current, previous)) in current.into_iter().zip(previous).enumerate() {
        let delta = current.checked_sub(previous)?;
        if index != 3 && index != 4 {
            busy = busy.checked_add(u128::from(delta))?;
        }
    }
    let divisor = u128::from(ticks_per_second).checked_mul(elapsed.as_nanos())?;
    let millis = busy.checked_mul(1_000_000_000_000)?.checked_div(divisor)?;
    u32::try_from(millis).ok()
}

fn memory_used(text: &str) -> Option<u64> {
    let mut total = None;
    let mut available = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let destination = match fields.next()? {
            "MemTotal:" => &mut total,
            "MemAvailable:" => &mut available,
            _ => continue,
        };
        let kib: u64 = fields.next()?.parse().ok()?;
        if fields.next()? != "kB" || fields.next().is_some() {
            return None;
        }
        *destination = Some(kib.checked_mul(1024)?);
        if total.is_some() && available.is_some() {
            break;
        }
    }
    total?.checked_sub(available?)
}

fn uptime(text: &str) -> Option<u64> {
    let value = text.split_whitespace().next()?;
    let (seconds, fraction) = value.split_once('.')?;
    if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    seconds.parse().ok()
}

fn disk_bytes(blocks: u64, free: u64, block_size: u64) -> Option<(u64, u64)> {
    if block_size == 0 {
        return None;
    }
    Some((
        blocks.checked_mul(block_size)?,
        blocks.checked_sub(free)?.checked_mul(block_size)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_counts_guest_time_once_and_excludes_idle_and_iowait() {
        let previous = cpu_counters("cpu 100 10 20 500 40 5 5 0 80 8").unwrap();
        let current = cpu_counters("cpu 200 20 40 900 90 10 10 10 160 16").unwrap();
        assert_eq!(
            cpu_delta(previous, current, Duration::from_secs(1), 100),
            Some(1500)
        );
    }

    #[test]
    fn cpu_is_unknown_until_two_consecutive_samples_can_be_compared() {
        let mut sampler = Sampler {
            previous: None,
            ticks_per_second: Some(100),
        };
        let now = Instant::now();
        assert_eq!(sampler.observe_cpu(Some([0; 8]), now), None);
        assert_eq!(
            sampler.observe_cpu(Some([0; 8]), now + Duration::from_secs(1)),
            Some(0)
        );
        assert_eq!(
            sampler.observe_cpu(None, now + Duration::from_secs(2)),
            None
        );
        assert_eq!(
            sampler.observe_cpu(Some([0; 8]), now + Duration::from_secs(3)),
            None
        );
    }

    #[test]
    fn bounded_reads_do_not_treat_truncated_lines_as_measurements() {
        let input = b"MemTotal: 1024 kB\nMemAvailable: 256 kB\n";
        let mut buffer = [0; 64];
        assert_eq!(
            read_bounded(&input[..], &mut buffer[..20], memory_used),
            None
        );
        assert_eq!(
            read_bounded(&input[..], &mut buffer, memory_used),
            Some(768 * 1024)
        );
        assert_eq!(
            read_bounded(&b"123.45 0.00\n"[..], &mut buffer[..6], uptime),
            None
        );
    }

    #[test]
    fn cpu_distinguishes_actual_idle_from_unusable_intervals() {
        let counters = [10; 8];
        assert_eq!(
            cpu_delta(counters, counters, Duration::from_secs(1), 100),
            Some(0)
        );
        assert_eq!(cpu_delta(counters, counters, Duration::ZERO, 100), None);
        assert_eq!(
            cpu_delta(counters, counters, Duration::from_secs(1), 0),
            None
        );
        assert_eq!(
            cpu_delta(counters, [0; 8], Duration::from_secs(1), 100),
            None
        );
        assert_eq!(cpu_counters("cpu 1 2 3"), None);
        assert_eq!(cpu_counters("cpu0 1 2 3 4 5 6 7 8"), None);
    }

    #[test]
    fn cpu_never_wraps_when_the_interval_or_counters_are_extreme() {
        assert_eq!(
            cpu_delta([0; 8], [u64::MAX; 8], Duration::from_nanos(1), 100),
            None
        );
        assert_eq!(cpu_delta([0; 8], [1; 8], Duration::MAX, u64::MAX), None);
    }

    #[test]
    fn memory_measures_total_minus_available_without_inventing_missing_values() {
        assert_eq!(
            memory_used("MemTotal: 1024 kB\nMemFree: 10 kB\nMemAvailable: 256 kB"),
            Some(768 * 1024)
        );
        assert_eq!(memory_used("MemTotal: 0 kB\nMemAvailable: 0 kB"), Some(0));
        assert_eq!(memory_used("MemTotal: 1024 kB\nMemFree: 256 kB"), None);
        assert_eq!(memory_used("MemTotal: 1 kB\nMemAvailable: 2 kB"), None);
        assert_eq!(memory_used("MemTotal: 1 MB\nMemAvailable: 0 kB"), None);
        assert_eq!(
            memory_used("MemTotal: 18446744073709551615 kB\nMemAvailable: 0 kB"),
            None
        );
    }

    #[test]
    fn disk_usage_includes_reserved_blocks_without_wrapping() {
        assert_eq!(disk_bytes(100, 40, 4096), Some((409600, 245760)));
        assert_eq!(disk_bytes(100, 100, 4096), Some((409600, 0)));
        assert_eq!(disk_bytes(1, 2, 4096), None);
        assert_eq!(disk_bytes(u64::MAX, 0, 4096), None);
        assert_eq!(disk_bytes(1, 0, 0), None);
    }

    #[test]
    fn uptime_truncates_fractional_seconds_but_rejects_bad_samples() {
        assert_eq!(uptime("123.99 456.00"), Some(123));
        assert_eq!(uptime("0.00 0.00"), Some(0));
        assert_eq!(uptime("-1.00 0.00"), None);
        assert_eq!(uptime("1.bad 0.00"), None);
    }
}
