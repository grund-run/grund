use chrono::{DateTime, Utc};

pub fn ago(at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let seconds = (now - at).num_seconds().max(0);
    match seconds {
        0..60 => format!("{seconds} s ago"),
        60..3_600 => format!("{} m ago", seconds / 60),
        3_600..86_400 => format!("{} h ago", seconds / 3_600),
        86_400..2_592_000 => format!("{} d ago", seconds / 86_400),
        _ => at.format("%-d %b %Y").to_string(),
    }
}

pub fn display(value: &str, now: DateTime<Utc>) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|at| ago(at.with_timezone(&Utc), now))
        .unwrap_or_else(|_| "Not reported".to_owned())
}

pub fn absolute(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|at| {
            at.with_timezone(&Utc)
                .format("%-d %b %Y %H:%M:%S UTC")
                .to_string()
        })
        .unwrap_or_else(|_| "Not reported".to_owned())
}

pub fn date(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|at| at.with_timezone(&Utc).format("%-d %B %Y").to_string())
        .unwrap_or_else(|_| "Not reported".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_times_are_relative_and_old_times_are_dates() {
        let now = DateTime::parse_from_rfc3339("2026-10-06T12:00:00Z")
            .expect("a time")
            .with_timezone(&Utc);
        for (seconds, words) in [
            (12, "12 s ago"),
            (60, "1 m ago"),
            (7_200, "2 h ago"),
            (86_400, "1 d ago"),
            (40 * 86_400, "27 Aug 2026"),
        ] {
            assert_eq!(ago(now - chrono::Duration::seconds(seconds), now), words);
        }
        assert_eq!(display("", now), "Not reported");
    }
    #[test]
    fn billing_expiry_uses_the_utc_calendar_date() {
        assert_eq!(date("2027-01-01T00:00:00Z"), "1 January 2027");
        assert_eq!(date("2026-12-31T23:30:00-02:00"), "1 January 2027");
    }
}
