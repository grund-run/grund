//! Shared, human-friendly progress for local installation and maintenance.

use std::{
    future::Future,
    io::Write,
    time::{Duration, Instant},
};

use indicatif::{ProgressBar, ProgressStyle};

use crate::{
    context::Ctx,
    error::{CliError, CliResult},
    output::Format,
};

/// Progress uses stderr; callers retain their single regular stdout result.
pub struct Progress {
    enabled: bool,
    animated: bool,
    color: bool,
    verbose: bool,
}

impl Progress {
    /// Animate only an attended text terminal, respecting `NO_COLOR`.
    pub fn new(ctx: &Ctx, yes: bool, verbose: bool) -> Self {
        Self::configured(ctx, yes, verbose, std::env::var_os("NO_COLOR").is_some())
    }

    fn configured(ctx: &Ctx, yes: bool, verbose: bool, no_color: bool) -> Self {
        let enabled = ctx.format == Format::Text;
        let animated = enabled && ctx.interactive && !yes;
        Self {
            enabled,
            animated,
            color: animated && !no_color,
            verbose,
        }
    }

    /// Await a real operation without changing its result or recovery guidance.
    /// `fix` is used only when the operation has no more specific error hint.
    /// Labels must be short, public descriptions, never credentials or subprocess output.
    pub async fn step<T>(
        &self,
        label: &str,
        fix: &str,
        future: impl Future<Output = CliResult<T>>,
    ) -> CliResult<T> {
        self.step_to(label, fix, future, &mut std::io::stderr())
            .await
    }

    async fn step_to<T>(
        &self,
        label: &str,
        fix: &str,
        future: impl Future<Output = CliResult<T>>,
        diagnostics: &mut impl Write,
    ) -> CliResult<T> {
        let started = Instant::now();
        let spinner = if self.animated {
            let bar = ProgressBar::new_spinner();
            bar.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner} {msg}")
                    .expect("the static progress template is valid")
                    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
            );
            bar.set_message(label.to_owned());
            bar.enable_steady_tick(Duration::from_millis(100));
            Some(bar)
        } else {
            None
        };
        let result = future.await.map_err(|mut error| {
            if self.enabled && error.hint.is_empty() {
                error.hint = fix.to_owned();
            }
            error
        });
        if self.enabled {
            let elapsed = started.elapsed().as_secs_f32();
            let (symbol, suffix, color) = if result.is_ok() {
                (if self.animated { "✓" } else { "OK" }, "", "32")
            } else {
                (if self.animated { "✗" } else { "FAIL" }, ": failed", "31")
            };
            let symbol = if self.color {
                format!("\x1b[{color}m{symbol}\x1b[0m")
            } else {
                symbol.to_owned()
            };
            let line = format!("{symbol} {label}{suffix} ({elapsed:.1}s)");
            if let Some(spinner) = spinner {
                spinner.set_style(
                    ProgressStyle::with_template("{msg}")
                        .expect("the static completion template is valid"),
                );
                spinner.finish_with_message(line);
            } else {
                let _ = writeln!(diagnostics, "{line}");
            }
            if let Err(error) = &result {
                if !error.hint.is_empty() {
                    let _ = writeln!(diagnostics, "Fix: {}", error.hint);
                }
                if self.verbose {
                    let _ = writeln!(diagnostics, "Details: {}", error.message);
                }
            }
            let _ = diagnostics.flush();
        }
        result
    }

    /// Keep structured errors exact, but hide technical text unless verbose.
    /// Specific recovery hints and stable error codes are always retained.
    pub fn failure(&self, mut error: CliError, label: &str, fix: &str) -> CliError {
        if self.enabled && !self.verbose {
            error.message = format!("{label} failed");
            error.reason.clear();
            if error.hint.is_empty() {
                error.hint = fix.to_owned();
            }
        }
        error
    }

    /// Render a final summary for `Output::with_text`, never print it separately.
    /// Values, including an owner setup link, occur only once in this result.
    pub fn summary(&self, title: &str, fields: &[(&str, &str)]) -> String {
        if !self.enabled {
            return String::new();
        }
        let mut lines = vec![title.to_owned()];
        for (label, value) in fields {
            lines.push(format!("{label}: {value}"));
        }
        if !self.animated {
            return format!("{}\n", lines.join("\n"));
        }
        let width = lines
            .iter()
            .flat_map(|line| line.lines())
            .map(|line| line.chars().count())
            .max()
            .unwrap_or(0);
        let mut text = format!("┌{}┐\n", "─".repeat(width + 2));
        for line in lines.iter().flat_map(|line| line.lines()) {
            text.push_str(&format!(
                "│ {line}{} │\n",
                " ".repeat(width - line.chars().count())
            ));
        }
        text.push_str(&format!("└{}┘\n", "─".repeat(width + 2)));
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{context::Global, error::Code};

    fn context(format: Format, interactive: bool) -> Ctx {
        Ctx {
            global: Global::default(),
            format,
            stdin: None,
            interactive,
        }
    }

    #[tokio::test]
    async fn structured_output_never_emits_progress_even_with_verbose_and_a_terminal() {
        for format in [Format::Json, Format::Yaml] {
            let progress = Progress::configured(&context(format, true), false, true, false);
            let mut diagnostics = Vec::new();
            progress
                .step_to(
                    "Checking release",
                    "Check connectivity.",
                    async { Ok(()) },
                    &mut diagnostics,
                )
                .await
                .unwrap();
            assert!(diagnostics.is_empty());
            let error = progress
                .step_to(
                    "Checking release",
                    "Check connectivity.",
                    async { Err::<(), _>(CliError::new(Code::Unavailable, "release unavailable")) },
                    &mut diagnostics,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, Code::Unavailable);
            assert!(error.hint.is_empty());
            assert!(diagnostics.is_empty());
        }
    }

    #[tokio::test]
    async fn only_verbose_text_exposes_technical_failure_details() {
        for verbose in [false, true] {
            let progress =
                Progress::configured(&context(Format::Text, false), true, verbose, false);
            let mut diagnostics = Vec::new();
            let result = progress
                .step_to(
                    "Checking server",
                    "Run sudo grund server doctor.",
                    async { Err::<(), _>(CliError::new(Code::Failed, "technical-check-detail")) },
                    &mut diagnostics,
                )
                .await;
            assert!(result.is_err());
            assert_eq!(
                String::from_utf8(diagnostics)
                    .unwrap()
                    .contains("technical-check-detail"),
                verbose
            );
        }
    }

    #[tokio::test]
    async fn unattended_steps_are_plain_and_do_not_expose_result_or_error_details() {
        for (interactive, yes) in [(false, false), (true, true)] {
            let progress =
                Progress::configured(&context(Format::Text, interactive), yes, false, false);
            let mut diagnostics = Vec::new();
            let secret = "https://localhost/setup?token=private";
            progress
                .step_to(
                    "Preparing server",
                    "Check Docker.",
                    async { Ok(secret) },
                    &mut diagnostics,
                )
                .await
                .unwrap();
            progress
                .step_to(
                    "Starting server",
                    "Run sudo systemctl start docker.",
                    async {
                        Err::<(), _>(CliError::new(
                            Code::Failed,
                            "technical private subprocess detail",
                        ))
                    },
                    &mut diagnostics,
                )
                .await
                .unwrap_err();
            let text = String::from_utf8(diagnostics).unwrap();
            assert!(text.is_ascii());
            assert!(!text.contains('\x1b'));
            assert!(!text.contains('\r'));
            assert!(!text.contains(secret));
            assert!(!text.contains("technical private"));
            assert!(text.contains("Run sudo systemctl start docker."));
        }
    }

    #[test]
    fn summaries_print_owner_capabilities_once_and_unattended_text_stays_plain() {
        let secret = "http://localhost:8080/setup?token=one-real-link";
        for interactive in [false, true] {
            let progress =
                Progress::configured(&context(Format::Text, interactive), false, false, true);
            let text = progress.summary(
                "grund is ready",
                &[("Open", secret), ("Next", "Create your owner account")],
            );
            assert_eq!(text.matches(secret).count(), 1);
            assert!(!text.contains('\x1b'));
            if !interactive {
                assert!(text.is_ascii());
            }
        }
    }

    #[test]
    fn concise_failures_preserve_recovery_and_structured_errors_keep_their_details() {
        let mut original = CliError::new(Code::Conflict, "technical filesystem diagnostic")
            .hint("Restore the complete backup before restarting.");
        original.reason = "underlying technical reason".to_owned();
        for format in [Format::Text, Format::Json, Format::Yaml] {
            for verbose in [false, true] {
                let progress = Progress::configured(&context(format, false), true, verbose, false);
                let error = progress.failure(original.clone(), "Server update", "Check Docker.");
                assert_eq!(error.code, original.code);
                assert_eq!(error.hint, original.hint);
                if format != Format::Text || verbose {
                    assert_eq!(error.json(), original.json());
                } else {
                    assert!(!error.text().contains("technical"));
                    assert!(error.text().contains(&original.hint));
                }
            }
        }
    }
}
