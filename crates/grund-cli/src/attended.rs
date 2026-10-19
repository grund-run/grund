//! Help on a terminal (grund-docs design/cli-redesign.md §18): when a
//! person at a terminal leaves out a name a command needs, grund lists the
//! candidates and lets them pick one. The command definitions do not change:
//! scripts, `--json` and pipes get the usage error they always got.

use std::io::IsTerminal;

use ratatui::{
    Terminal, TerminalOptions, Viewport,
    backend::CrosstermBackend,
    crossterm::{
        event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
        terminal,
    },
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::Line,
    widgets::{Gauge, List, ListItem, ListState, Paragraph},
};
use serde_json::{Value, json};

use crate::{
    context::{Ctx, Global},
    credentials,
};

/// Whether a person is at the terminal: stdin and stderr are terminals,
/// the output is text, and neither CI nor GRUND_NO_INPUT is set.
pub fn attended(args: &[String]) -> bool {
    let json = args.iter().enumerate().any(|(i, a)| {
        a == "--json"
            || a.starts_with("--output=")
            || a.starts_with("-o") && a.len() > 2
            || (a == "-o" || a == "--output") && args.get(i + 1).is_some()
    }) || std::env::var("GRUND_OUTPUT").is_ok_and(|v| !v.is_empty() && v != "text");
    !json
        && std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal()
        && std::env::var_os("CI").is_none()
        && std::env::var_os("GRUND_NO_INPUT").is_none()
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().enumerate().find_map(|(i, a)| {
        if a == name {
            args.get(i + 1).cloned()
        } else {
            a.strip_prefix(&format!("{name}=")).map(str::to_string)
        }
    })
}

fn names(answer: &Value, list: &str, field: &str) -> Vec<String> {
    answer[list]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item[field].as_str().map(str::to_string))
        .collect()
}

async fn candidates(args: &[String], value_name: &str) -> Option<Vec<String>> {
    if value_name == "NAME" && args.get(1).is_some_and(|a| a == "context") {
        return credentials::load()
            .ok()
            .map(|file| file.contexts.into_iter().map(|c| c.name).collect());
    }
    let global = Global {
        instance: flag(args, "--instance"),
        context: flag(args, "--context"),
        org: flag(args, "--org"),
        ..Global::default()
    };
    let ctx = Ctx::new(global);
    let api = ctx.api().ok()?;
    if value_name == "SLUG" {
        let answer = api
            .call(
                "grund.organisation.v1.OrganisationService/ListOrganisations",
                json!({}),
            )
            .await
            .ok()?;
        return Some(names(&answer, "organisations", "slug"));
    }
    let org = ctx.org(&api).await.ok()?;
    let (rpc, request, list, field) = match value_name {
        "APP" => (
            "grund.app.v1.AppService/ListApps",
            json!({"organisation": org}),
            "apps",
            "name",
        ),
        "STACK" => (
            "grund.stack.v1.StackService/ListStacks",
            json!({"organisation": org, "pageSize": 100}),
            "stacks",
            "name",
        ),
        "MACHINE" => (
            "grund.machine.v1.MachineService/ListMachines",
            json!({"organisation": org}),
            "machines",
            "name",
        ),
        "DOMAIN" => (
            "grund.domain.v1.DomainService/ListDomains",
            json!({"organisation": org}),
            "domains",
            "name",
        ),
        "MEMBER" => (
            "grund.organisation.v1.OrganisationService/ListMembers",
            json!({"slug": org}),
            "members",
            "username",
        ),
        _ => return None,
    };
    let answer = api.call(rpc, request).await.ok()?;
    Some(names(&answer, list, field))
}

/// Shows a filterable list of `items` on stderr and returns the one picked,
/// or `None` when the person pressed Esc or Ctrl-C.
pub fn pick(prompt: &str, items: &[String]) -> std::io::Result<Option<String>> {
    terminal::enable_raw_mode()?;
    let result = (|| {
        let height = (items.len().min(10) + 2) as u16;
        let mut terminal = Terminal::with_options(
            CrosstermBackend::new(std::io::stderr()),
            TerminalOptions {
                viewport: Viewport::Inline(height),
            },
        )?;
        let mut filter = String::new();
        let mut state = ListState::default().with_selected(Some(0));
        let picked = loop {
            let lower = filter.to_lowercase();
            let shown: Vec<&String> = items
                .iter()
                .filter(|item| item.to_lowercase().contains(&lower))
                .collect();
            if state.selected().is_some_and(|s| s >= shown.len()) {
                state.select(Some(shown.len().saturating_sub(1)));
            }
            terminal.draw(|frame| {
                let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)])
                    .areas(frame.area());
                frame.render_widget(
                    Paragraph::new(Line::from(format!("{prompt} {filter}"))),
                    top,
                );
                let list = List::new(shown.iter().map(|s| ListItem::new(s.as_str())))
                    .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
                    .highlight_symbol("> ");
                frame.render_stateful_widget(list, rest, &mut state);
            })?;
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Esc => break None,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        break None;
                    }
                    KeyCode::Enter => {
                        break state
                            .selected()
                            .and_then(|i| shown.get(i))
                            .map(|s| s.to_string());
                    }
                    KeyCode::Up => state.select_previous(),
                    KeyCode::Down => state.select_next(),
                    KeyCode::Backspace => {
                        filter.pop();
                    }
                    KeyCode::Char(c) => filter.push(c),
                    _ => {}
                }
            }
        };
        terminal.clear()?;
        Ok(picked)
    })();
    terminal::disable_raw_mode()?;
    result
}

/// For a command line clap refused for a missing name, on a terminal: the
/// line with a name the person picked appended, or `None` to leave the
/// refusal as it is.
pub async fn complete(args: &[String], error: &clap::Error) -> Option<Vec<String>> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    if error.kind() != ErrorKind::MissingRequiredArgument || !attended(args) {
        return None;
    }
    let missing = match error.get(ContextKind::InvalidArg)? {
        ContextValue::Strings(values) => values.first()?.clone(),
        ContextValue::String(value) => value.clone(),
        _ => return None,
    };
    let value_name = missing.strip_prefix('<')?.strip_suffix('>')?.to_string();
    let items = candidates(args, &value_name).await?;
    if items.is_empty() {
        return None;
    }
    let picked = pick(&format!("{}:", value_name.to_lowercase()), &items).ok()??;
    let mut completed = args.to_vec();
    completed.push(picked);
    Some(completed)
}

/// The dim line saying the whole command that ran, after a prompt filled
/// it in.
pub fn ran(args: &[String]) {
    let words: Vec<String> = args
        .iter()
        .skip(1)
        .map(|a| {
            if a.is_empty() || a.contains(char::is_whitespace) {
                format!("'{a}'")
            } else {
                a.clone()
            }
        })
        .collect();
    let line = format!("ran: grund {}", words.join(" "));
    if std::env::var_os("NO_COLOR").is_some() {
        eprintln!("{line}");
    } else {
        eprintln!("\x1b[2m{line}\x1b[0m");
    }
}

/// A live view of something under way, drawn in a few lines on stderr and
/// cleared when it is dropped, so the scrollback keeps only the result.
pub struct Live {
    terminal: Terminal<CrosstermBackend<std::io::Stderr>>,
    started: std::time::Instant,
}

impl Live {
    /// A view `lines` high below the cursor, or `None` when stderr cannot
    /// take one.
    pub fn start(lines: u16) -> Option<Self> {
        let terminal = Terminal::with_options(
            CrosstermBackend::new(std::io::stderr()),
            TerminalOptions {
                viewport: Viewport::Inline(lines + 2),
            },
        )
        .ok()?;
        Some(Live {
            terminal,
            started: std::time::Instant::now(),
        })
    }

    /// Draws `title`, a bar of `done` out of `wanted`, and `lines` under it.
    pub fn show(&mut self, title: &str, done: u64, wanted: u64, lines: &[String]) {
        let elapsed = self.started.elapsed().as_secs();
        let ratio = if wanted == 0 {
            0.0
        } else {
            (done as f64 / wanted as f64).clamp(0.0, 1.0)
        };
        let _ = self.terminal.draw(|frame| {
            let [top, bar, rest] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(0),
            ])
            .areas(frame.area());
            frame.render_widget(Paragraph::new(Line::from(title.to_string())), top);
            frame.render_widget(
                Gauge::default()
                    .ratio(ratio)
                    .label(format!("{done} of {wanted} copies ready · {elapsed}s")),
                bar,
            );
            frame.render_widget(
                Paragraph::new(
                    lines
                        .iter()
                        .map(|l| Line::from(l.as_str()))
                        .collect::<Vec<_>>(),
                ),
                rest,
            );
        });
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let _ = self.terminal.clear();
    }
}

fn matching<'a>(lines: &'a [String], filter: &str) -> Vec<&'a String> {
    let filter = filter.to_lowercase();
    lines
        .iter()
        .filter(|l| filter.is_empty() || l.to_lowercase().contains(&filter))
        .collect()
}

/// A full-screen view of lines that keep coming (`app logs --follow` on a
/// terminal): it follows the newest line until the person scrolls or
/// pauses, filters with `/`, and quits with `q`. The terminal is restored
/// when it is dropped.
pub struct Pager {
    terminal: Terminal<CrosstermBackend<std::io::Stderr>>,
    title: String,
    lines: Vec<String>,
    from_bottom: usize,
    paused: bool,
    filter: String,
    typing: Option<String>,
}

/// What a key did to the pager.
pub enum Step {
    Continue,
    Quit,
}

impl Pager {
    const KEEP: usize = 20_000;

    /// Takes over the terminal for `title`.
    pub fn start(title: &str) -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        ratatui::crossterm::execute!(std::io::stderr(), terminal::EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(std::io::stderr()))?;
        Ok(Pager {
            terminal,
            title: title.to_string(),
            lines: Vec::new(),
            from_bottom: 0,
            paused: false,
            filter: String::new(),
            typing: None,
        })
    }

    /// Adds lines at the bottom; a paused or scrolled view stays where it is.
    pub fn push(&mut self, text: &str) {
        for line in text.lines() {
            self.lines.push(line.to_string());
            if self.paused || self.from_bottom > 0 {
                self.from_bottom += 1;
            }
        }
        if self.lines.len() > Self::KEEP {
            let excess = self.lines.len() - Self::KEEP;
            self.lines.drain(..excess);
        }
    }

    fn shown(&self) -> Vec<&String> {
        matching(&self.lines, &self.filter)
    }

    /// Draws the view, with `error` in the status line when the feed broke.
    pub fn draw(&mut self, error: Option<&str>) -> std::io::Result<()> {
        let shown: Vec<String> = self.shown().into_iter().cloned().collect();
        let state = match (&self.typing, error) {
            (Some(typing), _) => format!("filter: {typing}"),
            (None, Some(error)) => format!("stopped: {error}"),
            (None, None) if self.paused => "paused (space follows)".into(),
            (None, None) if self.from_bottom > 0 => "scrolled (G follows)".into(),
            _ => "following".into(),
        };
        let filter = if self.filter.is_empty() {
            String::new()
        } else {
            format!(" · filter \"{}\"", self.filter)
        };
        let status = format!(
            "{} · {state}{filter} · {} lines · q quit, space pause, ↑↓ scroll, / filter",
            self.title,
            shown.len()
        );
        let from_bottom = self.from_bottom;
        self.terminal.draw(|frame| {
            let [body, bar] =
                Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(frame.area());
            let height = body.height as usize;
            let end = shown.len().saturating_sub(from_bottom.min(shown.len()));
            let start = end.saturating_sub(height);
            let visible: Vec<Line> = shown[start..end]
                .iter()
                .map(|l| Line::from(l.as_str()))
                .collect();
            frame.render_widget(Paragraph::new(visible), body);
            frame.render_widget(
                Paragraph::new(Line::from(status.clone()))
                    .style(Style::default().add_modifier(Modifier::REVERSED)),
                bar,
            );
        })?;
        Ok(())
    }

    /// Waits up to `wait` for a key and acts on it.
    pub fn key(&mut self, wait: std::time::Duration) -> std::io::Result<Step> {
        if !event::poll(wait)? {
            return Ok(Step::Continue);
        }
        let Event::Key(key) = event::read()? else {
            return Ok(Step::Continue);
        };
        if key.kind != KeyEventKind::Press {
            return Ok(Step::Continue);
        }
        if let Some(typing) = self.typing.as_mut() {
            match key.code {
                KeyCode::Enter => {
                    self.filter = self.typing.take().unwrap_or_default();
                    self.from_bottom = 0;
                }
                KeyCode::Esc => self.typing = None,
                KeyCode::Backspace => {
                    typing.pop();
                }
                KeyCode::Char(c) => typing.push(c),
                _ => {}
            }
            return Ok(Step::Continue);
        }
        let page = self
            .terminal
            .size()
            .map_or(20, |s| s.height.saturating_sub(2) as usize);
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(Step::Quit),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(Step::Quit);
            }
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                if !self.paused {
                    self.from_bottom = 0;
                }
            }
            KeyCode::Char('/') => self.typing = Some(self.filter.clone()),
            KeyCode::Up | KeyCode::Char('k') => self.from_bottom += 1,
            KeyCode::Down | KeyCode::Char('j') => {
                self.from_bottom = self.from_bottom.saturating_sub(1)
            }
            KeyCode::PageUp => self.from_bottom += page,
            KeyCode::PageDown => self.from_bottom = self.from_bottom.saturating_sub(page),
            KeyCode::Char('g') | KeyCode::Home => self.from_bottom = self.lines.len(),
            KeyCode::Char('G') | KeyCode::End => self.from_bottom = 0,
            _ => {}
        }
        let most = self.shown().len();
        self.from_bottom = self.from_bottom.min(most);
        Ok(Step::Continue)
    }
}

impl Drop for Pager {
    fn drop(&mut self) {
        let _ = ratatui::crossterm::execute!(std::io::stderr(), terminal::LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filter_keeps_the_lines_that_contain_it_in_any_case() {
        let lines: Vec<String> = (0..30)
            .map(|n| format!("2026-10-19T20:00:00Z instance=web-1 stream=stdout | Line {n}"))
            .collect();
        let kept = matching(&lines, "line 2");
        assert_eq!(kept.len(), 11);
        assert!(kept.iter().all(|l| l.contains("Line 2")));
        assert_eq!(matching(&lines, "").len(), 30);
    }

    #[test]
    fn json_output_or_ci_is_never_attended() {
        let words = |line: &str| line.split(' ').map(str::to_string).collect::<Vec<_>>();
        assert!(!attended(&words("grund app logs --json")));
        assert!(!attended(&words("grund app logs -o json")));
        assert!(!attended(&words("grund app logs --output=yaml")));
    }

    #[test]
    fn the_flags_a_lister_needs_come_from_the_line_either_way() {
        let words = |line: &str| line.split(' ').map(str::to_string).collect::<Vec<_>>();
        let args = words("grund app logs --context home --org=acme");
        assert_eq!(flag(&args, "--context").as_deref(), Some("home"));
        assert_eq!(flag(&args, "--org").as_deref(), Some("acme"));
        assert_eq!(flag(&args, "--instance"), None);
    }
}
