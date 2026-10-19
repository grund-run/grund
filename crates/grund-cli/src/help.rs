//! `grund --help`: the client commands in labelled groups, one short line
//! each (grund-docs design/cli.md, help). Built from the command tree, so a
//! command's line is its `about`; a visible command no group names is listed
//! under MORE rather than left out.

/// The groups, in order, and the commands each lists when the tree has them.
pub const GROUPS: &[(&str, &[&str])] = &[
    ("APPS", &["app", "stack", "volume", "domain", "registry"]),
    ("MACHINES", &["machine"]),
    ("ORGANISATION", &["org", "member", "notification"]),
    (
        "THIS COMPUTER",
        &[
            "join",
            "leave",
            "status",
            "update",
            "doctor",
            "server",
            "install",
            "uninstall",
        ],
    ),
    ("SETUP", &["auth", "context", "completion"]),
    (
        "FOR AGENTS AND SCRIPTS",
        &["api", "describe", "schema", "skill", "mcp"],
    ),
];

const EXAMPLES: &[&str] = &[
    "grund auth login https://grund.example.com",
    "grund app deploy",
    "grund app logs web --follow",
];

/// The root help for `root`, grouped.
pub fn grouped(root: &clap::Command) -> String {
    let visible: Vec<&clap::Command> = root
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .collect();
    let width = visible
        .iter()
        .map(|c| c.get_name().len())
        .max()
        .unwrap_or(0)
        + 2;
    let line = |c: &clap::Command| {
        let about = c.get_about().map(|a| a.to_string()).unwrap_or_default();
        format!("  {:width$}{about}\n", c.get_name())
    };
    let mut text = String::new();
    if let Some(about) = root.get_about() {
        text.push_str(&format!("{about}\n\n"));
    }
    text.push_str("USAGE\n  grund <command> <subcommand> [flags]\n");
    for (title, names) in GROUPS {
        let listed: Vec<&&clap::Command> = names
            .iter()
            .filter_map(|n| visible.iter().find(|c| c.get_name() == *n))
            .collect();
        if listed.is_empty() {
            continue;
        }
        text.push_str(&format!("\n{title}\n"));
        for command in listed {
            text.push_str(&line(command));
        }
    }
    let rest: Vec<&&clap::Command> = visible
        .iter()
        .filter(|c| {
            !GROUPS
                .iter()
                .any(|(_, names)| names.contains(&c.get_name()))
        })
        .collect();
    if !rest.is_empty() {
        text.push_str("\nMORE\n");
        for command in rest {
            text.push_str(&line(command));
        }
    }
    text.push_str("\nFLAGS\n  --org SLUG   -o, --output text|json|yaml   --json   -h   -V\n");
    text.push_str("\nEXAMPLES\n");
    for example in EXAMPLES {
        text.push_str(&format!("  {example}\n"));
    }
    text.push_str("\nLearn more: grund <command> --help\n");
    text
}

/// `root` with its help grouped.
pub fn with_grouped_help(root: clap::Command) -> clap::Command {
    let help = grouped(&root);
    root.override_help(help)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn every_visible_client_command_is_in_exactly_one_group() {
        let root = crate::Standalone::command();
        for command in root.get_subcommands().filter(|c| !c.is_hide_set()) {
            let groups = GROUPS
                .iter()
                .filter(|(_, names)| names.contains(&command.get_name()))
                .count();
            assert_eq!(groups, 1, "{} is in {groups} groups", command.get_name());
        }
        assert!(!grouped(&root).contains("\nMORE\n"));
    }

    #[test]
    fn the_root_help_lists_each_command_under_its_group_with_its_about() {
        let text = grouped(&crate::Standalone::command());
        let apps = text.find("\nAPPS\n").unwrap();
        let machines = text.find("\nMACHINES\n").unwrap();
        let app = text.find("\n  app ").unwrap();
        assert!(apps < app && app < machines);
        assert!(text.contains("Deploy, inspect and change apps"));
        assert!(!text.contains("--log"));
    }
}
