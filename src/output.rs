//! Output formatting and JSON serialization for the v2.0 CLI.

use anyhow::Result;
use console::style;
use serde::Serialize;

/// Context for controlling output format across all commands.
pub struct OutputContext {
    pub json: bool,
    pub pretty: bool,
    pub verbose: bool,
    pub silent: bool,
}

impl OutputContext {
    pub fn human(&self) -> bool {
        !self.json && !self.silent
    }
}

#[derive(Serialize)]
struct JsonOutput<T> {
    command: String,
    timestamp: String,
    version: String,
    success: bool,
    result: T,
}

#[derive(Serialize)]
struct JsonError {
    command: String,
    timestamp: String,
    version: String,
    success: bool,
    error: String,
}

fn current_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Output a successful result, either as JSON or letting the caller handle human output.
pub fn output_result<T: Serialize>(command: &str, result: T, ctx: &OutputContext) -> Result<()> {
    if ctx.json {
        let output = JsonOutput {
            command: command.to_string(),
            timestamp: current_timestamp(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            success: true,
            result,
        };

        let json_str = if ctx.pretty {
            serde_json::to_string_pretty(&output)?
        } else {
            serde_json::to_string(&output)?
        };

        std::println!("{}", json_str);
    }
    // If not JSON, the caller should have already printed human-readable output

    Ok(())
}

/// Output an error, either as JSON or as styled terminal text.
pub fn output_error(command: &str, error: &str, ctx: &OutputContext) -> Result<()> {
    if ctx.json {
        let output = JsonError {
            command: command.to_string(),
            timestamp: current_timestamp(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            success: false,
            error: error.to_string(),
        };

        let json_str = if ctx.pretty {
            serde_json::to_string_pretty(&output)?
        } else {
            serde_json::to_string(&output)?
        };

        eprintln!("{}", json_str);
    } else {
        eprintln!("  {} {}", style("✗").red().bold(), error);
    }

    Ok(())
}
