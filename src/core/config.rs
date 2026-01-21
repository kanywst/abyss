use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "abyss", author, version, about, long_about = None)]
pub struct AbyssConfig {
    /// Target domain (e.g., example.com)
    #[arg(short, long)]
    pub target: String,

    /// Output HTML report to file path
    #[arg(long)]
    pub html: Option<String>,

    /// Suppress log output (useful for JSON piping)
    #[arg(short, long)]
    pub quiet: bool,

    /// Set concurrency limit
    #[arg(long, default_value = "10")]
    pub concurrency: usize,
}