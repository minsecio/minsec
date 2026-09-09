#[path = "../src/cli.rs"]
mod cli;
#[path = "../../../scripts/completions.rs"]
mod completions;

fn main() -> std::io::Result<()> {
    completions::generate::<cli::Cli>()
}
