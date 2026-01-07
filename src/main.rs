//! lancer-strix
//! Rust clone of strix. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-strix", version, about = "Rust clone of strix")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-strix - scaffold ready. Implement per plan.md.");
    Ok(())
}
