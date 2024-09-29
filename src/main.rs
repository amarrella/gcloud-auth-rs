use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Auth
    Auth {
        #[command(subcommand)]
        auth_commands: Option<AuthCommands>,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    PrintIdToken,
}

fn main() {
    let cli = Cli::parse();
}
