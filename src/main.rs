use clap::{Parser, Subcommand};
mod auth;

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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Auth { auth_commands }) => match *auth_commands {
            Some(AuthCommands::PrintIdToken) => {
                let id_token = auth::idtoken_from_metadata_server().await;
                match id_token {
                    Ok(t) => println!("{t}"),
                    Err(e) => println!("{e:?}"),
                }
            }
            None => println!("Usage: gcloud auth [command]"),
        },
        None => println!("Usage gcloud [command]"),
    }
}
