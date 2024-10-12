use clap::{Parser, Subcommand};
mod auth;
mod config;

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
enum ApplicationDefaultCommands {
    Login
}

#[derive(Subcommand)]
enum AuthCommands {
    PrintIdToken,
    ApplicationDefault {
        #[command(subcommand)]
        app_default_commands: Option<ApplicationDefaultCommands>,
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Auth { auth_commands }) => match auth_commands {
            Some(AuthCommands::PrintIdToken) => {
                let client = reqwest::Client::new();
                let config_path: String = config::get_gcloud_config_path();
                let credentials_db = sqlite::Connection::open(format!("{config_path}/credentials.db")).unwrap();
                let id_token = auth::get_idtoken(&client, &credentials_db).await;
                match id_token {
                    Ok(t) => println!("{t}"),
                    Err(e) => println!("{e:?}"),
                }
            },
            Some(AuthCommands::ApplicationDefault {app_default_commands}) =>
                match app_default_commands {
                    Some(ApplicationDefaultCommands::Login) => {
                        let client = reqwest::Client::new();
                        auth::application_default_login(&client).await.expect("failed login");
                    }
                    None => 
                        println!("Usage: gcloud auth application-default [command]")
                }
            None => println!("Usage: gcloud auth [command]"),
        },
        None => println!("Usage gcloud [command]"),
    }
}
