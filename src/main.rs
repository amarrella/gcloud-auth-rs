use clap::{Parser, Subcommand};
mod auth;
mod config;

#[derive(Parser)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Auth
    Auth {
        #[command(subcommand)]
        auth_commands: AuthCommands,
    },
}

#[derive(Subcommand)]
enum ApplicationDefaultCommands {
    Login,
    PrintAccessToken,
}

#[derive(Subcommand)]
enum AuthCommands {
    Login,
    PrintIdentityToken,
    PrintAccessToken,
    ApplicationDefault {
        #[command(subcommand)]
        app_default_commands: ApplicationDefaultCommands,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Auth { auth_commands } => match auth_commands {
            AuthCommands::Login => {
                let client: reqwest::Client = reqwest::Client::new();
                let config_path: String = config::get_gcloud_config_path();
                let credentials_db =
                    sqlite::Connection::open(format!("{config_path}/credentials.db")).unwrap();
                let scopes = [
                    "openid",
                    "https://www.googleapis.com/auth/userinfo.email",
                    "https://www.googleapis.com/auth/cloud-platform",
                    "https://www.googleapis.com/auth/appengine.admin",
                    "https://www.googleapis.com/auth/sqlservice.login",
                    "https://www.googleapis.com/auth/compute",
                    "https://www.googleapis.com/auth/accounts.reauth",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect();
                auth::user_login(&client, &credentials_db, scopes)
                    .await
                    .expect("Login failed");
                println!("Login successful");
            }
            AuthCommands::PrintIdentityToken => {
                let client = reqwest::Client::new();
                let config_path: String = config::get_gcloud_config_path();
                let credentials_db =
                    sqlite::Connection::open(format!("{config_path}/credentials.db")).unwrap();
                let id_token = auth::get_idtoken(&client, &credentials_db).await;
                match id_token {
                    Ok(t) => print!("{t}"),
                    Err(e) => println!("Login required"),
                }
            }
            AuthCommands::PrintAccessToken => {
                let client = reqwest::Client::new();
                let config_path: String = config::get_gcloud_config_path();
                let credentials_db =
                    sqlite::Connection::open(format!("{config_path}/credentials.db")).unwrap();
                let access_token = auth::get_user_accesstoken(&client, &credentials_db).await;
                match access_token {
                    Ok(t) => println!("{t}"),
                    Err(e) => println!("Login required"),
                }
            }
            AuthCommands::ApplicationDefault {
                app_default_commands,
            } => match app_default_commands {
                ApplicationDefaultCommands::PrintAccessToken => {
                    let client = reqwest::Client::new();
                    match auth::get_adc_accesstoken(&client).await {
                        Ok(t) => print!("{t}"),
                        Err(e) => println!("Login required"),
                    }
                }
                ApplicationDefaultCommands::Login => {
                    let client = reqwest::Client::new();
                    let scopes = [
                        "openid",
                        "https://www.googleapis.com/auth/userinfo.email",
                        "https://www.googleapis.com/auth/cloud-platform",
                        "https://www.googleapis.com/auth/appengine.admin",
                        "https://www.googleapis.com/auth/sqlservice.login",
                        "https://www.googleapis.com/auth/compute",
                        "https://www.googleapis.com/auth/accounts.reauth",
                    ]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                    auth::application_default_login(&client, scopes)
                        .await
                        .expect("Login failed");
                    println!("Login successful")
                }
            },
        },
    }
}
