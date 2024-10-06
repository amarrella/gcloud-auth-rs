use reqwest::{self, Error};
use serde;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use const_format::concatcp;

const CLOUDSDK_CLIENT_ID: &str = "32555940559.apps.googleusercontent.com";
const GOOGLE_METADATA_URL: &str = "http://metadata/computeMetadata/v1/instance/service-accounts/";
const GOOGLE_OAUTH_URL: &str = "https://oauth2.googleapis.com";
const GOOGLE_OAUTH_TOKEN_URL: &str = concatcp!(
    GOOGLE_OAUTH_URL,
    "/token"
);

#[derive(Serialize, Deserialize)]
pub struct GoogleCredentials {
    account: String,
    client_id: String,
    client_secret: String,
    refresh_token: String,
    #[serde(rename = "type")]
    credential_type: String,
    universe_domain: String,
}

#[derive(Serialize, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    expires_in: u32,
    scope: String,
    token_type: String,
    id_token: String
}

type IdToken = String;

pub async fn idtoken_from_metadata_server(
    client: &reqwest::Client
) -> Result<IdToken, Error> {
    let jwt = client.get(
        format!("{GOOGLE_METADATA_URL}default/identity?audience={CLOUDSDK_CLIENT_ID}")
    ).header(
        "Metadata-Flavor",
        "Google"
    )
    .send()
    .await?
    .text()
    .await;

    jwt
}

fn read_credentials_from_file(path: &str) -> Result<GoogleCredentials, std::io::Error> {
    let content = fs::read_to_string(path)?;
    let credentials: GoogleCredentials = serde_json::from_str(&content)?;
    Ok(credentials)
}

pub async fn idtoken_from_credentials(
    creds: &GoogleCredentials,
    client: &reqwest::Client
) -> Result<IdToken, Error> {
    let response = client.post(
        GOOGLE_OAUTH_TOKEN_URL
    ).form(
        &[
            ("client_id", creds.client_id.as_str()),
            ("client_secret", creds.client_secret.as_str()),
            ("refresh_token", creds.refresh_token.as_str()),
            ("grant_type", "refresh_token")
        ]
    )
    .send()
    .await?
    .json::<GoogleTokenResponse>()
    .await;

    Ok(response?.id_token)
}

pub async fn get_idtoken(
    client: &reqwest::Client
) -> Result<IdToken, Error> {
    let idtoken = idtoken_from_metadata_server(
        &client
    ).await;

    let result = match idtoken {
        Ok(tok) => Ok(tok),
        Err(_) => {

            let credentials_path: String = match env::var("GOOGLE_APPLICATION_CREDENTIALS") {
                Ok(path) => path,
                Err(_) => {
                    let home = env::var("HOME");
                    let adc = ".config/gcloud/application_default_credentials.json";
                    match home {
                        Ok(h) =>  format!("{h}/{adc}"),
                        Err(_) => format!("/root/{adc}")
                    }
                }
            };
            let credentials = read_credentials_from_file(&credentials_path).expect(
                format!("Couldn't find credentials at {credentials_path}").as_str()
            );
            return idtoken_from_credentials(&credentials, &client).await;
        }
    };

    result
}