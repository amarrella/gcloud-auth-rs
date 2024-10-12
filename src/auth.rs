use reqwest::{self, Client, Error};
use serde;
use serde::{Deserialize, Serialize};
use sqlite::{Connection, State};
use tokio::fs;
use const_format::concatcp;
use open;
use hyper;
use tokio::net::TcpListener;
use hyper_util::rt::TokioIo;
use hyper::service::service_fn;
use hyper::server::conn::http1;
use http_body_util::Full;
use hyper::body::Bytes;
use regex::Regex;
use tokio::sync::mpsc;
use ini;
use crate::config;

const CLOUDSDK_CLIENT_ID: &str = "32555940559.apps.googleusercontent.com";
const CLOUDSDK_CLIENT_NOTSOSECRET: &str = "ZmssLNjJy2998hD4CTg2ejr2";
const CLOUDSDK_APPLICATION_DEFAULT_CLIENT_ID: &str = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com";
const CLOUDSDK_APPLICATION_DEFAULT_CLIENT_SECRET: &str = "d-FL95Q19q7MQmFpd7hHD0Ty";
const GOOGLE_METADATA_URL: &str = "http://metadata/computeMetadata/v1/instance/service-accounts/";
const GOOGLE_OAUTH_URL: &str = "https://oauth2.googleapis.com";
const GOOGLE_OAUTH_TOKEN_URL: &str = concatcp!(
    GOOGLE_OAUTH_URL,
    "/token"
);
const GOOGLE_CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const AUTH_CODE_REGEX: &str = "(code=)(.*)(&*)";

#[derive(Serialize, Deserialize)]
pub struct GoogleCredentials {
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    client_id: String,
    client_secret: String,
    refresh_token: String,
    #[serde(rename = "type")]
    credential_type: String,
    universe_domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoke_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Box<[String]>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_uri: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct GoogleCredentialsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>
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

async fn read_credentials_from_file(path: &str) -> Result<GoogleCredentials, std::io::Error> {
    let content = fs::read_to_string(path).await?;
    let credentials: GoogleCredentials = serde_json::from_str(&content)?;
    Ok(credentials)
}

async fn get_active_account(
    config_path: &str
) -> Result<String, String> {
    let active_config_path: String = format!("{config_path}/active_config");
    let active_config_binary = fs::read(&active_config_path).await.expect(
        format!("Couldn't read active config from {active_config_path}").as_str()
    );
    let active_config_str = String::from_utf8(active_config_binary).expect(
        "Couldn't decode config from {active_config_path}"
    );
    let gcloud_config = ini::ini!(&format!("{config_path}/configurations/config_{active_config_str}"));
    let active_account: String = gcloud_config["core"]["account"].clone().unwrap();
    return Ok(active_account);
}

fn read_credentials_from_db(
    connection: &Connection,
    account: &str
) -> Result<GoogleCredentials, String> {
    let query = format!("SELECT value FROM credentials WHERE account_id = ?");
    let mut statement = connection.prepare(query).unwrap();
    statement.bind((1, account));
    let mut credentials = None;
    while let Ok(State::Row) = statement.next() {
        let value = statement.read::<String, _>("value").unwrap();
        credentials = serde_json::from_str(&value).unwrap();
    }
    Ok(credentials.unwrap())
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
    .json::<GoogleCredentialsResponse>()
    .await;

    Ok(response?.id_token.unwrap())
}

async fn credentials_response_from_auth_code(
    auth_code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: &str,
    client: &reqwest::Client
) -> Result<GoogleCredentialsResponse, Error> {
    let response = client.post(
        GOOGLE_OAUTH_TOKEN_URL
    ).form(
        &[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", auth_code),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code")
        ]
    )
    .send()
    .await?;

    let response = match response.error_for_status() {
        Ok(res) => Ok(res),
        Err(e) => Err(dbg!(e))
    };

    let json = response?.json::<GoogleCredentialsResponse>().await;

    json
}

pub async fn get_idtoken(
    client: &reqwest::Client,
    connection: &Connection
) -> Result<IdToken, Error> {
    let idtoken = idtoken_from_metadata_server(
        &client
    ).await;

    let result = match idtoken {
        Ok(tok) => Ok(tok),
        Err(_) => {
            let config_path: String = config::get_gcloud_config_path();
            let active_account: String = get_active_account(&config_path).await.unwrap();
            let credentials = read_credentials_from_db(connection, &active_account).expect(
                format!("Couldn't find credentials at {active_account}").as_str()
            );
            return idtoken_from_credentials(&credentials, &client).await;
        }
    };

    result
}

#[derive(Serialize, Deserialize)]
struct AuthCodeQuery {
    code: String
}

pub async fn installed_app_flow_auth(
    client: &Client,
    client_id: &str,
    client_secret: &str
) -> Result<GoogleCredentialsResponse, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_server_addr = listener.local_addr()?;
    let local_server_uri = local_server_addr.to_string();
    let redirect_uri = format!("http://{local_server_uri}");
    let google_auth_url: String = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope={GOOGLE_CLOUD_PLATFORM_SCOPE}"
    );
    
    open::that(format!("{google_auth_url}")).expect(
        format!("Couldn't open auth url {google_auth_url}").as_str()
    );
    let (tx, mut rx) = mpsc::channel::<String>(1);

    async fn get_auth_code(req: hyper::Request<hyper::body::Incoming>, tx: mpsc::Sender<String>,
    ) -> Result<hyper::Response<Full<Bytes>>, std::convert::Infallible> {
        let uri = req.uri();
        let query = uri.query().unwrap_or("");
        let auth_code_re = Regex::new(AUTH_CODE_REGEX).unwrap();
        let caps = auth_code_re.captures(query);
        let code: Option<String> = caps.map(
            |cs| {
                return cs[2].to_string();
            }
        );
        match code {
            Some(c) => {
                if c != "" {
                    let _ = tx.send(c).await;
                }
            }
            None => {}
        }
        Ok(hyper::Response::new(Full::new(Bytes::from(""))))
    }


    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            let tx_clone = tx.clone();

            tokio::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(io, service_fn(|req| get_auth_code(req, tx_clone.clone())))
                    .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            });
        }
    });

    let auth_code = rx.recv().await.expect("auth code not received");
    
    let credentials_response = credentials_response_from_auth_code(
        &auth_code,
        &redirect_uri,
        &client_id,
        &client_secret,
        client
    ).await?;

    Ok(credentials_response)
}

pub async fn application_default_login(
    client: &Client
) -> Result<(), Box<dyn std::error::Error>> {
    let google_credentials_response = installed_app_flow_auth(client, CLOUDSDK_APPLICATION_DEFAULT_CLIENT_ID, CLOUDSDK_APPLICATION_DEFAULT_CLIENT_SECRET).await;
    let credentials = GoogleCredentials {
        client_id: CLOUDSDK_APPLICATION_DEFAULT_CLIENT_ID.to_string(),
        client_secret: CLOUDSDK_APPLICATION_DEFAULT_CLIENT_SECRET.to_string(),
        account: None,
        credential_type: String::from("authorized_user"),
        refresh_token: google_credentials_response?.refresh_token.expect("No refresh token"),
        universe_domain: String::from("googleapis.com"),
        scopes: None,
        revoke_uri: None,
        token_uri: None
    };

    let credentials_path = config::get_adc_path();
    let credentials = serde_json::to_string(&credentials).expect(
        "serialization error"
    );
    fs::write(credentials_path, credentials).await.expect(
        "failed writing credentials"
    );
    Ok(())
}
