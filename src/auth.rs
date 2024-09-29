use reqwest::{self, Error};

const CLOUDSDK_CLIENT_ID: &str = "32555940559.apps.googleusercontent.com";

pub async fn idtoken_from_metadata_server() -> Result<String, Error> {
    let client = reqwest::Client::new();
    let body = client.get(
        format!("http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience={CLOUDSDK_CLIENT_ID}")
    ).header(
        "Metadata-Flavor",
        "Google"
    )
    .send()
    .await?
    .text()
    .await?;

    Ok(body)
}
