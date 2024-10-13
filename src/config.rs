use std::env;

pub fn get_config_home() -> String {
    return env::var("XDG_CONFIG_HOME")
        .or(env::var("HOME").map(|h| format!("{h}/.config")))
        .unwrap();
}

pub fn get_gcloud_config_path() -> String {
    match env::var("CLOUDSDK_CONFIG") {
        Ok(val) => val,
        Err(_) => {
            let config_home: String = get_config_home();
            format!("{config_home}/gcloud")
        }
    }
}

pub fn get_adc_path() -> String {
    match env::var("GOOGLE_APPLICATION_CREDENTIALS") {
        Ok(path) => path,
        Err(_) => {
            let config_home: String = get_gcloud_config_path();
            let adc = format!("{config_home}/application_default_credentials.json");
            adc
        }
    }
}
