use std::env;
use std::error::Error;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::MyError;
use crate::transfer::Transfer;
use crate::pelican::PelicanInfo;

fn get_cred_dir() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let dir_path = match env::var("_CONDOR_CREDS") {
        Ok(val) => val,
        Err(_) => {
            return Err(Box::new(MyError::CredentialsError("_CONDOR_CREDS env variable not set".into())));
        }
    };
    log::info!("Reading cred directory: {}", dir_path);

    let mut ret = Vec::new();
    match fs::read_dir(&dir_path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(dir_entry) => {
                        if let Some(filename) = dir_entry.file_name().to_str() && filename.ends_with(".use") {
                            ret.push(dir_entry.path().to_str().unwrap().to_string())
                        }
                    }
                    Err(_) => {
                        return Err(Box::new(MyError::CredentialsError("Error reading _CONDOR_CREDS dir".into())));
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error reading directory {}: {}", dir_path, e);
        }
    }

    Ok(ret)
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Clone)]
pub(crate) struct Credential {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u32,
    pub expires_at: f32,
    pub scope: Vec<String>,
}

pub struct Credentials(Vec<Credential>);

impl Credentials {
    pub fn new(data: Vec<Credential>) -> Self {
        Credentials(data)
    }

    pub fn from_condor() -> Result<Self, Box<dyn std::error::Error>> {
        let mut ret = Vec::new();
        for filename in get_cred_dir()? {
            log::info!("reading cred {}", filename);
            let json = fs::read_to_string(&filename)?;
            let data: Credential = serde_json::from_str(&json)?;
            log::info!("found scope {:?}", data.scope);
            ret.push(data);
        }
        Ok(Self(ret))
    }

    pub fn get_correct_cred(&self, transfer: &Transfer, info: &PelicanInfo) -> Result<&Credential, Box<dyn Error>> {
        let prefix = info.get_osdf_prefix();
        let path = match transfer.url.split_once(prefix) {
            Some(s) => s.1,
            None => {
                return Err(Box::new(MyError::CredentialsError("url does not match OSDF prefix".into())));
            }
        };
        let scope_options = match transfer.mode {
            crate::transfer::Verb::Get => vec!["storage.read"],
            crate::transfer::Verb::Put => vec!["storage.create", "storage.modify"],
        };
        log::info!("getting correct cred to match scope {:?} and path: {}", scope_options, path);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f32();
        let mut expired_cred = None;
        for cred in self.0.iter() {
            for scope in cred.scope.iter() {
                if let Some((pre, post)) = scope.split_once(':')
                    && scope_options.contains(&pre) && path.starts_with(post) {
                    if cred.expires_at <= now {
                        expired_cred = Some(cred);
                    } else {
                        return Ok(cred)
                    }
                }
            }
        }

        if let Some(cred) = expired_cred {
            log::warn!("only valid cred is expired. will try using it anyway");
            Ok(cred)
        } else {
            Err(Box::new(MyError::CredentialsError("No matching credentials for url".into())))
        }
    }
}


#[cfg(test)]
mod tests {
    use tempfile::{NamedTempFile, TempDir};

    use super::*;
    use crate::{logging::test_logger, transfer::Verb};

    #[test]
    fn test_credentials_from_condor() {
        test_logger();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f32();
        let test_cred = Credential{
            access_token: "token".into(),
            token_type: "bearer".into(),
            expires_in: 3600,
            expires_at: now+3600.,
            scope: vec![
                "storage.read:/read/scope".into(),
                "storage.modify:/write/scope".into()
            ]
        };

        let tmp_dir = TempDir::new().unwrap();
        let file_path = tmp_dir.path().join("test_cred.use");
        let contents = serde_json::to_vec_pretty(&test_cred).unwrap();
        fs::write(file_path, &contents).unwrap();

        temp_env::with_var("_CONDOR_CREDS", Some(tmp_dir.path().as_os_str()), || {
            let creds = Credentials::from_condor().unwrap();
            assert!(creds.0.len() == 1);
            assert_eq!(*creds.0.first().unwrap(), test_cred);
        });
    }

    #[test]
    fn test_get_correct_cred() {
        test_logger();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f32();
        let test_cred = Credential{
            access_token: "token".into(),
            token_type: "bearer".into(),
            expires_in: 3600,
            expires_at: now+3600.,
            scope: vec![
                "storage.read:/read/scope".into(),
                "storage.modify:/write/scope".into()
            ]
        };

        let creds = Credentials(vec![test_cred.clone()]);

        let file_path = NamedTempFile::new().ok().unwrap();
        let mut transfer = Transfer::new(
            "url://namespace/read/scope/file.bin".into(),
            file_path.path().to_str().unwrap().into(),
            Verb::Get
        );
        let info = PelicanInfo{
            origins: vec!["http://origin".into()],
            osdf_prefix: "url://namespace".into()
        };

        let out_cred = creds.get_correct_cred(&transfer, &info).unwrap();
        assert_eq!(out_cred, &test_cred);

        transfer.mode = Verb::Put;
        assert!(creds.get_correct_cred(&transfer, &info).is_err());
    }

    #[test]
    fn test_get_correct_cred_expired() {
        test_logger();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f32();
        let test_cred = Credential{
            access_token: "token".into(),
            token_type: "bearer".into(),
            expires_in: 3600,
            expires_at: now-3600.,
            scope: vec![
                "storage.read:/read/scope".into(),
                "storage.modify:/write/scope".into()
            ]
        };

        let creds = Credentials(vec![test_cred.clone()]);

        let file_path = NamedTempFile::new().ok().unwrap();
        let transfer = Transfer::new(
            "url://namespace/read/scope/file.bin".into(),
            file_path.path().to_str().unwrap().into(),
            Verb::Get
        );
        let info = PelicanInfo{
            origins: vec!["http://origin".into()],
            osdf_prefix: "url://namespace".into()
        };

        let out_cred = creds.get_correct_cred(&transfer, &info).unwrap();
        assert_eq!(out_cred, &test_cred);
    }
}
