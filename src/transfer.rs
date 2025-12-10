use std::error::Error;

use reqwest::blocking::RequestBuilder;
use url::Url;

use crate::credentials::Credentials;
use crate::error::MyError;
use crate::pelican::PelicanInfo;

pub(crate) enum Verb {
    Put,
    Get,
}

pub(crate) struct Transfer {
    pub url: String,
    filename: String,
    pub mode: Verb,
}

impl Transfer {
    pub fn new(url: String, filename: String, mode: Verb) -> Self {
        Transfer {
            url,
            filename,
            mode,
        }
    }

    fn get_origin_url(&self, origin: &PelicanInfo) -> Result<String, Box<dyn Error>> {
        let origin_url = origin.choose_origin()?;
        let prefix = origin.get_osdf_prefix();
        match self.url.split_once(prefix) {
            Some((_, suffix)) => Ok(Url::parse(origin_url)?.join(suffix)?.to_string()),
            None => Err(Box::new(MyError::Transfer(
                "url does not match OSDF prefix".into(),
            ))),
        }
    }

    pub fn execute(&self, creds: &Credentials, origin: &PelicanInfo) -> Result<(), Box<dyn Error>> {
        let cred = creds.get_correct_cred(self, origin)?;
        let final_url = self.get_origin_url(origin)?;
        log::info!("using final url {}", final_url);

        let http_client = reqwest::blocking::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        let do_auth = |x: RequestBuilder| {
            x.header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", cred.access_token),
            )
        };

        let result = match self.mode {
            Verb::Get => {
                let mut file = std::fs::File::create(&self.filename)?;
                let mut ret = do_auth(http_client.get(final_url)).send()?;
                if !ret.status().is_success() {
                    return Err(Box::new(MyError::Transfer(format!(
                        "Error getting file. status {}, body {}",
                        ret.status(),
                        ret.text().unwrap_or("<no_body>".into())
                    ))));
                }
                ret.copy_to(&mut file)?;
                ret
            }
            Verb::Put => {
                let file = std::fs::File::open(&self.filename)?;
                do_auth(http_client.put(final_url).body(file)).send()?
            }
        };

        // Verify response
        if !result.status().is_success() {
            return Err(Box::new(MyError::Transfer(format!(
                "Error transferring file. status {}, body {}",
                result.status(),
                result.text().unwrap_or("<no_body>".into())
            ))));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        time::{SystemTime, UNIX_EPOCH},
    };

    use httpmock::prelude::*;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::{credentials::Credential, logging::test_logger, transfer::Verb};

    #[test]
    fn test_get_origin_url() {
        test_logger();

        let file_path = NamedTempFile::new().ok().unwrap();
        let transfer = Transfer::new(
            "url://namespace/read/scope/file.bin".into(),
            file_path.path().to_str().unwrap().into(),
            Verb::Get,
        );
        let info = PelicanInfo {
            origins: vec!["http://origin".into()],
            osdf_prefix: "url://namespace".into(),
        };

        let ret = transfer.get_origin_url(&info).unwrap();
        assert_eq!(ret, "http://origin/read/scope/file.bin");
    }

    #[test]
    fn test_get_origin_url_extra_slash() {
        test_logger();

        let file_path = NamedTempFile::new().ok().unwrap();
        let transfer = Transfer::new(
            "url://namespace/read/scope/file.bin".into(),
            file_path.path().to_str().unwrap().into(),
            Verb::Get,
        );
        let info = PelicanInfo {
            origins: vec!["http://origin/".into()],
            osdf_prefix: "url://namespace".into(),
        };

        let ret = transfer.get_origin_url(&info).unwrap();
        assert_eq!(ret, "http://origin/read/scope/file.bin");
    }

    #[test]
    fn test_execute_get() {
        test_logger();

        const TEST_DATA: &str = "somebodydata";

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.path("/read/scope/file.bin")
                .header("Authorization", "Bearer token");
            then.status(200).body(TEST_DATA);
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f32();
        let test_cred = Credential {
            access_token: "token".into(),
            token_type: "bearer".into(),
            expires_in: 3600,
            expires_at: now + 3600.,
            scope: vec![
                "storage.read:/read/scope".into(),
                "storage.modify:/write/scope".into(),
            ],
        };
        let creds = Credentials::new(vec![test_cred.clone()]);

        let file_path = NamedTempFile::new().ok().unwrap();
        let transfer = Transfer::new(
            "url://namespace/read/scope/file.bin".into(),
            file_path.path().to_str().unwrap().into(),
            Verb::Get,
        );
        let info = PelicanInfo {
            origins: vec![server.url("/")],
            osdf_prefix: "url://namespace".into(),
        };

        transfer.execute(&creds, &info).unwrap();

        mock.assert();
        assert!(file_path.path().exists());
        let mut data = String::new();
        file_path.as_file().read_to_string(&mut data).unwrap();
        assert_eq!(data, TEST_DATA);
    }

    #[test]
    fn test_execute_put() {
        test_logger();

        const TEST_DATA: &str = "somebodydata";

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.path("/write/scope/file.bin")
                .header("Authorization", "Bearer token")
                .body(TEST_DATA);
            then.status(200);
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f32();
        let test_cred = Credential {
            access_token: "token".into(),
            token_type: "bearer".into(),
            expires_in: 3600,
            expires_at: now + 3600.,
            scope: vec![
                "storage.read:/read/scope".into(),
                "storage.modify:/write/scope".into(),
            ],
        };
        let creds = Credentials::new(vec![test_cred.clone()]);

        let file_path = NamedTempFile::new().ok().unwrap();
        file_path.as_file().write_all(TEST_DATA.as_bytes()).unwrap();

        let transfer = Transfer::new(
            "url://namespace/write/scope/file.bin".into(),
            file_path.path().to_str().unwrap().into(),
            Verb::Put,
        );
        let info = PelicanInfo {
            origins: vec![server.url("/")],
            osdf_prefix: "url://namespace".into(),
        };

        transfer.execute(&creds, &info).unwrap();

        mock.assert();
    }
}
