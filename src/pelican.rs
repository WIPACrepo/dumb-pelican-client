use std::error::Error;

use memoize::memoize;
use rand::seq::IndexedRandom;
use reqwest::header::HeaderMap;

use crate::error::MyError;

pub fn handle_link_header(header: &str) -> Result<Vec<&str>, Box<dyn Error>> {
    let mut ret = Vec::new();
    for line in header.split(',') {
        let url = match match line.split_once('<') {
            Some(part) => part.1,
            None => {
                return Err(Box::new(MyError::Pelican(
                    "Error parsing link header".into(),
                )));
            }
        }
        .split_once('>')
        {
            Some(part) => part.0,
            None => {
                return Err(Box::new(MyError::Pelican(
                    "Error parsing link header".into(),
                )));
            }
        };
        ret.push(url);
    }
    Ok(ret)
}

pub fn handle_namespace_header(header: &str) -> Result<&str, Box<dyn Error>> {
    Ok(
        match match header.split_once(',') {
            Some(part) => part.0,
            None => {
                return Err(Box::new(MyError::Pelican(
                    "Error parsing x-pelican-namespace header".into(),
                )));
            }
        }
        .split_once('=')
        {
            Some(part) => part.1,
            None => {
                return Err(Box::new(MyError::Pelican(
                    "Error parsing x-pelican-namespace header".into(),
                )));
            }
        },
    )
}

const OSDF_URL_PREFIX: &str = "osdf://";
const OSDF_DIRECTOR: &str = "https://osdf-director.osg-htc.org/api/v1.0/director/origin";

#[derive(Debug, PartialEq, Clone)]
struct DirectorInfo {
    headers: HeaderMap,
}

#[memoize]
fn get_director_info(path: String) -> DirectorInfo {
    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    let director_url = format!("{}{}", OSDF_DIRECTOR, path);
    let result = http_client
        .get(director_url)
        .send()
        .expect("Cannot contact Pelican director");

    match result.status().as_u16() {
        n if n >= 400 => {
            let text = match result.text() {
                Ok(t) => t,
                Err(_) => "".into(),
            };
            panic!("Error finding Pelican Origin: {}", text)
        }
        _ => {
            let headers = result.headers();
            DirectorInfo {
                headers: headers.clone(),
            }
        }
    }
}

pub struct PelicanInfo {
    pub(crate) origins: Vec<String>,
    pub(crate) osdf_prefix: String,
}

impl PelicanInfo {
    pub fn from_url(url: &str) -> Result<Self, Box<dyn Error>> {
        let path = match url.split_once(OSDF_URL_PREFIX) {
            Some((_, s2)) => s2,
            None => {
                return Err(Box::new(MyError::Pelican(
                    "url is not an OSDF url".into(),
                )));
            }
        };

        let director_info = get_director_info(path.to_string());

        let headers = director_info.headers;
        let origins = match headers.get("link") {
            Some(links) => handle_link_header(links.to_str()?)?,
            None => {
                return Err(Box::new(MyError::Pelican(
                    "No link header when locating origins".into(),
                )));
            }
        };
        log::info!("origin urls: {:?}", origins);
        let namespace = match headers.get("x-pelican-namespace") {
            Some(parts) => handle_namespace_header(parts.to_str()?)?,
            None => {
                return Err(Box::new(MyError::Pelican(
                    "No link header when locating origins".into(),
                )));
            }
        };
        log::info!("pelican namespace: {}", namespace);

        Ok(Self {
            origins: origins.iter().map(|x| x.to_string()).collect(),
            osdf_prefix: format!("{}{}", OSDF_URL_PREFIX, namespace),
        })
    }

    pub fn get_osdf_prefix(&self) -> &str {
        self.osdf_prefix.as_str()
    }

    pub fn choose_origin(&self) -> Result<&str, Box<dyn Error>> {
        let mut rng = rand::rng();
        match self.origins.as_slice().choose(&mut rng) {
            Some(e) => Ok(e),
            None => Err(Box::new(MyError::Pelican(
                "No origins available".into(),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::test_logger;

    #[test]
    fn test_pelican_from_url() {
        test_logger();

        let info = PelicanInfo::from_url("osdf:///icecube/wipac/").unwrap();
        assert_eq!(info.get_osdf_prefix(), "osdf:///icecube/wipac");
        info.choose_origin().unwrap();
    }
}
