use std::fmt::{Debug, Display, Formatter};

use reqwest::{
    header::{HeaderMap, ToStrError},
    RequestBuilder, Response, StatusCode,
};

use async_trait::async_trait;
use digest_auth::{AuthContext, AuthorizationHeader, HttpMethod};

#[async_trait]
pub trait DigestAuth {
    async fn digest_auth(
        &self,
        username: &str,
        password: &str,
    ) -> Result<RequestBuilder, DigestError>;
}

#[async_trait]
impl DigestAuth for RequestBuilder {
    async fn digest_auth(
        &self,
        username: &str,
        password: &str,
    ) -> Result<RequestBuilder, DigestError> {
        let first_response = clone_request_builder(self)?.send().await?;
        match first_response.status() {
            StatusCode::UNAUTHORIZED => {
                let request = clone_request_builder(self)?.build()?;
                let path = request.url().path();
                let method = HttpMethod::from(request.method().as_str());
                let body = request.body().and_then(|b| b.as_bytes());
                let answer = parse_digest_auth_header(
                    first_response.headers(),
                    path,
                    method,
                    body,
                    username,
                    password,
                );

                match answer {
                    Ok(answer) => Ok(clone_request_builder(self)?
                        .header("Authorization", answer.to_header_string())),
                    Err(DigestError::AuthHeaderMissing) => clone_request_builder(self),
                    Err(error) => Err(error),
                }
            }
            _ => clone_request_builder(self),
        }
    }
}

pub async fn digest_auth_simple(
    rb: &RequestBuilder,
    username: &str,
    password: &str,
) -> Result<Response, DigestError> {
    let first_response = clone_request_builder(rb)?.send().await?;
    match first_response.status() {
        StatusCode::UNAUTHORIZED => {
            let request = clone_request_builder(rb)?.build()?;
            let path = request.url().path();
            let method = HttpMethod::from(request.method().as_str());
            let body = request.body().and_then(|b| b.as_bytes());
            let answer = parse_digest_auth_header(
                first_response.headers(),
                path,
                method,
                body,
                username,
                password,
            );

            match answer {
                Ok(answer) => Ok(clone_request_builder(rb)?
                    .header("Authorization", answer.to_header_string())
                    .send()
                    .await?),
                Err(DigestError::AuthHeaderMissing) => Ok(first_response),
                Err(error) => Err(error),
            }
        }
        _ => Ok(first_response),
    }
}

fn clone_request_builder(request_builder: &RequestBuilder) -> Result<RequestBuilder, DigestError> {
    request_builder
        .try_clone()
        .ok_or(DigestError::RequestBuilderNotCloneable)
}

fn parse_digest_auth_header(
    header: &HeaderMap,
    path: &str,
    method: HttpMethod,
    body: Option<&[u8]>,
    username: &str,
    password: &str,
) -> Result<AuthorizationHeader, DigestError> {
    let www_auth = header
        .get("www-authenticate")
        .ok_or(DigestError::AuthHeaderMissing)?
        .to_str()?;
    let context = AuthContext::new_with_method(username, password, path, body, method);
    let mut prompt = digest_auth::parse(www_auth)?;

    Ok(prompt.respond(&context)?)
}
#[derive(Debug)]
pub enum DigestError {
    Reqwest(reqwest::Error),
    DigestAuth(digest_auth::Error),
    ToStr(reqwest::header::ToStrError),
    AuthHeaderMissing,
    RequestBuilderNotCloneable,
}

impl Display for DigestError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use DigestError::*;

        match self {
            Reqwest(e) => std::fmt::Display::fmt(e, f),
            DigestAuth(e) => std::fmt::Display::fmt(e, f),
            ToStr(e) => std::fmt::Display::fmt(e, f),
            RequestBuilderNotCloneable => write!(f, "Request body must not be a stream."),
            AuthHeaderMissing => write!(f, "The header 'www-authenticate' is missing."),
        }
    }
}

impl std::error::Error for DigestError {}

impl From<reqwest::Error> for DigestError {
    fn from(e: reqwest::Error) -> Self {
        DigestError::Reqwest(e)
    }
}

impl From<digest_auth::Error> for DigestError {
    fn from(e: digest_auth::Error) -> Self {
        DigestError::DigestAuth(e)
    }
}

impl From<reqwest::header::ToStrError> for DigestError {
    fn from(e: ToStrError) -> Self {
        DigestError::ToStr(e)
    }
}
