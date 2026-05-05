use std::io::{Read, Write};
use std::net::TcpStream;
use std::str::FromStr as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use collections::HashMap;
use futures::AsyncReadExt as _;
use http_client::{AsyncBody, HttpClient, Method, Request, Response};
use url::Url;
use util::ResultExt as _;

use crate::oauth::OAuthTokenProvider;

const PROXY_RECV_TIMEOUT: Duration = Duration::from_millis(500);

pub struct McpHttpProxy {
    local_url: String,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl McpHttpProxy {
    pub fn start(
        http_client: Arc<dyn HttpClient>,
        upstream_url: Url,
        headers: HashMap<String, String>,
        token_provider: Arc<dyn OAuthTokenProvider>,
    ) -> Result<Self> {
        let server = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|err| anyhow!(err).context("failed to bind MCP HTTP proxy"))?;
        let port = server
            .server_addr()
            .to_ip()
            .context("MCP HTTP proxy is not bound to a TCP address")?
            .port();
        let local_url = format!("http://127.0.0.1:{port}/");
        let shutdown = Arc::new(AtomicBool::new(false));

        let thread = std::thread::Builder::new()
            .name(format!("mcp-http-proxy-{port}"))
            .spawn({
                let shutdown = shutdown.clone();
                move || {
                    while !shutdown.load(Ordering::SeqCst) {
                        let Some(request) = (match server.recv_timeout(PROXY_RECV_TIMEOUT) {
                            Ok(request) => request,
                            Err(err) => {
                                log::warn!("MCP HTTP proxy accept failed: {err}");
                                return;
                            }
                        }) else {
                            continue;
                        };

                        if shutdown.load(Ordering::SeqCst) {
                            request.respond(tiny_http::Response::empty(503)).log_err();
                            break;
                        }

                        std::thread::spawn({
                            let http_client = http_client.clone();
                            let upstream_url = upstream_url.clone();
                            let headers = headers.clone();
                            let token_provider = token_provider.clone();
                            move || {
                                respond_to_proxy_request(
                                    request,
                                    http_client,
                                    upstream_url,
                                    headers,
                                    token_provider,
                                );
                            }
                        });
                    }
                }
            })?;

        Ok(Self {
            local_url,
            shutdown,
            thread: Some(thread),
        })
    }

    pub fn local_url(&self) -> &str {
        &self.local_url
    }
}

impl Drop for McpHttpProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);

        if let Ok(url) = Url::parse(&self.local_url)
            && let Some(port) = url.port()
            && let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port))
        {
            stream
                .write_all(
                    b"GET /__zed_mcp_proxy_shutdown HTTP/1.1\r\n\
                      Host: 127.0.0.1\r\n\
                      Connection: close\r\n\r\n",
                )
                .log_err();
        }

        if let Some(thread) = self.thread.take() {
            if let Err(err) = thread.join() {
                log::warn!("MCP HTTP proxy accept thread panicked: {err:?}");
            }
        }
    }
}

fn respond_to_proxy_request(
    mut request: tiny_http::Request,
    http_client: Arc<dyn HttpClient>,
    upstream_url: Url,
    headers: HashMap<String, String>,
    token_provider: Arc<dyn OAuthTokenProvider>,
) {
    let response = gpui::block_on(proxy_request(
        &mut request,
        http_client,
        upstream_url,
        headers,
        token_provider,
    ));

    match response {
        Ok(response) => {
            request.respond(response).log_err();
        }
        Err(err) => {
            log::warn!("MCP HTTP proxy request failed: {err:#}");
            request
                .respond(
                    tiny_http::Response::from_string("MCP proxy request failed")
                        .with_status_code(502),
                )
                .log_err();
        }
    }
}

async fn proxy_request(
    request: &mut tiny_http::Request,
    http_client: Arc<dyn HttpClient>,
    upstream_url: Url,
    headers: HashMap<String, String>,
    token_provider: Arc<dyn OAuthTokenProvider>,
) -> Result<tiny_http::Response<BlockingAsyncBodyReader>> {
    let method = Method::from_bytes(request.method().as_str().as_bytes())
        .context("failed to parse proxied MCP request method")?;

    let mut body = Vec::new();
    request
        .as_reader()
        .read_to_end(&mut body)
        .context("failed to read proxied MCP request body")?;

    let response = send_upstream_request(
        &http_client,
        &upstream_url,
        request.url(),
        method,
        request.headers(),
        &headers,
        &token_provider,
        body,
    )
    .await?;

    let data_length = response_content_length(response.headers());
    let response_headers = response_headers(response.headers());

    let status_code = tiny_http::StatusCode(response.status().as_u16());
    Ok(tiny_http::Response::new(
        status_code,
        response_headers,
        BlockingAsyncBodyReader {
            body: response.into_body(),
        },
        data_length,
        None,
    ))
}

async fn send_upstream_request(
    http_client: &Arc<dyn HttpClient>,
    upstream_url: &Url,
    local_request_url: &str,
    method: Method,
    request_headers: &[tiny_http::Header],
    configured_headers: &HashMap<String, String>,
    token_provider: &Arc<dyn OAuthTokenProvider>,
    body: Vec<u8>,
) -> Result<Response<AsyncBody>> {
    if token_provider.access_token().is_none() {
        try_refresh_token(token_provider).await;
    }

    let mut response = send_upstream_request_once(
        http_client,
        upstream_url,
        local_request_url,
        method.clone(),
        request_headers,
        configured_headers,
        token_provider.access_token(),
        body.clone(),
    )
    .await?;

    if response.status().as_u16() == 401 {
        if try_refresh_token(token_provider).await {
            response = send_upstream_request_once(
                http_client,
                upstream_url,
                local_request_url,
                method,
                request_headers,
                configured_headers,
                token_provider.access_token(),
                body,
            )
            .await?;
        }
    }

    Ok(response)
}

async fn send_upstream_request_once(
    http_client: &Arc<dyn HttpClient>,
    upstream_url: &Url,
    local_request_url: &str,
    method: Method,
    request_headers: &[tiny_http::Header],
    configured_headers: &HashMap<String, String>,
    access_token: Option<String>,
    body: Vec<u8>,
) -> Result<Response<AsyncBody>> {
    let upstream_uri = upstream_uri(upstream_url, local_request_url)?;
    let mut request_builder = Request::builder().method(method).uri(upstream_uri.as_str());

    for header in request_headers {
        let name = header.field.as_str().as_str();
        if should_forward_request_header(name) {
            request_builder = request_builder.header(name, header.value.as_str());
        }
    }

    for (name, value) in configured_headers {
        request_builder = request_builder.header(name.as_str(), value.as_str());
    }

    if let Some(access_token) = access_token {
        request_builder = request_builder.header("Authorization", format!("Bearer {access_token}"));
    }

    let request = request_builder.body(AsyncBody::from(body))?;
    http_client.send(request).await
}

fn upstream_uri(upstream_url: &Url, local_request_url: &str) -> Result<Url> {
    let mut upstream_uri = upstream_url.clone();
    let local_url = Url::parse(&format!("http://127.0.0.1{local_request_url}"))
        .context("failed to parse proxied MCP request URL")?;
    if local_url.query().is_some() {
        upstream_uri.set_query(local_url.query());
    }
    Ok(upstream_uri)
}

fn should_forward_request_header(name: &str) -> bool {
    !is_hop_by_hop_header(name)
        && ![
            "authorization",
            "content-length",
            "host",
            "proxy-authenticate",
            "proxy-authorization",
        ]
        .iter()
        .any(|filtered| name.eq_ignore_ascii_case(filtered))
}

fn should_forward_response_header(name: &str) -> bool {
    !is_hop_by_hop_header(name)
        && !["content-length"]
            .iter()
            .any(|filtered| name.eq_ignore_ascii_case(filtered))
}

fn is_hop_by_hop_header(name: &str) -> bool {
    [
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|filtered| name.eq_ignore_ascii_case(filtered))
}

fn response_headers(headers: &http_client::http::HeaderMap) -> Vec<tiny_http::Header> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            if !should_forward_response_header(name.as_str()) {
                return None;
            }

            match tiny_http::Header::from_bytes(name.as_str().as_bytes(), value.as_bytes()) {
                Ok(header) => Some(header),
                Err(()) => {
                    log::warn!("failed to forward MCP proxy response header {name}");
                    None
                }
            }
        })
        .collect()
}

async fn try_refresh_token(token_provider: &Arc<dyn OAuthTokenProvider>) -> bool {
    match token_provider.try_refresh().await {
        Ok(refreshed) => refreshed,
        Err(err) => {
            log::warn!("failed to refresh MCP OAuth token for proxy: {err:#}");
            false
        }
    }
}

fn response_content_length(headers: &http_client::http::HeaderMap) -> Option<usize> {
    headers
        .get(http_client::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| usize::from_str(value).ok())
}

struct BlockingAsyncBodyReader {
    body: AsyncBody,
}

impl Read for BlockingAsyncBodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        gpui::block_on(self.body.read(buf))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use http_client::Response;

    use super::*;

    struct FakeTokenProvider;

    #[async_trait::async_trait]
    impl OAuthTokenProvider for FakeTokenProvider {
        fn access_token(&self) -> Option<String> {
            Some("zed-token".to_string())
        }

        async fn try_refresh(&self) -> Result<bool> {
            Ok(false)
        }
    }

    #[test]
    fn test_proxy_adds_oauth_header_and_preserves_mcp_headers() {
        let (request_tx, request_rx) = mpsc::channel();
        let http_client = http_client::FakeHttpClient::create(move |mut request| {
            let request_tx = request_tx.clone();
            Box::pin(async move {
                let authorization = request
                    .headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned);
                let session_id = request
                    .headers()
                    .get("mcp-session-id")
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned);
                let mut body = String::new();
                request.body_mut().read_to_string(&mut body).await?;

                request_tx
                    .send((authorization, session_id, body))
                    .expect("test receiver should be available");

                Ok(Response::builder()
                    .status(200)
                    .header("Content-Type", "application/json")
                    .body(AsyncBody::from(r#"{"ok":true}"#))?)
            })
        }) as Arc<dyn HttpClient>;

        let proxy = McpHttpProxy::start(
            http_client,
            Url::parse("https://mcp.example.com/mcp").unwrap(),
            HashMap::default(),
            Arc::new(FakeTokenProvider),
        )
        .unwrap();

        let url = Url::parse(proxy.local_url()).unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", url.port().unwrap())).unwrap();
        stream
            .write_all(
                b"POST / HTTP/1.1\r\n\
                  Host: 127.0.0.1\r\n\
                  Connection: close\r\n\
                  Content-Type: application/json\r\n\
                  Mcp-Session-Id: session-1\r\n\
                  Content-Length: 15\r\n\r\n\
                  {\"jsonrpc\":\"2\"}",
            )
            .unwrap();

        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(response.contains(r#"{"ok":true}"#));

        let (authorization, session_id, body) = request_rx.recv().unwrap();
        assert_eq!(authorization.as_deref(), Some("Bearer zed-token"));
        assert_eq!(session_id.as_deref(), Some("session-1"));
        assert_eq!(body, r#"{"jsonrpc":"2"}"#);
    }
}
