mod common;
mod config;
mod proxy;

use crate::config::Config;
use crate::proxy::*;

use std::collections::HashMap;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde_json::json;
use uuid::Uuid;
use worker::*;
use once_cell::sync::Lazy;
use regex::Regex;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+-\d+$").unwrap());
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z]{2})").unwrap());


#[event(fetch)]
pub async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid = env
        .var("UUID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    let config = Config {
        uuid,
        host: host.clone(),
        proxy_addr: host,
        proxy_port: 443,
    };

    Router::with_data(config)
        .on_async("/", tunnel)
        .on("/link", link)
        .on_async("/:proxyip", tunnel)
        .on_async("/Benxx-Project/:proxyip", tunnel)
        .run(req, env)
        .await
}

async fn tunnel(req: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    let mut proxyip = cx.param("proxyip").map(|s| s.to_string()).unwrap_or_default();

    // Logika KV
    if PROXYKV_PATTERN.is_match(&proxyip) {
        let kvid_list: Vec<String> = proxyip.split(',').map(|s| s.to_string()).collect();
        let kv = cx.kv("YUMI")?;
        let mut proxy_kv_str = kv.get("proxy_kv").text().await?.unwrap_or_default();
        let mut rand_buf = [0u8; 1];
        getrandom::getrandom(&mut rand_buf).map_err(|e| Error::from(format!("failed generating random number: {}", e)))?;

        if proxy_kv_str.is_empty() {
            console_log!("getting proxy kv from github...");
            let url = "https://raw.githubusercontent.com/ziyosen/tunel-worker/refs/heads/main/proxy.json";
            let req = Fetch::Url(Url::parse(url)?);
            let mut res = req.send().await?;
            if res.status_code() == 200 {
                proxy_kv_str = res.text().await?;
                kv.put("proxy_kv", &proxy_kv_str)?.expiration_ttl(60 * 60 * 12).execute().await?;
            } else {
                return Err(Error::from(format!("error getting proxy kv: {}", res.status_code())));
            }
        }

        let proxy_kv: HashMap<String, Vec<String>> = serde_json::from_str(&proxy_kv_str)?;
        if kvid_list.is_empty() {
            return Err(Error::from("kvid list kosong"));
        }
        let kv_index = (rand_buf[0] as usize) % kvid_list.len();
        proxyip = kvid_list[kv_index].clone();
        if let Some(list) = proxy_kv.get(&proxyip).filter(|l| !l.is_empty()) {
            let proxyip_index = (rand_buf[0] as usize) % list.len();
            proxyip = list[proxyip_index].clone().replace(':', "-");
        } else {
            // proxyip tidak ada di KV (atau kosong) — pakai apa adanya, tanpa panic.
            proxyip = proxyip.replace(':', "-");
        }
    }

    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade == "websocket" && PROXYIP_PATTERN.is_match(&proxyip) {
        if let Some((addr, port_str)) = proxyip.split_once('-') {
            if let Ok(port) = port_str.parse() {
                cx.data.proxy_addr = addr.to_string();
                cx.data.proxy_port = port;
            }
        }

        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;

        wasm_bindgen_futures::spawn_local(async move {
            let events = match server.events() {
                Ok(ev) => ev,
                Err(e) => {
                    console_error!("[tunnel]: events() gagal: {}", e);
                    return;
                }
            };
            if let Err(e) = ProxyStream::new(cx.data, &server, events).process().await {
                console_error!("[tunnel]: {}", e);
            }
        });

        Response::from_websocket(client)
    } else {
        Response::from_html("hi from wasm!")
    }
}

fn link(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    let host = cx.data.host.to_string();
    let uuid = cx.data.uuid.to_string();

    let vmess_link = {
        let config = json!({
            "ps": "Changli vmess",
            "v": "2",
            "add": host,
            "port": "80",
            "id": uuid,
            "aid": "0",
            "scy": "zero",
            "net": "ws",
            "type": "none",
            "host": host,
            "path": "/ID",
            "tls": "",
            "sni": host,
            "alpn": ""
        });
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };
    let vless_link = format!("vless://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FID&security=tls&sni={host}#Changli vless");
    let trojan_link = format!("trojan://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FID&security=tls&sni={host}#Changli trojan");
    let ss_link = format!("ss://{}@{host}:443?plugin=v2ray-plugin%3Btls%3Bmux%3D0%3Bmode%3Dwebsocket%3Bpath%3D%2FID%3Bhost%3D{host}#Changli ss", URL_SAFE.encode(format!("none:{uuid}")));
    
    Response::from_body(ResponseBody::Body(format!("{vmess_link}\n{vless_link}\n{trojan_link}\n{ss_link}").into()))
}
