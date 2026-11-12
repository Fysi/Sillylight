use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use worker::{js_sys::Reflect, wasm_bindgen::prelude::*, *};

const AUTH: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN: &str = "https://oauth2.googleapis.com/token";
const USERINFO: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const HOME: &str = "https://home.googleapis.com/mcp";
const SCOPE: &str = "openid email https://www.googleapis.com/auth/home.platform.v2";
const SESSION_SECONDS: u64 = 30 * 24 * 60 * 60;

#[wasm_bindgen]
extern "C" {
    /// Cloudflare Flagship binding, which workers-rs has no wrapper for.
    type Flags;
    #[wasm_bindgen(method, catch, js_name = getStringValue)]
    async fn string(this: &Flags, key: &str, default: &str) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = crypto, js_name = randomUUID)]
    fn uuid() -> String;
}

/// Errors made from a string are safe to show the user; anything else becomes a blank 500.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    match route(req, env).await {
        Err(Error::RustError(message)) => text(&message, 400),
        other => other,
    }
}

async fn route(mut req: Request, env: Env) -> Result<Response> {
    let url = req.url()?;
    let origin = url.origin().ascii_serialization();
    if req.method() == Method::Post && req.headers().get("origin")?.as_deref() != Some(&origin) {
        return text("Cross-site request blocked", 403);
    }
    let kv = env.kv("KV")?;
    let sid = cookie(&req, "__Host-sid");
    let user = match &sid {
        Some(sid) => kv.get(&format!("s:{sid}")).text().await?,
        None => None,
    };
    let redirect_uri = format!("{origin}/callback");

    match (req.method(), url.path(), user) {
        (Method::Get, "/api/state", user) => {
            let light = match &user {
                Some(sub) => kv.get(&format!("l:{sub}")).json::<Value>().await?,
                None => None,
            };
            Response::from_json(&json!({
                "image": flag(&env, "image-url", "/button.png").await,
                "sound": flag(&env, "sound-url", "/sound.mp3").await,
                "user": user.is_some(),
                "light": light,
            }))
        }
        (Method::Get, "/login", _) => {
            let verifier = uuid() + &uuid();
            let challenge = challenge(&verifier);
            let params = [
                ("client_id", &*env.secret("GOOGLE_CLIENT_ID")?.to_string()),
                ("redirect_uri", &redirect_uri),
                ("response_type", "code"),
                ("scope", SCOPE),
                ("state", &challenge),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("access_type", "offline"),
                ("prompt", "consent"),
            ];
            redirect(Url::parse_with_params(AUTH, params)?.as_str(), "__Host-login", &verifier, 600)
        }
        (Method::Get, "/callback", _) => {
            let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
            let (Some(verifier), Some(code)) = (cookie(&req, "__Host-login"), query.get("code")) else {
                return Err("Sign-in failed, please try again".into());
            };
            if query.get("state").map(|s| &**s) != Some(&*challenge(&verifier)) {
                return Err("Sign-in failed, please try again".into());
            }
            let grant = [
                ("grant_type", "authorization_code"),
                ("code", code),
                ("code_verifier", &verifier),
                ("redirect_uri", &redirect_uri),
            ];
            let tokens = token(&env, &grant).await?;
            let me = google(USERINFO, tokens["access_token"].as_str().unwrap_or_default(), None).await?;
            let (Some(sub), Some(email), Some(refresh)) =
                (me["sub"].as_str(), me["email"].as_str(), tokens["refresh_token"].as_str())
            else {
                return Err("Sign-in failed, please try again".into());
            };
            let allowed = env.secret("ALLOWED_EMAILS")?.to_string();
            if me["email_verified"] != true || !allowed.split(',').any(|a| a.trim().eq_ignore_ascii_case(email)) {
                return text("This Google account is not allowed here", 403);
            }
            let sid = uuid();
            kv.put(&format!("t:{sub}"), refresh)?.execute().await?;
            kv.put(&format!("s:{sid}"), sub)?.expiration_ttl(SESSION_SECONDS).execute().await?;
            redirect("/", "__Host-sid", &sid, SESSION_SECONDS)
        }
        (Method::Post, "/logout", _) => {
            if let Some(sid) = sid {
                kv.delete(&format!("s:{sid}")).await?;
            }
            redirect("/", "__Host-sid", "", 0)
        }
        (Method::Get, "/api/lights", Some(sub)) => {
            let access = access_token(&env, &kv, &sub).await?;
            let (mut lights, mut page) = (vec![], String::new());
            loop {
                let args = json!({"filter": {"shortenedResourceTraits": ["OnOff"]}, "pageToken": page});
                let found = home(&access, "list_home_resources", args).await?;
                for d in found["resources"].as_array().into_iter().flatten() {
                    lights.push(json!({"id": d["id"], "type": d["type"], "name": d["displayName"]}));
                }
                page = found["nextPageToken"].as_str().unwrap_or_default().into();
                if page.is_empty() {
                    return Response::from_json(&lights);
                }
            }
        }
        (Method::Post, "/api/light", Some(sub)) => {
            let light: Value = serde_json::from_str(&req.text().await?)?;
            let (Some(id), Some(kind)) = (light["id"].as_str(), light["type"].as_str()) else {
                return Err("Pick a light".into());
            };
            kv.put(&format!("l:{sub}"), json!({"id": id, "type": kind}).to_string())?.execute().await?;
            Response::empty()
        }
        (Method::Post, "/api/press", Some(sub)) => {
            let light = kv.get(&format!("l:{sub}")).json::<Value>().await?.ok_or("Pick a light first")?;
            let action = json!({"id": light["id"], "type": light["type"], "command": "OnOff.Off"});
            let access = access_token(&env, &kv, &sub).await?;
            let done = home(&access, "run_home_actions", json!({"homeActionRequests": [action]})).await?;
            match done["homeActionResponses"][0]["error"]["message"].as_str() {
                Some(message) => Err(message.into()),
                None => Response::empty(),
            }
        }
        (_, path, None) if path.starts_with("/api/") => text("Sign in first", 401),
        _ => text("Not found", 404),
    }
}

fn cookie(req: &Request, name: &str) -> Option<String> {
    let cookies = req.headers().get("cookie").ok()??;
    cookies.split("; ").find_map(|c| c.strip_prefix(name)?.strip_prefix('=').map(str::to_owned))
}

/// A plain-text reply. The content type stops browsers reading an error message as HTML.
fn text(message: &str, status: u16) -> Result<Response> {
    Ok(Response::ok(message)?.with_status(status))
}

/// The public half of the sign-in secret kept in the browser's cookie (PKCE), also sent as `state`.
fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier))
}

/// Redirects the browser, setting a cookie on the way.
fn redirect(to: &str, name: &str, value: &str, max_age: u64) -> Result<Response> {
    let cookie = format!("{name}={value}; Max-Age={max_age}; Path=/; Secure; HttpOnly; SameSite=Lax");
    Ok(Response::builder().with_status(302).with_header("location", to)?.with_header("set-cookie", &cookie)?.empty())
}

/// Reads a URL from a Flagship flag, falling back to the asset in this repo.
async fn flag(env: &Env, key: &str, default: &str) -> String {
    let flags = Reflect::get(env, &"FLAGS".into()).unwrap_or_default();
    if flags.is_undefined() {
        return default.into();
    }
    match flags.unchecked_into::<Flags>().string(key, default).await.ok().and_then(|v| v.as_string()) {
        Some(url) if url.starts_with("https://") => url,
        _ => default.into(),
    }
}

/// Sends a request to a Google API (POST when there is a body) and parses the JSON reply.
async fn google(url: &str, bearer: &str, body: Option<(&str, String)>) -> Result<Value> {
    let headers = Headers::new();
    let mut init = RequestInit::new();
    if !bearer.is_empty() {
        headers.set("authorization", &format!("Bearer {bearer}"))?;
    }
    if let Some((content_type, body)) = body {
        headers.set("content-type", content_type)?;
        init.with_method(Method::Post).with_body(Some(body.into()));
    }
    let request = Request::new_with_init(url, init.with_headers(headers))?;
    Fetch::Request(request).send().await?.json().await
}

/// Asks Google's token endpoint for tokens, using either a sign-in code or a refresh token.
async fn token(env: &Env, grant: &[(&str, &str)]) -> Result<Value> {
    let id = env.secret("GOOGLE_CLIENT_ID")?.to_string();
    let secret = env.secret("GOOGLE_CLIENT_SECRET")?.to_string();
    let client = [("client_id", &*id), ("client_secret", &*secret)];
    let form = Url::parse_with_params(TOKEN, client.iter().chain(grant))?;
    let body = form.query().unwrap_or_default().to_owned();
    let tokens = google(TOKEN, "", Some(("application/x-www-form-urlencoded", body))).await?;
    match tokens["access_token"] {
        Value::String(_) => Ok(tokens),
        _ => Err("Google sign-in has expired, please sign in again".into()),
    }
}

async fn access_token(env: &Env, kv: &KvStore, sub: &str) -> Result<String> {
    let refresh = kv.get(&format!("t:{sub}")).text().await?.ok_or("Please sign in again")?;
    let tokens = token(env, &[("grant_type", "refresh_token"), ("refresh_token", &refresh)]).await?;
    Ok(tokens["access_token"].as_str().unwrap_or_default().into())
}

/// Calls one tool on Google's Home MCP server and returns the data it produced.
async fn home(access: &str, tool: &str, args: Value) -> Result<Value> {
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}});
    let reply = google(HOME, access, Some(("application/json", call.to_string()))).await?;
    let result = &reply["result"];
    let text = result["content"][0]["text"].as_str();
    if result.is_null() || result["isError"] == true {
        return Err(text.or(reply["error"]["message"].as_str()).unwrap_or("Google Home did not answer").into());
    }
    Ok(match &result["structuredContent"] {
        Value::Null => serde_json::from_str(text.unwrap_or("null"))?,
        data => data.clone(),
    })
}
