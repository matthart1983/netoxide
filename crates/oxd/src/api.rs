//! The HTTP API. Every route works out who is calling, checks that their
//! role allows the action, then makes a thin call into the commit engine.
//!
//! There are two ways in:
//!
//! - **The Unix socket.** Whoever can open the socket file is an admin, and
//!   their name is the name of the user that owns the calling process, read
//!   from the kernel. Nothing the client sends decides its name.
//! - **The HTTPS listener.** Every request carries an access token, and the
//!   token's role decides what it may do.

use std::{collections::BTreeSet, net::IpAddr, path::PathBuf};

use axum::{
    Json, Router,
    extract::{ConnectInfo, FromRequestParts, Path, State, connect_info::Connected},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
    serve::IncomingStream,
};
use ox_explain::{Explanation, Packet, explain};
use ox_nft::{Ruleset, compile};
use ox_plan::FlowProto;
use ox_schema::Config;
use ox_store::{Action, Identity, Role, Section, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Shared, now, web};

/// Where the HTTPS listener is and the fingerprint of its certificate, set
/// once at start when there is a listener.
pub static HTTPS: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();

/// The user ID of the process on the other end of a Unix socket connection.
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub Option<u32>);

impl Connected<IncomingStream<'_, tokio::net::UnixListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, tokio::net::UnixListener>) -> Peer {
        Peer(stream.io().peer_cred().ok().map(|c| c.uid()))
    }
}

/// The name of a local user, for the audit log.
fn user_name(uid: Option<u32>) -> String {
    let Some(uid) = uid else {
        return "local user".into();
    };
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map_or_else(|| format!("uid {uid}"), |u| u.name)
}

/// Who is calling. Extracting this is what authenticates a request.
pub struct Caller(pub Identity, pub Local);

/// True when the caller is on the box itself, through the Unix socket.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Local(pub bool);

impl Caller {
    /// Refuses the request unless the caller's role allows the action.
    fn may(&self, action: Action) -> Api<&str> {
        if self.0.role.may(action) {
            Ok(&self.0.name)
        } else {
            Err(ApiError(
                StatusCode::FORBIDDEN,
                format!(
                    "{} has the role {}, which may not {}",
                    self.0.name,
                    self.0.role.name,
                    action.describe()
                ),
            ))
        }
    }

    /// Refuses the request if the change it would make reaches outside the
    /// sections of the config the caller's role is held to.
    fn within(&self, touched: &BTreeSet<Section>) -> Api<()> {
        let outside = self.0.role.outside(touched);
        if outside.is_empty() {
            return Ok(());
        }
        let names = |s: &mut dyn Iterator<Item = &Section>| {
            s.map(|x| x.as_str()).collect::<Vec<_>>().join(", ")
        };
        Err(ApiError(
            StatusCode::FORBIDDEN,
            format!(
                "{} has the role {}, which may only change {}; this would also change {}",
                self.0.name,
                self.0.role.name,
                names(&mut self.0.role.sections.iter().flatten()),
                names(&mut outside.iter()),
            ),
        ))
    }
}

/// Checks that the caller may save `text` as the candidate `name`: the
/// change must stay inside the caller's sections, and so must the candidate
/// it would replace, so a limited role cannot wipe out a draft it could not
/// have deleted.
fn may_save(
    caller: &Caller,
    e: &ox_store::Engine<Box<dyn ox_store::Applier>>,
    name: &str,
    text: &str,
) -> Api<()> {
    caller.within(&e.touched_by(text)?)?;
    if let Ok(old) = e.candidate(name) {
        caller.within(&e.touched_by(&old)?)?;
    }
    Ok(())
}

impl FromRequestParts<Shared> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Caller, ApiError> {
        // A connection on the Unix socket carries the peer's user ID.
        if let Some(ConnectInfo(Peer(uid))) = parts.extensions.get::<ConnectInfo<Peer>>() {
            return Ok(Caller(
                Identity {
                    name: user_name(*uid),
                    role: Role::admin(),
                },
                Local(true),
            ));
        }
        let secret = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| {
                ApiError(
                    StatusCode::UNAUTHORIZED,
                    "send an access token: Authorization: Bearer <token>".into(),
                )
            })?;
        state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .identify(secret, now())
            .map(|identity| Caller(identity, Local(false)))
            .ok_or_else(|| {
                ApiError(
                    StatusCode::UNAUTHORIZED,
                    "this access token is unknown, expired or revoked".into(),
                )
            })
    }
}

/// What the box is doing right now: traffic, connections and what is being
/// blocked, one reading a second. Asking is what keeps the readings coming.
fn live_view(
    State(s): State<Shared>,
    caller: Caller,
    live: &crate::live::SharedLive,
) -> Api<Response> {
    caller.may(Action::Read)?;
    let text = s
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .running_config()?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "there is no commit yet".into()))?;
    let config = Config::from_toml(&text).map_err(invalid)?;
    let mut live = live.lock().unwrap_or_else(|e| e.into_inner());
    // So the first answer already names the networks, before any reading.
    live.set_plan(crate::live::Plan::new(&config));
    Ok(Json(live.view(std::time::Instant::now())).into_response())
}

pub fn router(
    shared: Shared,
    lease_file: PathBuf,
    state_dir: PathBuf,
    live: crate::live::SharedLive,
) -> Router {
    let key_dir = state_dir.clone();
    let backup_dir = state_dir.clone();
    let vpn_dir = state_dir.clone();
    Router::new()
        .route(
            "/v1/actions/vpn-peer",
            post(
                move |state: State<Shared>, caller: Caller, body: Json<VpnPeerBody>| {
                    let dir = vpn_dir.clone();
                    async move { action_vpn_peer(state, caller, &dir, body) }
                },
            ),
        )
        .route(
            "/v1/wireguard",
            get(move |state: State<Shared>, caller: Caller| {
                let dir = state_dir.clone();
                async move { wireguard(state, caller, dir).await }
            }),
        )
        .route(
            "/v1/wireguard/{iface}/key",
            get(move |caller: Caller, Path(iface): Path<String>| {
                let dir = key_dir.clone();
                async move { wireguard_key(&caller, &dir, &iface) }
            }),
        )
        .route(
            "/v1/backup",
            get({
                let dir = backup_dir.clone();
                move |state: State<Shared>, caller: Caller| {
                    let dir = dir.clone();
                    async move { backup(state, caller, &dir) }
                }
            }),
        )
        .route(
            "/v1/restore",
            post({
                let dir = backup_dir;
                move |state: State<Shared>, caller: Caller, body: Json<Backup>| {
                    let dir = dir.clone();
                    async move { restore(state, caller, &dir, body) }
                }
            }),
        )
        .route(
            "/v1/live",
            get(move |state: State<Shared>, caller: Caller| {
                let live = live.clone();
                async move { live_view(state, caller, &live) }
            }),
        )
        .route("/v1/whoami", get(whoami))
        .route("/v1/status", get(status))
        .route("/v1/running", get(running))
        .route("/v1/running/json", get(running_json))
        .route("/v1/actions/forward", post(action_forward))
        .route("/v1/actions/block", post(action_block))
        .route("/v1/commits", get(commits))
        .route("/v1/commits/{id}", get(commit))
        .route("/v1/candidates", get(candidates))
        .route(
            "/v1/candidates/{name}",
            get(candidate).put(put_candidate).delete(delete_candidate),
        )
        .route("/v1/candidates/{name}/meta", get(candidate_meta))
        .route("/v1/candidates/{name}/plan", post(plan))
        .route("/v1/candidates/{name}/approve", post(approve))
        .route("/v1/candidates/{name}/commit", post(commit_candidate))
        .route("/v1/check", post(check))
        .route("/v1/confirm", post(confirm))
        .route("/v1/revert", post(revert))
        .route("/v1/rollback", post(rollback))
        .route("/v1/explain", post(explain_packet))
        .route("/v1/audit", get(audit))
        .route("/v1/hygiene", get(hygiene))
        .route("/metrics", get(metrics))
        .route("/v1/kernel", get(kernel))
        .route("/v1/settings", get(settings).put(put_settings))
        .route("/v1/tokens", get(tokens).post(create_token))
        .route("/v1/tokens/{name}", axum::routing::delete(revoke_token))
        .route("/v1/roles", get(roles).post(create_role))
        .route("/v1/roles/{name}", axum::routing::delete(delete_role))
        .route("/v1/leases", {
            let path = lease_file.clone();
            get(move |caller: Caller| {
                let path = path.clone();
                async move { leases(&caller, path) }
            })
        })
        .route(
            "/v1/home",
            get(move |state: State<Shared>, caller: Caller| {
                let path = lease_file.clone();
                async move { home(state, caller, path) }
            }),
        )
        .route("/v1/actions/access", post(action_access))
        .route("/v1/actions/network", post(action_network))
        .route("/v1/actions/block-site", post(action_block_site))
        .merge(crate::setup::routes())
        .merge(web::routes())
        .with_state(shared)
}

/// An error as the API returns it: a status and `{"error": "..."}`.
pub struct ApiError(StatusCode, String);

impl ApiError {
    pub fn new(status: StatusCode, message: &str) -> ApiError {
        ApiError(status, message.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> ApiError {
        let status = match &e {
            StoreError::NotFound(_) => StatusCode::NOT_FOUND,
            StoreError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            StoreError::Busy { .. } | StoreError::NothingPending => StatusCode::CONFLICT,
            StoreError::NeedsApproval(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError(status, e.to_string())
    }
}

fn invalid(msg: impl ToString) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.to_string())
}

type Api<T> = Result<T, ApiError>;

fn load(text: &str) -> Api<(Config, Ruleset)> {
    let config = Config::from_toml(text).map_err(invalid)?;
    let ruleset = compile(&config).map_err(invalid)?;
    Ok((config, ruleset))
}

async fn whoami(caller: Caller) -> Response {
    let role = &caller.0.role;
    Json(json!({
        "name": caller.0.name,
        "role": role.name,
        "can": role.can,
        "sections": role.sections,
    }))
    .into_response()
}

async fn status(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    let mut v = serde_json::to_value(e.status(now())?).expect("status is plain JSON");
    v["four_eyes"] = json!(e.settings()?.four_eyes);
    v["https"] = HTTPS.get().cloned().unwrap_or_default();
    v["version"] = json!(env!("CARGO_PKG_VERSION"));
    // The setup code is for someone at the box, never for a token.
    if caller.1 == Local(true)
        && let Some(code) = crate::setup::code_for_local(v["running"].is_object())
    {
        v["setup_code"] = json!(code);
    }
    Ok(Json(v).into_response())
}

async fn running(State(s): State<Shared>, caller: Caller) -> Api<String> {
    caller.may(Action::Read)?;
    s.lock()
        .unwrap_or_else(|e| e.into_inner())
        .running_config()?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "there is no commit yet".into()))
}

/// The running config as JSON, with what it does in plain sentences.
async fn running_json(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    let text = s
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .running_config()?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "there is no commit yet".into()))?;
    let (config, ruleset) = load(&text)?;
    Ok(Json(json!({
        "config": config,
        "summary": ruleset.summary(),
        "describe": ox_setup::describe(&config),
    }))
    .into_response())
}

/// Applies a one-step action to the running config and saves the result
/// as a candidate. Nothing is applied to the box.
fn act(
    s: &Shared,
    caller: &Caller,
    candidate: &str,
    change: impl FnOnce(&mut Config) -> Result<Vec<String>, String>,
) -> Api<Response> {
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    let text = e.running_config()?.ok_or_else(|| {
        invalid(
            "there is no commit yet; set the box up and commit a first config before changing it",
        )
    })?;
    let mut config = Config::from_toml(&text).map_err(invalid)?;
    let done = change(&mut config).map_err(invalid)?;
    let text = config.to_toml();
    may_save(caller, &e, candidate, &text)?;
    e.put_candidate(candidate, &text, &caller.0.name, now())?;
    Ok(Json(json!({ "candidate": candidate, "done": done })).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardBody {
    name: String,
    /// The outside port, such as `tcp/443`.
    port: String,
    to: IpAddr,
    #[serde(default)]
    to_port: Option<u16>,
    #[serde(default)]
    address: Option<IpAddr>,
}

async fn action_forward(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<ForwardBody>,
) -> Api<Response> {
    caller.may(Action::Edit)?;
    let req = ox_setup::ForwardRequest {
        name: body.name.clone(),
        service: body.port.parse().map_err(invalid)?,
        to: body.to,
        to_port: body.to_port,
        address: body.address,
    };
    act(
        &s,
        &caller,
        &ox_setup::candidate_name("forward", &body.name),
        |c| ox_setup::add_forward(c, &req),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VpnPeerBody {
    name: String,
    /// How the device finds the box from outside: a name or an address.
    endpoint: String,
    /// The device's own public key. Without it the daemon makes a key pair
    /// for the device and returns the private key once.
    #[serde(default)]
    public_key: Option<String>,
}

/// Adds a device to the VPN as a candidate, and returns the config file
/// for the device.
fn action_vpn_peer(
    State(s): State<Shared>,
    caller: Caller,
    dir: &std::path::Path,
    Json(body): Json<VpnPeerBody>,
) -> Api<Response> {
    let who = caller.may(Action::Edit)?;
    let endpoint = body.endpoint.trim();
    let plain = !endpoint.is_empty()
        && endpoint.len() <= 255
        && endpoint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    if !plain {
        return Err(invalid(
            "say how the device reaches the box from outside: a name such as home.example.net, or an address",
        ));
    }
    let (private, public) = match &body.public_key {
        Some(key) => (None, key.clone()),
        None => {
            let (private, public) = crate::wg::new_keypair()
                .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            (Some(private), public)
        }
    };
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    let text = e.running_config()?.ok_or_else(|| {
        invalid(
            "there is no commit yet; set the box up and commit a first config before changing it",
        )
    })?;
    let mut config = Config::from_toml(&text).map_err(invalid)?;
    let peer = ox_setup::add_vpn_peer(
        &mut config,
        &ox_setup::VpnPeerRequest {
            name: body.name.clone(),
            public_key: public,
        },
    )
    .map_err(invalid)?;
    let box_key = crate::wg::public_key(dir, &peer.tunnel)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let candidate = ox_setup::candidate_name("vpn", &body.name);
    let text = config.to_toml();
    may_save(&caller, &e, &candidate, &text)?;
    e.put_candidate(&candidate, &text, who, now())?;
    // The device's private key goes back in this answer and nowhere else:
    // not into the candidate, the audit log or the state directory.
    let client_config = ox_setup::client_config(
        &peer,
        private
            .as_deref()
            .unwrap_or("<the device's own private key>"),
        &box_key,
        endpoint,
    );
    Ok(Json(json!({
        "candidate": candidate,
        "done": peer.done,
        // A code to scan is only any use with the device's key inside it.
        "qr": private.as_ref().and_then(|_| ox_setup::qr_rows(&client_config)),
        "client_config": client_config,
        "key_made_here": private.is_some(),
    }))
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessBody {
    /// The network the traffic comes from, by zone name.
    from: String,
    to: String,
    allow: bool,
}

/// Lets one network reach another, or stops it, as a candidate.
async fn action_access(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<AccessBody>,
) -> Api<Response> {
    caller.may(Action::Edit)?;
    let name = ox_setup::candidate_name(
        if body.allow { "allow" } else { "block" },
        &format!("{}-{}", body.from, body.to),
    );
    act(&s, &caller, &name, |c| {
        ox_setup::set_access(c, &body.from, &body.to, body.allow)
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteBody {
    /// The website's name, such as example.com.
    name: String,
    /// True to block it, false to lift the block.
    block: bool,
}

/// Blocks a website by name in the box's DNS, or lifts the block, as a candidate.
async fn action_block_site(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<SiteBody>,
) -> Api<Response> {
    caller.may(Action::Edit)?;
    let site = ox_setup::site_name(&body.name).map_err(invalid)?;
    let name = ox_setup::candidate_name(if body.block { "block" } else { "unblock" }, &site);
    act(&s, &caller, &name, |c| {
        ox_setup::block_name(c, &site, body.block)
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkBody {
    /// What to call the network, such as "Guest Wi-Fi".
    name: String,
    /// The inside port that carries it.
    port: String,
    /// Its VLAN number on that port.
    vlan: u16,
    /// The box's address on it, with a prefix length. Left out, one is chosen.
    #[serde(default)]
    address: Option<String>,
    /// Whether it may reach the internet. Yes unless said otherwise.
    #[serde(default = "yes")]
    internet: bool,
}

fn yes() -> bool {
    true
}

/// Adds a network of its own, such as one for guests, as a candidate.
async fn action_network(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<NetworkBody>,
) -> Api<Response> {
    caller.may(Action::Edit)?;
    let address = match body
        .address
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
    {
        Some(text) => Some(text.parse().map_err(|_| {
            invalid(format!(
                "'{text}' is not an address with a prefix length, such as 192.168.20.1/24"
            ))
        })?),
        None => None,
    };
    let req = ox_setup::NetworkRequest {
        name: body.name.clone(),
        port: body.port.clone(),
        vlan: body.vlan,
        address,
        internet: body.internet,
    };
    act(
        &s,
        &caller,
        &ox_setup::candidate_name("network", &body.name),
        |c| ox_setup::add_network(c, &req),
    )
}

/// The simple view of the running config: the networks, who can reach
/// what, what is let in from the internet, and how many devices each
/// network has handed an address to.
fn home(State(s): State<Shared>, caller: Caller, lease_file: PathBuf) -> Api<Response> {
    caller.may(Action::Read)?;
    let text = s
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .running_config()?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "there is no commit yet".into()))?;
    let config = Config::from_toml(&text).map_err(invalid)?;
    let grid = ox_setup::grid(&config);
    let leases =
        ox_services::parse_leases(&std::fs::read_to_string(lease_file).unwrap_or_default());
    let devices: Vec<usize> = grid
        .networks
        .iter()
        .map(|n| {
            leases
                .iter()
                .filter_map(|l| l.address.parse::<IpAddr>().ok())
                .filter(|a| {
                    ox_setup::interface_for(&config, *a).is_some_and(|i| n.interfaces.contains(&i))
                        && !n.internet
                })
                .count()
        })
        .collect();
    let mut v = serde_json::to_value(&grid).expect("the grid is plain JSON");
    v["devices"] = json!(devices);
    Ok(Json(v).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockBody {
    address: String,
    #[serde(default)]
    name: Option<String>,
}

async fn action_block(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<BlockBody>,
) -> Api<Response> {
    caller.may(Action::Edit)?;
    let net: ox_schema::Net = body.address.parse().map_err(invalid)?;
    let name = body
        .name
        .clone()
        .filter(|n| !n.is_empty())
        .unwrap_or(body.address.clone());
    act(
        &s,
        &caller,
        &ox_setup::candidate_name("block", &name),
        |c| ox_setup::block(c, net, &name),
    )
}

async fn commits(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    Ok(Json(s.lock().unwrap_or_else(|e| e.into_inner()).history()?).into_response())
}

async fn commit(State(s): State<Shared>, caller: Caller, Path(id): Path<u64>) -> Api<Response> {
    caller.may(Action::Read)?;
    let e = s.lock().unwrap_or_else(|e| e.into_inner());
    Ok(Json(json!({ "commit": e.commit(id)?, "config": e.commit_config(id)? })).into_response())
}

async fn candidates(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    Ok(Json(s.lock().unwrap_or_else(|e| e.into_inner()).candidates()?).into_response())
}

async fn candidate(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<String> {
    caller.may(Action::Read)?;
    Ok(s.lock()
        .unwrap_or_else(|e| e.into_inner())
        .candidate(&name)?)
}

async fn candidate_meta(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<Response> {
    caller.may(Action::Read)?;
    Ok(Json(
        s.lock()
            .unwrap_or_else(|e| e.into_inner())
            .candidate_meta(&name)?,
    )
    .into_response())
}

async fn put_candidate(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
    body: String,
) -> Api<Response> {
    let who = caller.may(Action::Edit)?;
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    may_save(&caller, &e, &name, &body)?;
    e.put_candidate(&name, &body, who, now())?;
    Ok(Json(json!({ "saved": name })).into_response())
}

async fn delete_candidate(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<Response> {
    let who = caller.may(Action::Edit)?;
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    caller.within(&e.touched_by(&e.candidate(&name)?)?)?;
    e.delete_candidate(&name, who, now())?;
    Ok(Json(json!({ "deleted": name })).into_response())
}

async fn approve(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<Response> {
    let who = caller.may(Action::Approve)?;
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    caller.within(&e.touched_by(&e.candidate(&name)?)?)?;
    Ok(Json(e.approve(&name, who, now())?).into_response())
}

/// Checks a config without storing it. The body is the config text.
async fn check(caller: Caller, body: String) -> Api<Response> {
    caller.may(Action::Read)?;
    let (config, ruleset) = load(&body)?;
    Ok(Json(json!({
        "valid": true,
        "summary": ruleset.summary(),
        "describe": ox_setup::describe(&config),
    }))
    .into_response())
}

#[derive(Serialize)]
struct PlanView {
    /// True when there is no running commit to compare with.
    first_commit: bool,
    summary: String,
    changes: Vec<String>,
    flows_checked: Option<usize>,
    /// Flows whose verdict the candidate changes.
    impact: Vec<String>,
    /// The change in plain sentences: what the box starts doing.
    starts: Vec<String>,
    /// And what it stops doing.
    stops: Vec<String>,
    /// The change in a few sentences about networks. Empty when it has
    /// no such sentence.
    headline: Vec<String>,
}

/// The body, if any, is a JSON Lines file of observed flows.
async fn plan(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
    body: String,
) -> Api<Response> {
    caller.may(Action::Read)?;
    let (candidate_text, running_text) = {
        let e = s.lock().unwrap_or_else(|e| e.into_inner());
        (e.candidate(&name)?, e.running_config()?)
    };
    let (new, new_rs) = load(&candidate_text)?;
    let mut view = PlanView {
        first_commit: running_text.is_none(),
        summary: new_rs.summary(),
        changes: vec![],
        flows_checked: None,
        impact: vec![],
        starts: vec![],
        stops: vec![],
        headline: vec![],
    };
    if let Some(text) = running_text {
        let (old, old_rs) = load(&text)?;
        view.changes = ox_plan::diff(&old, &new)
            .iter()
            .map(ToString::to_string)
            .collect();
        (view.starts, view.stops) = ox_setup::plain_changes(&old, &new);
        view.headline = ox_setup::headline(&old, &new);
        if !body.trim().is_empty() {
            let flows = ox_plan::parse_flows(&body).map_err(invalid)?;
            let hits = ox_plan::impact(&old_rs, &new_rs, &flows).map_err(invalid)?;
            view.flows_checked = Some(flows.len());
            view.impact = hits.iter().map(ToString::to_string).collect();
        }
    }
    Ok(Json(view).into_response())
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct CommitBody {
    /// Revert unless confirmed within this many seconds.
    #[serde(default)]
    confirm_secs: Option<u64>,
    #[serde(default)]
    reason: String,
    /// For rollback: how many commits to go back.
    #[serde(default)]
    steps: Option<u64>,
}

fn check_window(body: &CommitBody) -> Api<()> {
    match body.confirm_secs {
        Some(s) if !(10..=3600).contains(&s) => Err(invalid(
            "the confirm window must be between 10 seconds and 1 hour",
        )),
        _ => Ok(()),
    }
}

async fn commit_candidate(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
    Json(body): Json<CommitBody>,
) -> Api<Response> {
    let who = caller.may(Action::Commit)?;
    check_window(&body)?;
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    caller.within(&e.touched_by(&e.candidate(&name)?)?)?;
    let c = e.commit_candidate(&name, who, &body.reason, body.confirm_secs, now())?;
    Ok(Json(c).into_response())
}

async fn confirm(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    let who = caller.may(Action::Commit)?;
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    caller.within(&e.touched_by_pending()?)?;
    Ok(Json(e.confirm(who, now())?).into_response())
}

async fn revert(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    let who = caller.may(Action::Commit)?;
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    caller.within(&e.touched_by_pending()?)?;
    Ok(Json(e.revert(who, false, now())?).into_response())
}

async fn rollback(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<CommitBody>,
) -> Api<Response> {
    let who = caller.may(Action::Rollback)?;
    check_window(&body)?;
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    caller.within(&e.touched_by_rollback(body.steps.unwrap_or(1))?)?;
    let c = e.rollback(
        body.steps.unwrap_or(1),
        who,
        &body.reason,
        body.confirm_secs,
        now(),
    )?;
    Ok(Json(c).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainBody {
    src: IpAddr,
    dst: IpAddr,
    proto: FlowProto,
    #[serde(default)]
    dport: Option<u16>,
    /// The interface the packet arrives on. Left out, it is worked out
    /// from the source address: the network it is on, else the internet side.
    #[serde(default, rename = "in")]
    iif: Option<String>,
    /// Also evaluate against this candidate.
    #[serde(default)]
    candidate: Option<String>,
}

#[derive(Serialize)]
struct ExplainView {
    verdict: &'static str,
    /// ID of the rule that decided, or null for a default.
    rule: Option<String>,
    steps: Vec<StepView>,
    /// The same explanation as text.
    text: String,
}

#[derive(Serialize)]
struct StepView {
    label: &'static str,
    value: String,
    detail: String,
}

fn view(e: Explanation) -> ExplainView {
    ExplainView {
        verdict: e.verdict.as_str(),
        text: e.to_string(),
        rule: e.rule.map(|r| r.id),
        steps: e
            .steps
            .into_iter()
            .map(|s| StepView {
                label: s.label,
                value: s.value,
                detail: s.detail,
            })
            .collect(),
    }
}

async fn explain_packet(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<ExplainBody>,
) -> Api<Response> {
    caller.may(Action::Read)?;
    let (running_text, candidate_text) = {
        let e = s.lock().unwrap_or_else(|e| e.into_inner());
        (
            e.running_config()?,
            body.candidate
                .as_deref()
                .map(|n| e.candidate(n))
                .transpose()?,
        )
    };
    let iif = match body.iif.filter(|i| !i.trim().is_empty()) {
        Some(iif) => iif,
        None => running_text
            .as_deref()
            .and_then(|text| Config::from_toml(text).ok())
            .and_then(|config| ox_setup::interface_for(&config, body.src))
            .ok_or_else(|| {
                invalid("cannot tell which network that address is on; say which interface the packet arrives on")
            })?,
    };
    let packet = Packet {
        src: body.src,
        dst: body.dst,
        l4: body.proto.into(),
        dport: body.dport,
        iif,
        // What the machine has now, so an address the provider assigned
        // counts as the box's own, as it does for the kernel.
        box_addrs: nix::ifaddrs::getifaddrs()
            .map(|all| {
                all.filter_map(|a| {
                    let s = a.address?;
                    s.as_sockaddr_in()
                        .map(|v4| std::net::IpAddr::V4(v4.ip()))
                        .or_else(|| s.as_sockaddr_in6().map(|v6| std::net::IpAddr::V6(v6.ip())))
                })
                .collect()
            })
            .unwrap_or_default(),
    };
    let run = |text: &str| -> Api<ExplainView> {
        let (_, rs) = load(text)?;
        Ok(view(explain(&rs, &packet).map_err(invalid)?))
    };
    Ok(Json(json!({
        "packet": packet.to_string(),
        "running": running_text.as_deref().map(run).transpose()?,
        "candidate": candidate_text.as_deref().map(run).transpose()?,
    }))
    .into_response())
}

/// The running config's tunnels: the box's public key, and each peer with
/// what the kernel knows about it.
async fn wireguard(State(s): State<Shared>, caller: Caller, dir: PathBuf) -> Api<Response> {
    caller.may(Action::Read)?;
    let (text, live) = {
        let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
        (e.running_config()?, e.applier().name() == "kernel")
    };
    let Some(text) = text else {
        return Ok(Json(json!([])).into_response());
    };
    let (config, _) = load(&text)?;
    let mut tunnels = vec![];
    for (name, wg) in &config.wireguard {
        let seen = if live {
            crate::wg::peers(name).await
        } else {
            vec![]
        };
        let peers: Vec<_> = wg
            .peers
            .iter()
            .map(|p| {
                let k = seen.iter().find(|k| k.public_key == p.public_key);
                json!({
                    "name": p.name,
                    "public_key": p.public_key,
                    "allowed": p.allowed,
                    "endpoint": p.endpoint,
                    "seen_at": k.and_then(|k| k.endpoint.clone()),
                    "last_handshake": k.and_then(|k| k.last_handshake),
                    "rx_bytes": k.map_or(0, |k| k.rx_bytes),
                    "tx_bytes": k.map_or(0, |k| k.tx_bytes),
                })
            })
            .collect();
        tunnels.push(json!({
            "name": name,
            "zone": wg.zone,
            "addresses": wg.addresses,
            "listen_port": wg.listen_port,
            "public_key": crate::wg::public_key(&dir, name)
                .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?,
            "peers": peers,
        }));
    }
    Ok(Json(json!(tunnels)).into_response())
}

/// How many tunnel keys the key route will make.
const MAX_TUNNEL_KEYS: usize = 32;

/// The box's public key for a tunnel, made if there is none yet, so two
/// sites can swap keys before either has the tunnel in its config.
fn wireguard_key(caller: &Caller, dir: &std::path::Path, iface: &str) -> Api<Response> {
    caller.may(Action::Edit)?;
    caller.within(&BTreeSet::from([Section::Vpn]))?;
    let ok = !iface.is_empty()
        && iface.len() <= 15
        && iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    if !ok {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "that is not an interface name".into(),
        ));
    }
    // Each new name makes a key file. A box has a handful of tunnels, so a
    // caller asking for many names is filling the disk, not swapping keys.
    let keys = dir.join("wireguard");
    let held = std::fs::read_dir(&keys).map_or(0, Iterator::count);
    if held >= MAX_TUNNEL_KEYS && !keys.join(format!("{iface}.key")).exists() {
        return Err(invalid(format!(
            "this box already holds keys for {MAX_TUNNEL_KEYS} tunnels; remove unused ones from {} first",
            keys.display()
        )));
    }
    let key = crate::wg::public_key(dir, iface)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "interface": iface, "public_key": key })).into_response())
}

/// The addresses DHCP has handed out. Empty when DHCP is not served.
fn leases(caller: &Caller, path: PathBuf) -> Api<Response> {
    caller.may(Action::Read)?;
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let rows: Vec<_> = ox_services::parse_leases(&text)
        .into_iter()
        .map(
            |l| json!({ "expires": l.expires, "mac": l.mac, "address": l.address, "name": l.name }),
        )
        .collect();
    Ok(Json(rows).into_response())
}

/// The whole audit log. A broken chain is an error, with the line named.
async fn audit(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::ReadAudit)?;
    let entries = s
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .audit()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "verified": true, "entries": entries })).into_response())
}

/// Packets counted per rule ID, summed over the kernel rules a config rule became.
fn kernel_hits(dump: &serde_json::Value) -> std::collections::BTreeMap<String, (u64, u64)> {
    let mut out = std::collections::BTreeMap::new();
    for item in dump["nftables"].as_array().into_iter().flatten() {
        let rule = &item["rule"];
        let Some(id) = rule["comment"].as_str() else {
            continue;
        };
        for e in rule["expr"].as_array().into_iter().flatten() {
            if let (Some(p), Some(b)) = (
                e["counter"]["packets"].as_u64(),
                e["counter"]["bytes"].as_u64(),
            ) {
                let entry = out.entry(id.to_string()).or_insert((0, 0));
                entry.0 += p;
                entry.1 += b;
            }
        }
    }
    out
}

/// Rules in the running config that never apply, add nothing, allow
/// everything, or have seen no packets since the ruleset was loaded.
async fn hygiene(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    let (text, dump) = {
        let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
        (e.running_config()?, e.applier().dump().ok())
    };
    let Some(text) = text else {
        return Ok(Json(json!([])).into_response());
    };
    let (_, rs) = load(&text)?;
    let mut rows: Vec<_> = ox_nft::hygiene(&rs)
        .into_iter()
        .map(|f| json!({ "from": f.from, "to": f.to, "rule": f.rule, "kind": f.kind.as_str(), "detail": f.detail }))
        .collect();
    // Counters only exist when rules are really in the kernel.
    let hits = dump.as_ref().map(kernel_hits).unwrap_or_default();
    if !hits.is_empty() {
        let flagged: Vec<String> = rows
            .iter()
            .map(|r| r["rule"].as_str().unwrap_or("").to_string())
            .collect();
        for chain in &rs.chains {
            for rule in &chain.rules {
                if hits.get(&rule.id).is_some_and(|h| h.0 == 0) && !flagged.contains(&rule.id) {
                    rows.push(json!({
                        "from": chain.from, "to": chain.to, "rule": rule.id, "kind": "no packets",
                        "detail": "no packet has matched this rule since the ruleset was last loaded",
                    }));
                }
            }
        }
    }
    Ok(Json(rows).into_response())
}

/// Counters in the Prometheus text format.
async fn metrics(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    let (status, dump, audit_len) = {
        let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
        (
            e.status(now())?,
            e.applier().dump().ok(),
            Some(e.audit_len()),
        )
    };
    let mut out = String::new();
    let mut metric = |name: &str, help: &str, kind: &str, lines: Vec<(String, u64)>| {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        for (labels, value) in lines {
            out.push_str(&format!("{name}{labels} {value}\n"));
        }
    };
    let one = |v: u64| vec![(String::new(), v)];
    metric(
        "netoxide_running_commit",
        "ID of the commit the box is running, 0 before the first commit.",
        "gauge",
        one(status.running.as_ref().map_or(0, |c| c.id)),
    );
    metric(
        "netoxide_commit_pending",
        "1 while a commit is waiting to be confirmed.",
        "gauge",
        one(u64::from(status.reverts_in.is_some())),
    );
    metric(
        "netoxide_commit_reverts_in_seconds",
        "Seconds until the pending commit reverts, 0 when none is pending.",
        "gauge",
        one(status.reverts_in.unwrap_or(0)),
    );
    metric(
        "netoxide_candidates",
        "Candidates stored on the box.",
        "gauge",
        one(status.candidates.len() as u64),
    );
    metric(
        "netoxide_service_up",
        "1 when a service the config asks for is running.",
        "gauge",
        status
            .services
            .iter()
            .map(|(name, state)| {
                (
                    format!("{{service=\"{name}\"}}"),
                    u64::from(state == "running"),
                )
            })
            .collect(),
    );
    if let Some(n) = audit_len {
        metric(
            "netoxide_audit_entries",
            "Entries in the audit log.",
            "counter",
            one(n),
        );
    }
    let hits = dump.as_ref().map(kernel_hits).unwrap_or_default();
    // Rule IDs are lowercase letters, digits and hyphens, plus "default a-b",
    // so they need no escaping as label values.
    let label = |id: &String| format!("{{rule=\"{id}\"}}");
    metric(
        "netoxide_rule_packets_total",
        "Packets matched per rule since the ruleset was last loaded.",
        "counter",
        hits.iter().map(|(id, h)| (label(id), h.0)).collect(),
    );
    metric(
        "netoxide_rule_bytes_total",
        "Bytes matched per rule since the ruleset was last loaded.",
        "counter",
        hits.iter().map(|(id, h)| (label(id), h.1)).collect(),
    );
    for (file, name, help) in [
        (
            "nf_conntrack_count",
            "netoxide_conntrack_entries",
            "Connections the kernel is tracking.",
        ),
        (
            "nf_conntrack_max",
            "netoxide_conntrack_max",
            "The most connections the kernel will track.",
        ),
    ] {
        if let Some(v) = std::fs::read_to_string(format!("/proc/sys/net/netfilter/{file}"))
            .ok()
            .and_then(|t| t.trim().parse::<u64>().ok())
        {
            metric(name, help, "gauge", one(v));
        }
    }
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response())
}

/// The Netoxide table as the kernel holds it now.
async fn kernel(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    let dump = s
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .applier()
        .dump()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(dump).into_response())
}

async fn settings(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    Ok(Json(s.lock().unwrap_or_else(|e| e.into_inner()).settings()?).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsBody {
    four_eyes: bool,
}

async fn put_settings(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<SettingsBody>,
) -> Api<Response> {
    let who = caller.may(Action::Manage)?;
    Ok(
        Json(s.lock().unwrap_or_else(|e| e.into_inner()).set_four_eyes(
            body.four_eyes,
            who,
            now(),
        )?)
        .into_response(),
    )
}

/// Tokens without their hashes: a name, a role and dates.
async fn tokens(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Manage)?;
    let rows: Vec<_> = s
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .tokens()?
        .into_iter()
        .map(|t| {
            json!({
                "name": t.name, "role": t.role, "created": t.created,
                "expires": t.expires, "created_by": t.created_by,
            })
        })
        .collect();
    Ok(Json(rows).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBody {
    name: String,
    role: String,
    /// Seconds until the token stops working. Omit for no expiry.
    #[serde(default)]
    ttl_secs: Option<u64>,
}

async fn create_token(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<TokenBody>,
) -> Api<Response> {
    let who = caller.may(Action::Manage)?;
    let secret = s.lock().unwrap_or_else(|e| e.into_inner()).create_token(
        &body.name,
        &body.role,
        body.ttl_secs,
        who,
        now(),
    )?;
    Ok(Json(json!({ "name": body.name, "role": body.role, "token": secret })).into_response())
}

async fn revoke_token(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<Response> {
    let who = caller.may(Action::Manage)?;
    s.lock()
        .unwrap_or_else(|e| e.into_inner())
        .revoke_token(&name, who, now())?;
    Ok(Json(json!({ "revoked": name })).into_response())
}

/// What a box needs to be set up again on other hardware: its config and
/// the things that are deliberately not in the config.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    /// The layout of this document. Always 1.
    #[serde(default)]
    format: u32,
    /// Unix time the backup was taken.
    #[serde(default)]
    taken: u64,
    /// The version of the daemon that made it.
    #[serde(default)]
    version: String,
    /// The running config, as TOML. Absent when there was no commit.
    #[serde(default)]
    config: Option<String>,
    /// Each tunnel's private key, by interface. With these, devices that
    /// already have the box's public key keep connecting.
    #[serde(default)]
    wireguard_keys: std::collections::BTreeMap<String, String>,
    /// Roles made on the box.
    #[serde(default)]
    roles: Vec<Role>,
    #[serde(default)]
    four_eyes: bool,
}

/// A backup of this box. It holds private keys, so it needs full control
/// and is recorded.
fn backup(State(s): State<Shared>, caller: Caller, dir: &std::path::Path) -> Api<Response> {
    let who = caller.may(Action::Manage)?;
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    let keys = crate::wg::export_keys(dir);
    let doc = Backup {
        format: 1,
        taken: now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        config: e.running_config()?,
        roles: e.roles().into_iter().filter(|r| !r.builtin).collect(),
        four_eyes: e.settings()?.four_eyes,
        wireguard_keys: keys,
    };
    e.note(
        now(),
        who,
        "backup taken",
        &format!(
            "config {}, {} tunnel key(s), {} role(s)",
            if doc.config.is_some() {
                "included"
            } else {
                "none"
            },
            doc.wireguard_keys.len(),
            doc.roles.len()
        ),
    )?;
    Ok(Json(doc).into_response())
}

/// Puts a backup's keys, roles and settings in place and saves its config
/// as the candidate `restore`. Nothing is applied until that is committed.
fn restore(
    State(s): State<Shared>,
    caller: Caller,
    dir: &std::path::Path,
    Json(doc): Json<Backup>,
) -> Api<Response> {
    let who = caller.may(Action::Manage)?;
    if doc.format != 1 {
        return Err(invalid(if doc.format == 0 {
            "this is not a Netoxide backup: it has no format number".to_string()
        } else {
            format!(
                "this backup has format {}, and this version reads format 1",
                doc.format
            )
        }));
    }
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    // The config first: if it is not valid, nothing else is touched.
    let mut done = vec![];
    if let Some(text) = &doc.config {
        e.put_candidate("restore", text, who, now())?;
        done.push("saved the config as candidate restore".to_string());
    }
    for (iface, key) in &doc.wireguard_keys {
        crate::wg::import_key(dir, iface, key).map_err(invalid)?;
        done.push(format!("put the VPN key for {iface} in place"));
    }
    for role in &doc.roles {
        if e.role(&role.name).is_some() {
            done.push(format!("kept the role {} that is already here", role.name));
            continue;
        }
        let can: Vec<Action> = role.can.iter().copied().collect();
        let sections: Option<Vec<Section>> =
            role.sections.as_ref().map(|s| s.iter().copied().collect());
        e.create_role(&role.name, &can, sections.as_deref(), who, now())?;
        done.push(format!("made the role {}", role.name));
    }
    if e.settings()?.four_eyes != doc.four_eyes {
        e.set_four_eyes(doc.four_eyes, who, now())?;
        done.push(format!(
            "turned four-eyes approval {}",
            if doc.four_eyes { "on" } else { "off" }
        ));
    }
    e.note(now(), who, "backup restored", &done.join("; "))?;
    Ok(Json(json!({
        "done": done,
        "candidate": doc.config.as_ref().map(|_| "restore"),
    }))
    .into_response())
}

/// Every role, with what it can do and where.
async fn roles(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    Ok(Json(s.lock().unwrap_or_else(|e| e.into_inner()).roles()).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleBody {
    name: String,
    /// Actions: read-audit, edit, approve, commit, rollback, manage.
    can: Vec<String>,
    /// Sections changes must stay inside: firewall, network, services, vpn.
    /// Omit for no limit.
    #[serde(default)]
    sections: Option<Vec<String>>,
}

async fn create_role(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<RoleBody>,
) -> Api<Response> {
    let who = caller.may(Action::Manage)?;
    let list = |all: &[&str]| all.join(", ");
    let can = body
        .can
        .iter()
        .map(|a| {
            Action::parse(a).ok_or_else(|| {
                invalid(format!(
                    "'{a}' is not an action; the actions are {}",
                    list(&Action::ALL.map(Action::as_str))
                ))
            })
        })
        .collect::<Api<Vec<_>>>()?;
    let sections = match &body.sections {
        None => None,
        Some(names) => Some(
            names
                .iter()
                .map(|n| {
                    Section::parse(n).ok_or_else(|| {
                        invalid(format!(
                            "'{n}' is not a section; the sections are {}",
                            list(&Section::ALL.map(Section::as_str))
                        ))
                    })
                })
                .collect::<Api<Vec<_>>>()?,
        ),
    };
    let role = s.lock().unwrap_or_else(|e| e.into_inner()).create_role(
        &body.name,
        &can,
        sections.as_deref(),
        who,
        now(),
    )?;
    Ok(Json(role).into_response())
}

async fn delete_role(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<Response> {
    let who = caller.may(Action::Manage)?;
    s.lock()
        .unwrap_or_else(|e| e.into_inner())
        .delete_role(&name, who, now())?;
    Ok(Json(json!({ "deleted": name })).into_response())
}

/// Headers every response should carry when a browser is on the other end.
pub fn security_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    ] {
        h.insert(k, v.parse().expect("static header"));
    }
    h
}
