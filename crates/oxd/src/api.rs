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

use std::{net::IpAddr, path::PathBuf};

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
use ox_store::{Action, Identity, Role, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Shared, now, web};

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
pub struct Caller(pub Identity);

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
                    self.0.role.as_str(),
                    action.describe()
                ),
            ))
        }
    }
}

impl FromRequestParts<Shared> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Caller, ApiError> {
        // A connection on the Unix socket carries the peer's user ID.
        if let Some(ConnectInfo(Peer(uid))) = parts.extensions.get::<ConnectInfo<Peer>>() {
            return Ok(Caller(Identity {
                name: user_name(*uid),
                role: Role::Admin,
            }));
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
            .unwrap()
            .identify(secret, now())
            .map(Caller)
            .ok_or_else(|| {
                ApiError(
                    StatusCode::UNAUTHORIZED,
                    "this access token is unknown, expired or revoked".into(),
                )
            })
    }
}

pub fn router(shared: Shared, lease_file: PathBuf) -> Router {
    Router::new()
        .route("/v1/whoami", get(whoami))
        .route("/v1/status", get(status))
        .route("/v1/running", get(running))
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
        .route("/v1/kernel", get(kernel))
        .route("/v1/settings", get(settings).put(put_settings))
        .route("/v1/tokens", get(tokens).post(create_token))
        .route("/v1/tokens/{name}", axum::routing::delete(revoke_token))
        .route(
            "/v1/leases",
            get(move |caller: Caller| {
                let path = lease_file.clone();
                async move { leases(&caller, path) }
            }),
        )
        .merge(web::routes())
        .with_state(shared)
}

/// An error as the API returns it: a status and `{"error": "..."}`.
pub struct ApiError(StatusCode, String);

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
    Json(json!({ "name": caller.0.name, "role": caller.0.role.as_str() })).into_response()
}

async fn status(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    let mut e = s.lock().unwrap();
    let mut v = serde_json::to_value(e.status(now())?).expect("status is plain JSON");
    v["four_eyes"] = json!(e.settings()?.four_eyes);
    Ok(Json(v).into_response())
}

async fn running(State(s): State<Shared>, caller: Caller) -> Api<String> {
    caller.may(Action::Read)?;
    s.lock()
        .unwrap()
        .running_config()?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "there is no commit yet".into()))
}

async fn commits(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    Ok(Json(s.lock().unwrap().history()?).into_response())
}

async fn commit(State(s): State<Shared>, caller: Caller, Path(id): Path<u64>) -> Api<Response> {
    caller.may(Action::Read)?;
    let e = s.lock().unwrap();
    Ok(Json(json!({ "commit": e.commit(id)?, "config": e.commit_config(id)? })).into_response())
}

async fn candidates(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    Ok(Json(s.lock().unwrap().candidates()?).into_response())
}

async fn candidate(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<String> {
    caller.may(Action::Read)?;
    Ok(s.lock().unwrap().candidate(&name)?)
}

async fn candidate_meta(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<Response> {
    caller.may(Action::Read)?;
    Ok(Json(s.lock().unwrap().candidate_meta(&name)?).into_response())
}

async fn put_candidate(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
    body: String,
) -> Api<Response> {
    let who = caller.may(Action::Edit)?;
    s.lock().unwrap().put_candidate(&name, &body, who, now())?;
    Ok(Json(json!({ "saved": name })).into_response())
}

async fn delete_candidate(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<Response> {
    let who = caller.may(Action::Edit)?;
    s.lock().unwrap().delete_candidate(&name, who, now())?;
    Ok(Json(json!({ "deleted": name })).into_response())
}

async fn approve(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<Response> {
    let who = caller.may(Action::Approve)?;
    Ok(Json(s.lock().unwrap().approve(&name, who, now())?).into_response())
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
        let e = s.lock().unwrap();
        (e.candidate(&name)?, e.running_config()?)
    };
    let (new, new_rs) = load(&candidate_text)?;
    let mut view = PlanView {
        first_commit: running_text.is_none(),
        summary: new_rs.summary(),
        changes: vec![],
        flows_checked: None,
        impact: vec![],
    };
    if let Some(text) = running_text {
        let (old, old_rs) = load(&text)?;
        view.changes = ox_plan::diff(&old, &new)
            .iter()
            .map(ToString::to_string)
            .collect();
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
    let c =
        s.lock()
            .unwrap()
            .commit_candidate(&name, who, &body.reason, body.confirm_secs, now())?;
    Ok(Json(c).into_response())
}

async fn confirm(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    let who = caller.may(Action::Commit)?;
    Ok(Json(s.lock().unwrap().confirm(who, now())?).into_response())
}

async fn revert(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    let who = caller.may(Action::Commit)?;
    Ok(Json(s.lock().unwrap().revert(who, false, now())?).into_response())
}

async fn rollback(
    State(s): State<Shared>,
    caller: Caller,
    Json(body): Json<CommitBody>,
) -> Api<Response> {
    let who = caller.may(Action::Rollback)?;
    check_window(&body)?;
    let c = s.lock().unwrap().rollback(
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
    #[serde(rename = "in")]
    iif: String,
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
        let e = s.lock().unwrap();
        (
            e.running_config()?,
            body.candidate
                .as_deref()
                .map(|n| e.candidate(n))
                .transpose()?,
        )
    };
    let packet = Packet {
        src: body.src,
        dst: body.dst,
        l4: body.proto.into(),
        dport: body.dport,
        iif: body.iif,
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
        .unwrap()
        .audit()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "verified": true, "entries": entries })).into_response())
}

/// The Netoxide table as the kernel holds it now.
async fn kernel(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    let dump = s
        .lock()
        .unwrap()
        .applier()
        .dump()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(dump).into_response())
}

async fn settings(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Read)?;
    Ok(Json(s.lock().unwrap().settings()?).into_response())
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
    Ok(Json(
        s.lock()
            .unwrap()
            .set_four_eyes(body.four_eyes, who, now())?,
    )
    .into_response())
}

/// Tokens without their hashes: a name, a role and dates.
async fn tokens(State(s): State<Shared>, caller: Caller) -> Api<Response> {
    caller.may(Action::Manage)?;
    let rows: Vec<_> = s
        .lock()
        .unwrap()
        .tokens()?
        .into_iter()
        .map(|t| {
            json!({
                "name": t.name, "role": t.role.as_str(), "created": t.created,
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
    let role = Role::parse(&body.role)
        .ok_or_else(|| invalid("role must be viewer, auditor, operator or admin"))?;
    let secret = s
        .lock()
        .unwrap()
        .create_token(&body.name, role, body.ttl_secs, who, now())?;
    Ok(Json(json!({ "name": body.name, "role": role.as_str(), "token": secret })).into_response())
}

async fn revoke_token(
    State(s): State<Shared>,
    caller: Caller,
    Path(name): Path<String>,
) -> Api<Response> {
    let who = caller.may(Action::Manage)?;
    s.lock().unwrap().revoke_token(&name, who, now())?;
    Ok(Json(json!({ "revoked": name })).into_response())
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
            "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'",
        ),
    ] {
        h.insert(k, v.parse().expect("static header"));
    }
    h
}
