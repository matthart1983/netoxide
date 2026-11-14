//! The HTTP API. Every route is a thin call into the commit engine.

use std::net::IpAddr;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ox_explain::{Explanation, Packet, explain};
use ox_nft::{Ruleset, compile};
use ox_plan::FlowProto;
use ox_schema::Config;
use ox_store::StoreError;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Shared, now};

pub fn router(shared: Shared) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/running", get(running))
        .route("/v1/commits", get(commits))
        .route("/v1/commits/{id}", get(commit))
        .route("/v1/candidates", get(candidates))
        .route(
            "/v1/candidates/{name}",
            get(candidate).put(put_candidate).delete(delete_candidate),
        )
        .route("/v1/candidates/{name}/plan", post(plan))
        .route("/v1/candidates/{name}/commit", post(commit_candidate))
        .route("/v1/confirm", post(confirm))
        .route("/v1/revert", post(revert))
        .route("/v1/rollback", post(rollback))
        .route("/v1/explain", post(explain_packet))
        .route("/v1/audit", get(audit))
        .route("/v1/kernel", get(kernel))
        .with_state(shared)
}

/// An error as the API returns it: a status and `{"error": "..."}`.
struct ApiError(StatusCode, String);

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
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError(status, e.to_string())
    }
}

fn invalid(msg: impl ToString) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.to_string())
}

type Api<T> = Result<T, ApiError>;

/// The caller's name, as the client states it.
fn who(headers: &HeaderMap) -> String {
    headers
        .get("x-ox-user")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn load(text: &str) -> Api<(Config, Ruleset)> {
    let config = Config::from_toml(text).map_err(invalid)?;
    let ruleset = compile(&config).map_err(invalid)?;
    Ok((config, ruleset))
}

async fn status(State(s): State<Shared>) -> Api<Response> {
    Ok(Json(s.lock().unwrap().status(now())?).into_response())
}

async fn running(State(s): State<Shared>) -> Api<String> {
    s.lock()
        .unwrap()
        .running_config()?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "there is no commit yet".into()))
}

async fn commits(State(s): State<Shared>) -> Api<Response> {
    Ok(Json(s.lock().unwrap().history()?).into_response())
}

async fn commit(State(s): State<Shared>, Path(id): Path<u64>) -> Api<Response> {
    let e = s.lock().unwrap();
    Ok(Json(json!({ "commit": e.commit(id)?, "config": e.commit_config(id)? })).into_response())
}

async fn candidates(State(s): State<Shared>) -> Api<Response> {
    Ok(Json(s.lock().unwrap().candidates()?).into_response())
}

async fn candidate(State(s): State<Shared>, Path(name): Path<String>) -> Api<String> {
    Ok(s.lock().unwrap().candidate(&name)?)
}

async fn put_candidate(
    State(s): State<Shared>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Api<Response> {
    s.lock()
        .unwrap()
        .put_candidate(&name, &body, &who(&headers), now())?;
    Ok(Json(json!({ "saved": name })).into_response())
}

async fn delete_candidate(
    State(s): State<Shared>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Api<Response> {
    s.lock()
        .unwrap()
        .delete_candidate(&name, &who(&headers), now())?;
    Ok(Json(json!({ "deleted": name })).into_response())
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
async fn plan(State(s): State<Shared>, Path(name): Path<String>, body: String) -> Api<Response> {
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
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CommitBody>,
) -> Api<Response> {
    check_window(&body)?;
    let c = s.lock().unwrap().commit_candidate(
        &name,
        &who(&headers),
        &body.reason,
        body.confirm_secs,
        now(),
    )?;
    Ok(Json(c).into_response())
}

async fn confirm(State(s): State<Shared>, headers: HeaderMap) -> Api<Response> {
    Ok(Json(s.lock().unwrap().confirm(&who(&headers), now())?).into_response())
}

async fn revert(State(s): State<Shared>, headers: HeaderMap) -> Api<Response> {
    Ok(Json(s.lock().unwrap().revert(&who(&headers), false, now())?).into_response())
}

async fn rollback(
    State(s): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<CommitBody>,
) -> Api<Response> {
    check_window(&body)?;
    let c = s.lock().unwrap().rollback(
        body.steps.unwrap_or(1),
        &who(&headers),
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

async fn explain_packet(State(s): State<Shared>, Json(body): Json<ExplainBody>) -> Api<Response> {
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

/// The whole audit log. A broken chain is an error, with the line named.
async fn audit(State(s): State<Shared>) -> Api<Response> {
    let entries = s
        .lock()
        .unwrap()
        .audit()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "verified": true, "entries": entries })).into_response())
}

/// The Netoxide table as the kernel holds it now.
async fn kernel(State(s): State<Shared>) -> Api<Response> {
    let dump = s
        .lock()
        .unwrap()
        .applier()
        .dump()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(dump).into_response())
}
