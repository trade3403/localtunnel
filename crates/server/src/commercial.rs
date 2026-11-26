//! Read-only owner-scoped commercial inventory. No plan mutation or
//! commercial enforcement is exposed by this first V0.8 increment.
use crate::auth;
use axum::{extract::State,http::{HeaderMap,StatusCode},response::Response,routing::get,Json,Router};
use serde::Serialize;
use sqlx::SqlitePool;
type Failure=(StatusCode,&'static str);
const INTERNAL:Failure=(StatusCode::SERVICE_UNAVAILABLE,"commercial inventory unavailable");
const DENIED:Failure=(StatusCode::UNAUTHORIZED,"invalid credentials or session");

#[derive(Serialize,sqlx::FromRow)]
struct Entitlement {
    tenant_id:String, plan_id:String, plan_code:String, plan_version:i64, plan_name:String,
    revision:i64, state:String, expires_at:Option<i64>, effective_state:String,
    max_active_devices:i64,max_retained_devices:i64,max_mappings:i64,
    max_bandwidth_bps:Option<i64>,max_monthly_bytes:Option<i64>,max_concurrent_connections:Option<i64>,
    active_devices:i64,retained_devices:i64,mappings:i64,
}
#[derive(Serialize)]
struct View {
    scope:&'static str,
    commercial_enforcement:bool,
    entitlement:Entitlement,
}
pub fn routes(pool:SqlitePool)->Router{
    Router::new().route("/api/v1/commercial/entitlement",get(current)).with_state(pool)
}
async fn current(State(pool):State<SqlitePool>,headers:HeaderMap)->Result<Response,Failure>{
    let digest=auth::bearer(&headers)?;
    // Identity, policy and real counts in one SQL snapshot. No caller-
    // supplied owner/tenant selector, no device credentials or hashes.
    let entitlement=sqlx::query_as::<_,Entitlement>(
        "SELECT t.id AS tenant_id,p.id AS plan_id,p.code AS plan_code,p.version AS plan_version,p.name AS plan_name,e.revision,e.state,e.expires_at,CASE WHEN e.state='suspended' THEN 'suspended' WHEN e.expires_at IS NOT NULL AND e.expires_at<=unixepoch() THEN 'expired' ELSE 'active' END AS effective_state,p.max_active_devices,p.max_retained_devices,p.max_mappings,p.max_bandwidth_bps,p.max_monthly_bytes,p.max_concurrent_connections,(SELECT count(*) FROM devices d WHERE d.owner_id=u.id AND d.enabled=1) AS active_devices,(SELECT count(*) FROM devices d WHERE d.owner_id=u.id) AS retained_devices,(SELECT count(*) FROM mappings m WHERE m.owner_id=u.id) AS mappings FROM users u JOIN admin_sessions a ON a.user_id=u.id JOIN tenants t ON t.owner_id=u.id JOIN tenant_entitlements e ON e.tenant_id=t.id JOIN commercial_plans p ON p.id=e.plan_id WHERE a.token_digest=? AND a.expires_at>unixepoch() AND u.enabled=1 AND u.role='admin'")
        .bind(digest).fetch_optional(&pool).await.map_err(|_|INTERNAL)?.ok_or(DENIED)?;
    Ok(auth::uncached(Json(View{scope:"owner_inventory_only",commercial_enforcement:false,entitlement})))
}
