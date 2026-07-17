//! HTTP and OpenAPI surface for a local Fractonica node.

use std::{sync::Arc, time::Instant};

use axum::{
    Json, Router,
    extract::{Path, Query, Request, State, rejection::QueryRejection},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use fractonica_glyph::{
    DEFAULT_DIGITS, FONT_ID as GLYPH_FONT_ID, FONT_SHA256 as GLYPH_FONT_SHA256,
    FONT_VERSION as GLYPH_FONT_VERSION, GEOMETRY_VERSION as GLYPH_GEOMETRY_VERSION,
    GRAMMAR_SHA256 as GLYPH_GRAMMAR_SHA256, GRAMMAR_VERSION as GLYPH_GRAMMAR_VERSION, GlyphConfig,
    GlyphError, GlyphFrame, GlyphPrimitiveKind, GlyphRasterOptions, MAX_DIGITS as GLYPH_MAX_DIGITS,
    MIN_DIGITS as GLYPH_MIN_DIGITS, OctalGlyph, RADIX as GLYPH_RADIX, Rgba8,
    SPEC_SHA256 as GLYPH_SPEC_SHA256,
};
use fractonica_saros_engine::{
    EclipseIdentity, EclipsePath, GeometryRelease, SarosEngine, SarosEngineError, SarosPulse,
    SarosReading,
};
use fractonica_store_sqlite::SqliteStore;
use fractonica_temporal_core::{BitPrecision, PhaseRatio, Rarity, TemporalError, Timestamp};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use utoipa_swagger_ui::SwaggerUi;

const SAROS_CAPABILITIES: &[&str] = &[
    "canonical-octal-glyphs",
    "node-http-api",
    "openapi",
    "saros-calculation",
    "reviewed-eclipse-geometry",
];
const FULL_NODE_CAPABILITIES: &[&str] = &[
    "canonical-octal-glyphs",
    "local-storage",
    "node-http-api",
    "openapi",
    "saros-calculation",
    "reviewed-eclipse-geometry",
];
const SAROS_PROFILE_INSTALLATION_ID: &str = "saros-engine";
const OPENAPI_CONTRACT: &str = include_str!("../../../contracts/openapi/v1.yaml");
const DISPLAY_NAME_MAX_LENGTH: usize = 128;
const VERSION_MAX_LENGTH: usize = 64;
const BEARER_TOKEN_MIN_LENGTH: usize = 32;
const BEARER_TOKEN_MAX_LENGTH: usize = 512;
const DEFAULT_GLYPH_RASTER_SIZE: u16 = 128;
const MAX_GLYPH_RASTER_DIMENSION: u16 = 2_048;
const MAX_GLYPH_RASTER_PIXELS: usize = 4_194_304;

#[derive(Debug, Error)]
pub enum ApiStateError {
    #[error("display name must contain between 1 and {DISPLAY_NAME_MAX_LENGTH} characters")]
    InvalidDisplayName,

    #[error("version must contain between 1 and {VERSION_MAX_LENGTH} characters")]
    InvalidVersion,

    #[error(
        "bootstrap bearer token must contain between {BEARER_TOKEN_MIN_LENGTH} and {BEARER_TOKEN_MAX_LENGTH} characters"
    )]
    InvalidBearerToken,

    #[error("failed to format node start time: {0}")]
    Time(#[from] time::error::Format),

    #[error("failed to load the embedded Saros engine: {0}")]
    Saros(#[from] SarosEngineError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeProfile {
    Full,
    Saros,
}

impl NodeProfile {
    const fn wire_id(self) -> &'static str {
        match self {
            Self::Full => "node",
            Self::Saros => "saros",
        }
    }

    const fn storage_kind(self) -> &'static str {
        match self {
            Self::Full => "sqlite",
            Self::Saros => "none",
        }
    }

    const fn storage_status(self) -> &'static str {
        match self {
            Self::Full => "ready",
            Self::Saros => "notConfigured",
        }
    }
}

#[derive(Clone)]
pub struct ApiState {
    store: Option<Arc<SqliteStore>>,
    saros: Arc<SarosEngine>,
    profile: NodeProfile,
    display_name: Arc<str>,
    version: Arc<str>,
    started_at: Arc<str>,
    started_instant: Instant,
    bearer_token: Option<Arc<str>>,
}

impl ApiState {
    pub fn new(
        store: Arc<SqliteStore>,
        display_name: impl Into<Arc<str>>,
        version: impl Into<Arc<str>>,
    ) -> Result<Self, ApiStateError> {
        Self::new_inner(Some(store), NodeProfile::Full, display_name, version)
    }

    /// Builds a stateless Saros-only HTTP surface.
    ///
    /// This profile does not create, open, or depend on SQLite. It is suitable
    /// for a deterministic local temporal/geometry service and deliberately
    /// omits the `local-storage` capability.
    pub fn new_saros_only(
        display_name: impl Into<Arc<str>>,
        version: impl Into<Arc<str>>,
    ) -> Result<Self, ApiStateError> {
        Self::new_inner(None, NodeProfile::Saros, display_name, version)
    }

    fn new_inner(
        store: Option<Arc<SqliteStore>>,
        profile: NodeProfile,
        display_name: impl Into<Arc<str>>,
        version: impl Into<Arc<str>>,
    ) -> Result<Self, ApiStateError> {
        let display_name = display_name.into();
        let version = version.into();
        if display_name.trim().is_empty() || display_name.chars().count() > DISPLAY_NAME_MAX_LENGTH
        {
            return Err(ApiStateError::InvalidDisplayName);
        }
        if version.trim().is_empty() || version.chars().count() > VERSION_MAX_LENGTH {
            return Err(ApiStateError::InvalidVersion);
        }

        let started_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
        Ok(Self {
            store,
            saros: Arc::new(SarosEngine::embedded_reviewed()?),
            profile,
            display_name,
            version,
            started_at: Arc::from(started_at),
            started_instant: Instant::now(),
            bearer_token: None,
        })
    }

    /// Replaces the checked-in engine with a caller-supplied immutable one.
    /// This keeps the HTTP transport testable and allows future node profiles
    /// to select another verified geometry release.
    #[must_use]
    pub fn with_saros_engine(mut self, saros: Arc<SarosEngine>) -> Self {
        self.saros = saros;
        self
    }

    pub fn with_bearer_token(
        mut self,
        bearer_token: impl Into<Arc<str>>,
    ) -> Result<Self, ApiStateError> {
        let bearer_token = bearer_token.into();
        let length = bearer_token.chars().count();
        if !(BEARER_TOKEN_MIN_LENGTH..=BEARER_TOKEN_MAX_LENGTH).contains(&length)
            || !bearer_token.is_ascii()
            || bearer_token.chars().any(char::is_whitespace)
        {
            return Err(ApiStateError::InvalidBearerToken);
        }
        self.bearer_token = Some(bearer_token);
        Ok(self)
    }
}

pub fn router(state: ApiState) -> Router {
    let openapi = serde_yaml_ng::from_str::<serde_json::Value>(OPENAPI_CONTRACT)
        .expect("checked-in OpenAPI contract must be valid YAML");
    let allowed_origins = AllowOrigin::list([
        HeaderValue::from_static("http://127.0.0.1:5173"),
        HeaderValue::from_static("http://localhost:5173"),
        HeaderValue::from_static("http://127.0.0.1:4173"),
        HeaderValue::from_static("http://localhost:4173"),
        HeaderValue::from_static("http://tauri.localhost"),
        HeaderValue::from_static("tauri://localhost"),
    ]);
    let authentication_state = state.clone();

    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/api/v1/node", get(node))
        .route("/api/v1/saros", get(saros_metadata))
        .route("/api/v1/glyphs", get(glyph_metadata))
        .route("/api/v1/glyphs/{octal}/geometry", get(glyph_geometry))
        .route("/api/v1/glyphs/{octal}/raster.rgba", get(glyph_raster))
        .route("/api/v1/saros/pulse", get(saros_pulse))
        .route("/api/v1/saros/series/{saros}/reading", get(saros_reading))
        .route(
            "/api/v1/saros/series/{saros}/eclipses/{sequence}/path",
            get(saros_path),
        )
        .merge(SwaggerUi::new("/api/docs").external_url_unchecked("/api/openapi.json", openapi))
        .layer(middleware::from_fn_with_state(
            authentication_state,
            authenticate,
        ))
        .layer(
            CorsLayer::new()
                .allow_origin(allowed_origins)
                .allow_methods([Method::GET])
                .allow_headers([header::ACCEPT, header::AUTHORIZATION])
                .expose_headers([
                    HeaderName::from_static("x-fractonica-pixel-format"),
                    HeaderName::from_static("x-fractonica-width"),
                    HeaderName::from_static("x-fractonica-height"),
                    HeaderName::from_static("x-fractonica-stride-bytes"),
                    HeaderName::from_static("x-fractonica-glyph-grammar-version"),
                    HeaderName::from_static("x-fractonica-glyph-geometry-version"),
                    HeaderName::from_static("x-fractonica-glyph-font-id"),
                    HeaderName::from_static("x-fractonica-glyph-font-version"),
                    HeaderName::from_static("x-fractonica-glyph-font-sha256"),
                ]),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct LiveResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadyResponse {
    pub status: &'static str,
    pub profile: &'static str,
    pub storage: StorageReady,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageReady {
    pub kind: &'static str,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeResponse {
    pub installation_id: String,
    pub profile: &'static str,
    pub display_name: String,
    pub version: String,
    pub started_at: String,
    pub uptime_seconds: u64,
    pub capabilities: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarosMetadataResponse {
    pub semantics_version: &'static str,
    pub geometry: GeometryRelease,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlyphMetadataResponse {
    pub grammar_version: &'static str,
    pub grammar_sha256: &'static str,
    pub geometry_version: &'static str,
    pub spec_sha256: &'static str,
    pub font: GlyphFontResponse,
    pub radix: u8,
    pub minimum_depth: u8,
    pub maximum_depth: u8,
    pub default_depth: u8,
    pub coordinate_system: GlyphCoordinateSystemResponse,
    pub stroke_bits: [GlyphStrokeResponse; 3],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlyphFontResponse {
    pub id: &'static str,
    pub version: &'static str,
    pub geometry_version: &'static str,
    pub sha256: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlyphCoordinateSystemResponse {
    pub origin: &'static str,
    pub x_axis: &'static str,
    pub y_axis: &'static str,
    pub rotation: &'static str,
    pub unit: &'static str,
}

#[derive(Debug, Serialize)]
pub struct GlyphStrokeResponse {
    pub id: &'static str,
    pub bit: u8,
    pub from: &'static str,
    pub to: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlyphGeometryResponse {
    pub grammar_version: &'static str,
    pub grammar_sha256: &'static str,
    pub geometry_version: &'static str,
    pub spec_sha256: &'static str,
    pub font: GlyphFontResponse,
    pub octal: String,
    pub depth: u8,
    pub coordinate_system: GlyphCoordinateSystemResponse,
    pub frame: GlyphFrameResponse,
    pub primitives: Vec<GlyphPrimitiveResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlyphFrameResponse {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub aspect_ratio: f32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlyphPrimitiveResponse {
    pub kind: &'static str,
    pub fill_rule: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_index: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digit_index: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digit: Option<u8>,
    pub contours: Vec<GlyphContourResponse>,
}

#[derive(Debug, Serialize)]
pub struct GlyphContourResponse {
    pub points: Vec<GlyphPointResponse>,
}

#[derive(Debug, Serialize)]
pub struct GlyphPointResponse {
    pub x: f32,
    pub y: f32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadingQuery {
    at_unix_seconds: i64,
    #[serde(default)]
    at_nanosecond: u32,
    #[serde(default = "default_precision_bits")]
    precision_bits: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PulseQuery {
    at_unix_seconds: i64,
    #[serde(default)]
    at_nanosecond: u32,
    #[serde(default = "default_anchor_saros")]
    anchor_saros: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GlyphQuery {
    depth: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GlyphRasterQuery {
    depth: Option<u8>,
    width: Option<u16>,
    height: Option<u16>,
    foreground: Option<String>,
    background: Option<String>,
}

const fn default_precision_bits() -> u8 {
    fractonica_temporal_core::REALTIME_PULSE_BITS
}

const fn default_anchor_saros() -> u16 {
    fractonica_temporal_core::DEFAULT_PULSE_SAROS as u16
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimestampResponse {
    pub unix_seconds: i64,
    pub nanosecond: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseResponse {
    pub numerator: String,
    pub denominator: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionResponse {
    pub precision_bits: u8,
    pub prefix: String,
    pub octal: String,
    pub trailing_bits: u8,
    pub trailing_value: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RarityResponse {
    pub family: &'static str,
    pub digit: u8,
    pub digit_name: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarosReadingResponse {
    pub saros: u16,
    pub at: TimestampResponse,
    pub previous: EclipseIdentity,
    pub next: EclipseIdentity,
    pub phase: PhaseResponse,
    pub phase_word_hex: String,
    pub projection: ProjectionResponse,
    pub rarity: Option<RarityResponse>,
    pub next_flip_at: TimestampResponse,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarosPulseResponse {
    pub anchor_saros: u16,
    pub reading: SarosReadingResponse,
    pub glyphs: PulseGlyphsResponse,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PulseGlyphsResponse {
    pub most_significant: String,
    pub least_significant: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EclipsePathResponse {
    pub geometry_status: &'static str,
    pub eclipse: EclipseIdentity,
    pub metadata: EclipseMetadataResponse,
    pub geometry: GeoJsonGeometry,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EclipseMetadataResponse {
    pub type_index: u8,
    pub unix_seconds: i64,
    pub latitude: f64,
    pub longitude: f64,
    pub sun_altitude_degrees: u8,
    pub magnitude: f64,
    pub gamma: f64,
    pub central_duration_seconds: Option<u16>,
    pub central_width_km: Option<u16>,
    pub polygon_count: u8,
    pub path_point_count: u32,
}

#[derive(Debug, Serialize)]
pub struct GeoJsonGeometry {
    #[serde(rename = "type")]
    pub geometry_type: &'static str,
    pub coordinates: Vec<Vec<Vec<[f64; 2]>>>,
}

#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub problem_type: &'static str,
    pub code: &'static str,
    pub title: &'static str,
    pub status: u16,
    pub detail: String,
}

struct ApiError {
    status: StatusCode,
    problem_type: &'static str,
    code: &'static str,
    title: &'static str,
    detail: String,
}

impl ApiError {
    fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            problem_type: "https://fractonica.com/problems/node-not-ready",
            code: "node_not_ready",
            title: "Node is not ready",
            detail: detail.into(),
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            problem_type: "https://fractonica.com/problems/invalid-bootstrap-token",
            code: "invalid_bootstrap_token",
            title: "Authentication required",
            detail: "Supply the bearer token issued by the local node supervisor.".into(),
        }
    }

    fn unprocessable(
        problem_type: &'static str,
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            problem_type,
            code,
            title,
            detail: detail.into(),
        }
    }

    fn not_found(
        problem_type: &'static str,
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            problem_type,
            code,
            title,
            detail: detail.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let problem = Problem {
            problem_type: self.problem_type,
            code: self.code,
            title: self.title,
            status: self.status.as_u16(),
            detail: self.detail,
        };
        let mut response = (self.status, Json(problem)).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"fractonica-desktop\""),
            );
        }
        response
    }
}

async fn authenticate(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let Some(expected) = state.bearer_token.as_deref() else {
        return next.run(request).await;
    };

    let supplied = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let valid = supplied.is_some_and(|supplied| {
        supplied.len() == expected.len()
            && bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()))
    });

    if valid {
        next.run(request).await
    } else {
        ApiError::unauthorized().into_response()
    }
}

async fn live() -> Json<LiveResponse> {
    Json(LiveResponse { status: "up" })
}

async fn ready(State(state): State<ApiState>) -> Result<Json<ReadyResponse>, ApiError> {
    let schema_version = match &state.store {
        Some(store) => {
            let store = Arc::clone(store);
            Some(
                tokio::task::spawn_blocking(move || store.readiness())
                    .await
                    .map_err(|error| {
                        ApiError::unavailable(format!("database task failed: {error}"))
                    })?
                    .map_err(|error| ApiError::unavailable(error.to_string()))?
                    .schema_version,
            )
        }
        None => None,
    };

    Ok(Json(ReadyResponse {
        status: "ready",
        profile: state.profile.wire_id(),
        storage: StorageReady {
            kind: state.profile.storage_kind(),
            status: state.profile.storage_status(),
            schema_version,
        },
    }))
}

async fn node(State(state): State<ApiState>) -> Result<Json<NodeResponse>, ApiError> {
    let installation_id = match &state.store {
        Some(store) => {
            let store = Arc::clone(store);
            tokio::task::spawn_blocking(move || store.installation())
                .await
                .map_err(|error| ApiError::unavailable(format!("database task failed: {error}")))?
                .map_err(|error| ApiError::unavailable(error.to_string()))?
                .installation_id
                .to_string()
        }
        None => SAROS_PROFILE_INSTALLATION_ID.to_owned(),
    };
    let capabilities = match state.profile {
        NodeProfile::Full => FULL_NODE_CAPABILITIES,
        NodeProfile::Saros => SAROS_CAPABILITIES,
    };

    Ok(Json(NodeResponse {
        installation_id,
        profile: state.profile.wire_id(),
        display_name: state.display_name.to_string(),
        version: state.version.to_string(),
        started_at: state.started_at.to_string(),
        uptime_seconds: state.started_instant.elapsed().as_secs(),
        capabilities: capabilities.to_vec(),
    }))
}

async fn saros_metadata(State(state): State<ApiState>) -> Json<SarosMetadataResponse> {
    Json(SarosMetadataResponse {
        semantics_version: state.saros.semantics_version(),
        geometry: state.saros.geometry_release().clone(),
    })
}

async fn glyph_metadata() -> Json<GlyphMetadataResponse> {
    Json(GlyphMetadataResponse {
        grammar_version: GLYPH_GRAMMAR_VERSION,
        grammar_sha256: GLYPH_GRAMMAR_SHA256,
        geometry_version: GLYPH_GEOMETRY_VERSION,
        spec_sha256: GLYPH_SPEC_SHA256,
        font: glyph_font_response(),
        radix: GLYPH_RADIX,
        minimum_depth: GLYPH_MIN_DIGITS,
        maximum_depth: GLYPH_MAX_DIGITS,
        default_depth: DEFAULT_DIGITS,
        coordinate_system: glyph_coordinate_system_response(),
        stroke_bits: [
            GlyphStrokeResponse {
                id: "left",
                bit: 1,
                from: "anchor",
                to: "left",
            },
            GlyphStrokeResponse {
                id: "centre",
                bit: 2,
                from: "anchor",
                to: "apex",
            },
            GlyphStrokeResponse {
                id: "right",
                bit: 4,
                from: "anchor",
                to: "right",
            },
        ],
    })
}

async fn glyph_geometry(
    Path(octal): Path<String>,
    query: Result<Query<GlyphQuery>, QueryRejection>,
) -> Result<Json<GlyphGeometryResponse>, ApiError> {
    let Query(query) = query.map_err(glyph_query_input_error)?;
    let glyph = glyph_from_input(&octal, query.depth)?;
    Ok(Json(glyph_geometry_response(glyph)?))
}

async fn glyph_raster(
    Path(octal): Path<String>,
    query: Result<Query<GlyphRasterQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(glyph_query_input_error)?;
    let glyph = glyph_from_input(&octal, query.depth)?;
    let width = query.width.unwrap_or(DEFAULT_GLYPH_RASTER_SIZE);
    let height = query.height.unwrap_or(DEFAULT_GLYPH_RASTER_SIZE);
    validate_raster_size(width, height)?;
    let foreground = query
        .foreground
        .as_deref()
        .map(|value| parse_rgba8(value, "foreground"))
        .transpose()?
        .unwrap_or(Rgba8::WHITE);
    let background = query
        .background
        .as_deref()
        .map(|value| parse_rgba8(value, "background"))
        .transpose()?
        .unwrap_or(Rgba8::TRANSPARENT);
    let mut pixels = vec![0_u8; width as usize * height as usize * 4];
    let info = glyph
        .rasterize_rgba8(
            GlyphConfig::default(),
            GlyphRasterOptions {
                width,
                height,
                foreground,
                background,
            },
            &mut pixels,
        )
        .map_err(glyph_input_error)?;

    let mut response = pixels.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.fractonica.rgba8"),
    );
    headers.insert(
        HeaderName::from_static("x-fractonica-pixel-format"),
        HeaderValue::from_static("rgba8"),
    );
    headers.insert(
        HeaderName::from_static("x-fractonica-width"),
        HeaderValue::from_str(&info.width.to_string())
            .expect("decimal width is a valid HTTP header"),
    );
    headers.insert(
        HeaderName::from_static("x-fractonica-height"),
        HeaderValue::from_str(&info.height.to_string())
            .expect("decimal height is a valid HTTP header"),
    );
    headers.insert(
        HeaderName::from_static("x-fractonica-stride-bytes"),
        HeaderValue::from_str(&info.stride_bytes.to_string())
            .expect("decimal stride is a valid HTTP header"),
    );
    headers.insert(
        HeaderName::from_static("x-fractonica-glyph-grammar-version"),
        HeaderValue::from_static(GLYPH_GRAMMAR_VERSION),
    );
    headers.insert(
        HeaderName::from_static("x-fractonica-glyph-geometry-version"),
        HeaderValue::from_static(GLYPH_GEOMETRY_VERSION),
    );
    headers.insert(
        HeaderName::from_static("x-fractonica-glyph-font-id"),
        HeaderValue::from_static(GLYPH_FONT_ID),
    );
    headers.insert(
        HeaderName::from_static("x-fractonica-glyph-font-version"),
        HeaderValue::from_static(GLYPH_FONT_VERSION),
    );
    headers.insert(
        HeaderName::from_static("x-fractonica-glyph-font-sha256"),
        HeaderValue::from_static(GLYPH_FONT_SHA256),
    );
    Ok(response)
}

async fn saros_reading(
    State(state): State<ApiState>,
    Path(saros): Path<u16>,
    query: Result<Query<ReadingQuery>, QueryRejection>,
) -> Result<Json<SarosReadingResponse>, ApiError> {
    let Query(query) = query.map_err(query_input_error)?;
    let at = timestamp_from_query(&query)?;
    let precision = BitPrecision::new(query.precision_bits).map_err(temporal_input_error)?;
    let reading = state
        .saros
        .reading_at(saros, at, precision)
        .map_err(saros_engine_error)?;
    Ok(Json(reading_response(reading)?))
}

async fn saros_pulse(
    State(state): State<ApiState>,
    query: Result<Query<PulseQuery>, QueryRejection>,
) -> Result<Json<SarosPulseResponse>, ApiError> {
    let Query(query) = query.map_err(query_input_error)?;
    let at = timestamp_from_parts(query.at_unix_seconds, query.at_nanosecond)?;
    let pulse = state
        .saros
        .pulse_at(query.anchor_saros, at)
        .map_err(saros_engine_error)?;
    Ok(Json(pulse_response(pulse)?))
}

async fn saros_path(
    State(state): State<ApiState>,
    Path((saros, sequence)): Path<(u16, u16)>,
) -> Result<Json<EclipsePathResponse>, ApiError> {
    let path = state
        .saros
        .path(saros, sequence)
        .map_err(saros_engine_error)?;
    Ok(Json(path_response(path)))
}

fn timestamp_from_query(query: &ReadingQuery) -> Result<Timestamp, ApiError> {
    timestamp_from_parts(query.at_unix_seconds, query.at_nanosecond)
}

fn timestamp_from_parts(unix_seconds: i64, nanosecond: u32) -> Result<Timestamp, ApiError> {
    Timestamp::new(unix_seconds, nanosecond).map_err(temporal_input_error)
}

fn temporal_input_error(error: TemporalError) -> ApiError {
    ApiError::unprocessable(
        "https://fractonica.com/problems/invalid-saros-input",
        "invalid_saros_input",
        "Invalid Saros input",
        error.to_string(),
    )
}

fn query_input_error(error: QueryRejection) -> ApiError {
    ApiError::unprocessable(
        "https://fractonica.com/problems/invalid-saros-input",
        "invalid_saros_input",
        "Invalid Saros input",
        error.body_text(),
    )
}

fn glyph_query_input_error(error: QueryRejection) -> ApiError {
    ApiError::unprocessable(
        "https://fractonica.com/problems/invalid-glyph-input",
        "invalid_glyph_input",
        "Invalid glyph input",
        error.body_text(),
    )
}

fn glyph_input_error(error: GlyphError) -> ApiError {
    ApiError::unprocessable(
        "https://fractonica.com/problems/invalid-glyph-input",
        "invalid_glyph_input",
        "Invalid glyph input",
        error.to_string(),
    )
}

fn glyph_from_input(octal: &str, depth: Option<u8>) -> Result<OctalGlyph, ApiError> {
    OctalGlyph::parse(depth.unwrap_or(DEFAULT_DIGITS), octal).map_err(glyph_input_error)
}

fn glyph_coordinate_system_response() -> GlyphCoordinateSystemResponse {
    GlyphCoordinateSystemResponse {
        origin: "glyphCentre",
        x_axis: "right",
        y_axis: "down",
        rotation: "clockwise",
        unit: "fontUnits",
    }
}

fn glyph_font_response() -> GlyphFontResponse {
    GlyphFontResponse {
        id: GLYPH_FONT_ID,
        version: GLYPH_FONT_VERSION,
        geometry_version: GLYPH_GEOMETRY_VERSION,
        sha256: GLYPH_FONT_SHA256,
    }
}

fn glyph_frame_response(frame: GlyphFrame) -> GlyphFrameResponse {
    GlyphFrameResponse {
        x: frame.x,
        y: frame.y,
        width: frame.width,
        height: frame.height,
        aspect_ratio: frame.aspect_ratio(),
    }
}

fn glyph_geometry_response(glyph: OctalGlyph) -> Result<GlyphGeometryResponse, ApiError> {
    let config = GlyphConfig::default();
    let frame = glyph.frame(config).map_err(glyph_input_error)?;
    let mut normalized = [0_u8; GLYPH_MAX_DIGITS as usize];
    glyph
        .write_normalized_ascii(&mut normalized)
        .map_err(glyph_input_error)?;
    let octal = String::from_utf8(normalized[..glyph.depth() as usize].to_vec())
        .expect("glyph core emits ASCII octal");
    let primitives = glyph
        .collect_primitives(config)
        .map_err(glyph_input_error)?
        .into_iter()
        .map(|primitive| GlyphPrimitiveResponse {
            kind: glyph_primitive_wire_id(primitive.kind),
            fill_rule: primitive.fill_rule.wire_id(),
            socket_index: primitive.socket_index,
            digit_index: primitive.digit_index,
            digit: primitive.digit,
            contours: primitive
                .contours
                .into_iter()
                .map(|contour| GlyphContourResponse {
                    points: contour
                        .points
                        .into_iter()
                        .map(|point| GlyphPointResponse {
                            x: point.x,
                            y: point.y,
                        })
                        .collect(),
                })
                .collect(),
        })
        .collect();
    Ok(GlyphGeometryResponse {
        grammar_version: GLYPH_GRAMMAR_VERSION,
        grammar_sha256: GLYPH_GRAMMAR_SHA256,
        geometry_version: GLYPH_GEOMETRY_VERSION,
        spec_sha256: GLYPH_SPEC_SHA256,
        font: glyph_font_response(),
        octal,
        depth: glyph.depth(),
        coordinate_system: glyph_coordinate_system_response(),
        frame: glyph_frame_response(frame),
        primitives,
    })
}

const fn glyph_primitive_wire_id(kind: GlyphPrimitiveKind) -> &'static str {
    kind.wire_id()
}

fn validate_raster_size(width: u16, height: u16) -> Result<(), ApiError> {
    let pixel_count = width as usize * height as usize;
    if width == 0
        || height == 0
        || width > MAX_GLYPH_RASTER_DIMENSION
        || height > MAX_GLYPH_RASTER_DIMENSION
        || pixel_count > MAX_GLYPH_RASTER_PIXELS
    {
        return Err(ApiError::unprocessable(
            "https://fractonica.com/problems/invalid-glyph-input",
            "invalid_glyph_input",
            "Invalid glyph input",
            format!(
                "raster dimensions must be between 1 and {MAX_GLYPH_RASTER_DIMENSION} with at most {MAX_GLYPH_RASTER_PIXELS} pixels, got {width}x{height}"
            ),
        ));
    }
    Ok(())
}

fn parse_rgba8(value: &str, field: &str) -> Result<Rgba8, ApiError> {
    let hex = value.strip_prefix('#').unwrap_or(value);
    let bytes = hex.as_bytes();
    if (bytes.len() != 6 && bytes.len() != 8) || !bytes.is_ascii() {
        return Err(invalid_colour(field, value));
    }
    let red = parse_hex_pair(bytes[0], bytes[1]).ok_or_else(|| invalid_colour(field, value))?;
    let green = parse_hex_pair(bytes[2], bytes[3]).ok_or_else(|| invalid_colour(field, value))?;
    let blue = parse_hex_pair(bytes[4], bytes[5]).ok_or_else(|| invalid_colour(field, value))?;
    let alpha = if bytes.len() == 8 {
        parse_hex_pair(bytes[6], bytes[7]).ok_or_else(|| invalid_colour(field, value))?
    } else {
        u8::MAX
    };
    Ok(Rgba8::new(red, green, blue, alpha))
}

const fn parse_hex_pair(high: u8, low: u8) -> Option<u8> {
    match (hex_nibble(high), hex_nibble(low)) {
        (Some(high), Some(low)) => Some((high << 4) | low),
        _ => None,
    }
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn invalid_colour(field: &str, value: &str) -> ApiError {
    ApiError::unprocessable(
        "https://fractonica.com/problems/invalid-glyph-input",
        "invalid_glyph_input",
        "Invalid glyph input",
        format!(
            "{field} must be a six- or eight-digit hexadecimal RRGGBB[AA] colour, got {value:?}"
        ),
    )
}

fn saros_engine_error(error: SarosEngineError) -> ApiError {
    match error {
        SarosEngineError::GeometryUnavailable(saros) => ApiError::not_found(
            "https://fractonica.com/problems/geometry-unavailable",
            "geometry_unavailable",
            "Reviewed geometry unavailable",
            format!("Saros {saros} is outside the reviewed geometry release (101–161)."),
        ),
        SarosEngineError::EclipseUnavailable { saros, sequence } => ApiError::not_found(
            "https://fractonica.com/problems/eclipse-not-found",
            "eclipse_not_found",
            "Eclipse not found",
            format!("Eclipse sequence {sequence} is not present in Saros {saros}."),
        ),
        SarosEngineError::OutsideCoverage(saros) => ApiError::unprocessable(
            "https://fractonica.com/problems/saros-outside-coverage",
            "saros_outside_coverage",
            "Saros instant is outside coverage",
            format!("Saros {saros} has no complete adjacent eclipse interval at this instant."),
        ),
        SarosEngineError::Temporal(error) => temporal_input_error(error),
        other => ApiError::unavailable(format!("Saros engine is unavailable: {other}")),
    }
}

fn reading_response(reading: SarosReading) -> Result<SarosReadingResponse, ApiError> {
    let projection = reading.projection();
    let full_octal_digits = projection.full_octal_digits();
    let mut octal = vec![b'0'; full_octal_digits];
    projection
        .write_octal_ascii(&mut octal)
        .map_err(temporal_input_error)?;
    let octal = String::from_utf8(octal).expect("temporal core writes ASCII octal digits");
    let trailing_bits = projection.trailing_bits();
    let trailing_value = if trailing_bits == 0 {
        0
    } else {
        (projection.prefix() & ((1_u64 << trailing_bits) - 1)) as u8
    };
    let rarity = if full_octal_digits == 0 {
        None
    } else {
        Some(rarity_response(
            reading.rarity().map_err(temporal_input_error)?,
        ))
    };

    Ok(SarosReadingResponse {
        saros: reading.saros,
        at: timestamp_response(reading.at),
        previous: reading.previous,
        next: reading.next,
        phase: phase_response(reading.phase()),
        phase_word_hex: format!("{:016x}", reading.word().raw()),
        projection: ProjectionResponse {
            precision_bits: projection.precision().get(),
            prefix: projection.prefix().to_string(),
            octal,
            trailing_bits,
            trailing_value,
        },
        rarity,
        next_flip_at: timestamp_response(reading.next_flip_at),
    })
}

fn pulse_response(pulse: SarosPulse) -> Result<SarosPulseResponse, ApiError> {
    Ok(SarosPulseResponse {
        anchor_saros: pulse.anchor_saros,
        reading: reading_response(pulse.reading)?,
        glyphs: PulseGlyphsResponse {
            most_significant: glyph_string(&pulse.glyphs.most_significant),
            least_significant: glyph_string(&pulse.glyphs.least_significant),
        },
    })
}

fn path_response(path: EclipsePath) -> EclipsePathResponse {
    let coordinates = path
        .polygons
        .into_iter()
        .map(|polygon| {
            vec![
                polygon
                    .into_iter()
                    .map(|point| {
                        [
                            f64::from(point.longitude_e6) / 1_000_000.0,
                            f64::from(point.latitude_e6) / 1_000_000.0,
                        ]
                    })
                    .collect(),
            ]
        })
        .collect();
    EclipsePathResponse {
        geometry_status: "reviewed",
        eclipse: path.identity,
        metadata: EclipseMetadataResponse {
            type_index: path.metadata.type_index,
            unix_seconds: path.metadata.unix_seconds,
            latitude: f64::from(path.metadata.latitude_e6) / 1_000_000.0,
            longitude: f64::from(path.metadata.longitude_e6) / 1_000_000.0,
            sun_altitude_degrees: path.metadata.sun_altitude_degrees,
            magnitude: f64::from(path.metadata.magnitude_e4) / 10_000.0,
            gamma: f64::from(path.metadata.gamma_e4) / 10_000.0,
            central_duration_seconds: path.metadata.central_duration_seconds,
            central_width_km: path.metadata.central_width_km,
            polygon_count: path.metadata.polygon_count,
            path_point_count: path.metadata.path_point_count,
        },
        geometry: GeoJsonGeometry {
            geometry_type: "MultiPolygon",
            coordinates,
        },
    }
}

fn timestamp_response(timestamp: Timestamp) -> TimestampResponse {
    TimestampResponse {
        unix_seconds: timestamp.epoch_seconds(),
        nanosecond: timestamp.nanosecond(),
    }
}

fn phase_response(phase: PhaseRatio) -> PhaseResponse {
    PhaseResponse {
        numerator: phase.numerator().to_string(),
        denominator: phase.denominator().to_string(),
    }
}

fn rarity_response(rarity: Rarity) -> RarityResponse {
    RarityResponse {
        family: rarity.family.wire_id(),
        digit: rarity.digit,
        digit_name: rarity.digit_name(),
    }
}

fn glyph_string(digits: &[u8]) -> String {
    digits
        .iter()
        .map(|digit| char::from(b'0' + *digit))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::collections::HashSet;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let store = Arc::new(SqliteStore::open_in_memory().expect("database"));
        let state = ApiState::new(store, "Test Node", "0.1.0").expect("API state");
        router(state)
    }

    fn authenticated_test_app() -> Router {
        let store = Arc::new(SqliteStore::open_in_memory().expect("database"));
        let state = ApiState::new(store, "Test Node", "0.1.0")
            .expect("API state")
            .with_bearer_token("0123456789abcdef0123456789abcdef")
            .expect("bearer token");
        router(state)
    }

    fn saros_only_app() -> Router {
        router(ApiState::new_saros_only("Saros test node", "0.1.0").expect("Saros-only API state"))
    }

    #[test]
    fn rejects_node_metadata_outside_the_public_contract() {
        let store = Arc::new(SqliteStore::open_in_memory().expect("database"));
        assert!(matches!(
            ApiState::new(Arc::clone(&store), "", "0.1.0"),
            Err(ApiStateError::InvalidDisplayName)
        ));
        assert!(matches!(
            ApiState::new(Arc::clone(&store), "x".repeat(129), "0.1.0"),
            Err(ApiStateError::InvalidDisplayName)
        ));
        assert!(matches!(
            ApiState::new(store, "Test Node", ""),
            Err(ApiStateError::InvalidVersion)
        ));

        let store = Arc::new(SqliteStore::open_in_memory().expect("database"));
        assert!(matches!(
            ApiState::new(store, "Test Node", "0.1.0")
                .expect("API state")
                .with_bearer_token("too-short"),
            Err(ApiStateError::InvalidBearerToken)
        ));
    }

    #[tokio::test]
    async fn protects_supervised_nodes_with_the_bootstrap_token() {
        let unauthorized = authenticated_test_app()
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_contract_schema("Problem", &json(unauthorized).await);

        let authorized = authenticated_test_app()
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .header(
                        header::AUTHORIZATION,
                        "Bearer 0123456789abcdef0123456789abcdef",
                    )
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(authorized.status(), StatusCode::OK);
        assert_contract_schema("LiveStatus", &json(authorized).await);
    }

    async fn json(response: Response) -> Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("JSON response")
    }

    fn assert_contract_schema(schema_name: &str, value: &Value) {
        let contract: Value =
            serde_yaml_ng::from_str(OPENAPI_CONTRACT).expect("valid OpenAPI contract");
        let schema = contract
            .pointer(&format!("/components/schemas/{schema_name}"))
            .expect("named OpenAPI schema");
        assert_schema(value, schema, &contract);
    }

    fn assert_schema(value: &Value, schema: &Value, contract: &Value) {
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let pointer = reference
                .strip_prefix('#')
                .expect("only local OpenAPI references are supported");
            let target = contract
                .pointer(pointer)
                .expect("referenced OpenAPI schema");
            assert_schema(value, target, contract);
            return;
        }

        if let Some(options) = schema.get("oneOf").and_then(Value::as_array) {
            let matching: Vec<&Value> = options
                .iter()
                .filter(|option| schema_const_properties_match(value, option, contract))
                .collect();
            assert_eq!(
                matching.len(),
                1,
                "value must match exactly one OpenAPI oneOf option"
            );
            assert_schema(value, matching[0], contract);
            return;
        }

        if let Some(expected) = schema.get("const") {
            assert_eq!(value, expected, "value does not match OpenAPI const");
        }

        if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
            assert!(
                allowed.iter().any(|candidate| candidate == value),
                "value does not match OpenAPI enum"
            );
        }

        let expected_type = match schema.get("type") {
            Some(Value::String(kind)) => Some(kind.as_str()),
            Some(Value::Array(kinds)) => kinds
                .iter()
                .filter_map(Value::as_str)
                .find(|kind| value_matches_schema_type(value, kind)),
            Some(other) => panic!("unsupported OpenAPI type declaration {other}"),
            None => None,
        };

        match expected_type {
            Some("object") => {
                let object = value.as_object().expect("OpenAPI object");
                let properties = schema
                    .get("properties")
                    .and_then(Value::as_object)
                    .expect("OpenAPI object properties");
                if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                    for key in object.keys() {
                        assert!(properties.contains_key(key), "unexpected property {key}");
                    }
                }
                if let Some(required) = schema.get("required").and_then(Value::as_array) {
                    for key in required {
                        let key = key.as_str().expect("required property name");
                        assert!(object.contains_key(key), "missing required property {key}");
                    }
                }
                for (key, property_schema) in properties {
                    if let Some(property) = object.get(key) {
                        assert_schema(property, property_schema, contract);
                    }
                }
            }
            Some("array") => {
                let array = value.as_array().expect("OpenAPI array");
                if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64) {
                    assert!(array.len() as u64 >= minimum, "array is below minItems");
                }
                if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64) {
                    assert!(array.len() as u64 <= maximum, "array exceeds maxItems");
                }
                if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
                    let unique: HashSet<String> = array.iter().map(Value::to_string).collect();
                    assert_eq!(unique.len(), array.len(), "array items are not unique");
                }
                if let Some(item_schema) = schema.get("items") {
                    for item in array {
                        assert_schema(item, item_schema, contract);
                    }
                }
            }
            Some("string") => {
                let string = value.as_str().expect("OpenAPI string");
                let length = string.chars().count() as u64;
                if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64) {
                    assert!(length >= minimum, "string is shorter than minLength");
                }
                if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64) {
                    assert!(length <= maximum, "string is longer than maxLength");
                }
                if schema.get("format").and_then(Value::as_str) == Some("date-time") {
                    OffsetDateTime::parse(string, &Rfc3339).expect("RFC 3339 date-time");
                }
            }
            Some("integer") => {
                let integer = value.as_i64().expect("OpenAPI integer");
                if let Some(minimum) = schema.get("minimum").and_then(Value::as_i64) {
                    assert!(integer >= minimum, "integer is below minimum");
                }
                if let Some(maximum) = schema.get("maximum").and_then(Value::as_i64) {
                    assert!(integer <= maximum, "integer is above maximum");
                }
            }
            Some("number") => {
                let number = value.as_f64().expect("OpenAPI number");
                if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
                    assert!(number >= minimum, "number is below minimum");
                }
                if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64) {
                    assert!(number <= maximum, "number is above maximum");
                }
            }
            Some("null") => assert!(value.is_null(), "OpenAPI null"),
            Some(other) => panic!("unsupported OpenAPI test schema type {other}"),
            None => {}
        }
    }

    fn value_matches_schema_type(value: &Value, kind: &str) -> bool {
        match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.as_i64().is_some(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        }
    }

    fn schema_const_properties_match(value: &Value, schema: &Value, contract: &Value) -> bool {
        let schema = if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let pointer = reference
                .strip_prefix('#')
                .expect("only local OpenAPI references are supported");
            contract
                .pointer(pointer)
                .expect("referenced OpenAPI schema")
        } else {
            schema
        };
        let Some(object) = value.as_object() else {
            return false;
        };
        let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
            return false;
        };
        let mut found_const = false;
        for (name, property) in properties {
            if let Some(expected) = property.get("const") {
                found_const = true;
                if object.get(name) != Some(expected) {
                    return false;
                }
            }
        }
        found_const
    }

    #[tokio::test]
    async fn reports_liveness() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_contract_schema("LiveStatus", &body);
        assert_eq!(body["status"], "up");
    }

    #[tokio::test]
    async fn reports_node_storage_readiness() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_contract_schema("ReadyStatus", &body);
        assert_eq!(body["status"], "ready");
        assert_eq!(body["profile"], "node");
        assert_eq!(body["storage"]["kind"], "sqlite");
        assert_eq!(body["storage"]["status"], "ready");
        assert_eq!(body["storage"]["schemaVersion"], 1);
    }

    #[tokio::test]
    async fn returns_stable_node_metadata() {
        let app = test_app();
        let request = || {
            Request::builder()
                .uri("/api/v1/node")
                .body(Body::empty())
                .expect("request")
        };

        let first = json(app.clone().oneshot(request()).await.expect("response")).await;
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let second = json(app.oneshot(request()).await.expect("response")).await;

        assert_contract_schema("NodeInfo", &first);
        assert_contract_schema("NodeInfo", &second);
        assert_eq!(first["installationId"], second["installationId"]);
        assert_eq!(first["profile"], "node");
        assert_eq!(first["displayName"], "Test Node");
        assert_eq!(first["version"], "0.1.0");
    }

    #[tokio::test]
    async fn serves_a_stateless_saros_profile_without_storage_capabilities() {
        let ready = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(ready.status(), StatusCode::OK);
        let ready = json(ready).await;
        assert_contract_schema("ReadyStatus", &ready);
        assert_eq!(ready["profile"], "saros");
        assert_eq!(ready["storage"]["kind"], "none");
        assert_eq!(ready["storage"]["status"], "notConfigured");
        assert!(ready["storage"].get("schemaVersion").is_none());

        let node = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/node")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(node.status(), StatusCode::OK);
        let node = json(node).await;
        assert_contract_schema("NodeInfo", &node);
        assert_eq!(node["installationId"], SAROS_PROFILE_INSTALLATION_ID);
        assert_eq!(node["profile"], "saros");
        assert!(
            !node["capabilities"]
                .as_array()
                .expect("capabilities")
                .iter()
                .any(|capability| capability == "local-storage")
        );
    }

    #[tokio::test]
    async fn publishes_the_verified_saros_release_metadata() {
        let response = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/saros")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_contract_schema("SarosMetadata", &body);
        assert_eq!(body["semanticsVersion"], "1.0.0");
        assert_eq!(
            body["geometry"]["datasetId"],
            "fractonica-solar-eclipse-geometry-reviewed-101-161-v1"
        );
        assert_eq!(body["geometry"]["source"]["sourceFileCount"], 61);
        assert_eq!(body["geometry"]["source"]["sourceBytes"], 2_056_880);
    }

    #[tokio::test]
    async fn serves_versioned_canonical_glyph_metadata_and_geometry() {
        let metadata = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/glyphs")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(metadata.status(), StatusCode::OK);
        let metadata = json(metadata).await;
        assert_contract_schema("GlyphMetadata", &metadata);
        assert_eq!(metadata["grammarVersion"], "1.0.0");
        assert_eq!(metadata["grammarSha256"], GLYPH_GRAMMAR_SHA256);
        assert_eq!(metadata["geometryVersion"], "2.1.0");
        assert_eq!(metadata["font"]["id"], "fractonica-hex-v2");
        assert_eq!(metadata["font"]["version"], "1.0.0");
        assert_eq!(metadata["font"]["sha256"], GLYPH_FONT_SHA256);
        assert_eq!(metadata["strokeBits"][0]["bit"], 1);
        assert_eq!(metadata["strokeBits"][1]["bit"], 2);
        assert_eq!(metadata["strokeBits"][2]["bit"], 4);

        let geometry = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/glyphs/12345/geometry?depth=5")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(geometry.status(), StatusCode::OK);
        let geometry = json(geometry).await;
        assert_contract_schema("GlyphGeometry", &geometry);
        assert_eq!(geometry["octal"], "12345");
        assert_eq!(geometry["font"]["id"], "fractonica-hex-v2");
        assert_eq!(geometry["primitives"][0]["kind"], "core");
        assert_eq!(geometry["primitives"][0]["fillRule"], "evenodd");
        assert_eq!(
            geometry["primitives"][0]["contours"]
                .as_array()
                .expect("core contours")
                .len(),
            2
        );
        assert_eq!(geometry["primitives"][1]["kind"], "arm");
        assert_eq!(geometry["primitives"][1]["fillRule"], "nonzero");
        assert_eq!(geometry["primitives"][1]["socketIndex"], 0);
        assert_eq!(geometry["primitives"][1]["digitIndex"], 0);
        assert_eq!(geometry["primitives"][1]["digit"], 1);
        assert_eq!(
            geometry["primitives"][1]["contours"]
                .as_array()
                .expect("arm contours")
                .len(),
            1
        );

        let zero = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/glyphs/00000/geometry?depth=5")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(zero.status(), StatusCode::OK);
        let zero = json(zero).await;
        assert_contract_schema("GlyphGeometry", &zero);
        assert_eq!(zero["primitives"].as_array().expect("primitives").len(), 1);

        let fixture = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/glyphs/777777/geometry?depth=6")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(fixture.status(), StatusCode::OK);
        let fixture = json(fixture).await;
        assert_contract_schema("GlyphGeometry", &fixture);
        assert_eq!(fixture["frame"]["x"], -176.0);
        assert_eq!(fixture["frame"]["y"], -200.0);
        assert_eq!(fixture["frame"]["width"], 352.0);
        assert_eq!(fixture["frame"]["height"], 400.0);
        assert_eq!(
            fixture["primitives"][0]["contours"][0]["points"][2],
            serde_json::json!({"x": 32.0, "y": -27.71})
        );
        assert_eq!(
            fixture["primitives"][2]["contours"][0]["points"][0],
            serde_json::json!({"x": 32.0, "y": -27.71})
        );
    }

    #[tokio::test]
    async fn rasterizes_rgba8_with_self_describing_headers() {
        let response = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri(
                        "/api/v1/glyphs/77777/raster.rgba?depth=5&width=32&height=16&foreground=12ABEF&background=00000000",
                    )
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/vnd.fractonica.rgba8"
        );
        assert_eq!(response.headers()["x-fractonica-pixel-format"], "rgba8");
        assert_eq!(response.headers()["x-fractonica-width"], "32");
        assert_eq!(response.headers()["x-fractonica-height"], "16");
        assert_eq!(response.headers()["x-fractonica-stride-bytes"], "128");
        assert_eq!(
            response.headers()["x-fractonica-glyph-font-id"],
            "fractonica-hex-v2"
        );
        assert_eq!(
            response.headers()["x-fractonica-glyph-font-version"],
            "1.0.0"
        );
        assert_eq!(
            response.headers()["x-fractonica-glyph-font-sha256"],
            GLYPH_FONT_SHA256
        );
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("raster body")
            .to_bytes();
        assert_eq!(bytes.len(), 32 * 16 * 4);
        assert!(bytes.chunks_exact(4).any(|pixel| pixel[3] > 0));

        let invalid = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/glyphs/8/geometry")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let invalid = json(invalid).await;
        assert_contract_schema("Problem", &invalid);
        assert_eq!(invalid["code"], "invalid_glyph_input");
    }

    #[tokio::test]
    async fn serves_the_exact_msb_first_saros_pulse() {
        let response = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/saros/pulse?atUnixSeconds=-11253795384")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_contract_schema("SarosPulse", &body);
        assert_eq!(body["anchorSaros"], 141);
        assert_eq!(body["reading"]["previous"]["sequence"], 0);
        assert_eq!(body["reading"]["next"]["sequence"], 1);
        assert_eq!(body["glyphs"]["mostSignificant"], "00000");
        assert_eq!(body["glyphs"]["leastSignificant"], "00000");
        assert_eq!(body["reading"]["rarity"]["family"], "nihil");
    }

    #[tokio::test]
    async fn exposes_requested_precision_and_reviewed_path() {
        let reading = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri(
                        "/api/v1/saros/series/141/reading?atUnixSeconds=-11253795384&precisionBits=32",
                    )
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(reading.status(), StatusCode::OK);
        let reading = json(reading).await;
        assert_contract_schema("SarosReading", &reading);
        assert_eq!(reading["projection"]["precisionBits"], 32);
        assert_eq!(reading["projection"]["octal"], "0000000000");
        assert_eq!(reading["projection"]["trailingBits"], 2);
        assert_eq!(reading["projection"]["trailingValue"], 0);

        let path = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/saros/series/141/eclipses/0/path")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(path.status(), StatusCode::OK);
        let path = json(path).await;
        assert_contract_schema("EclipsePath", &path);
        assert_eq!(path["geometryStatus"], "reviewed");
        assert_eq!(path["eclipse"]["saros"], 141);
        assert!(
            !path["geometry"]["coordinates"]
                .as_array()
                .expect("coordinates")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn maps_invalid_and_outside_saros_requests_to_stable_problems() {
        let invalid = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/saros/pulse")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let invalid = json(invalid).await;
        assert_contract_schema("Problem", &invalid);
        assert_eq!(invalid["code"], "invalid_saros_input");

        let outside = saros_only_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/saros/series/162/eclipses/0/path")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(outside.status(), StatusCode::NOT_FOUND);
        let outside = json(outside).await;
        assert_contract_schema("Problem", &outside);
        assert_eq!(outside["code"], "geometry_unavailable");
    }

    #[tokio::test]
    async fn serves_openapi() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/openapi.json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["info"]["title"], "Fractonica Node API");
        assert_eq!(body["info"]["version"], "1.0.0");
    }
}
