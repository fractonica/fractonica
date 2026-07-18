//! HTTP and OpenAPI surface for a local Fractonica node.

use std::{
    collections::{HashMap, HashSet},
    fs::File as StdFile,
    io::{Read as _, Seek as _, SeekFrom},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{
        Path, Query, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, head, options, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use fractonica_application::{
    ApplicationError, ApplicationService, DEFAULT_CHANGE_LIMIT, EntityState,
    MAX_AVAILABILITY_CONTENT_IDS, OperationChangePage, RepositoryError, StoredOperation,
    SubmitOperationCommand, UploadId, UploadSession, UploadState,
};
use fractonica_blob_store::{BlobStore, BlobStoreError, CreateUpload, MAX_PATCH_BYTES};
use fractonica_content::{
    ContentDescriptor, ContentId, MAX_MEDIA_TYPE_BYTES, MAX_ORIGINAL_NAME_CHARS,
};
use fractonica_data_model::{EntityId, EntitySchema};
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
use fractonica_temporal_core::{BitPrecision, PhaseRatio, Rarity, TemporalError, Timestamp};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
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
    "causal-operation-log",
    "local-storage",
    "node-http-api",
    "openapi",
    "saros-calculation",
    "reviewed-eclipse-geometry",
];
const FULL_NODE_CONTENT_CAPABILITIES: &[&str] = &[
    "canonical-octal-glyphs",
    "causal-operation-log",
    "content-addressed-resources",
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
const TUS_VERSION: &str = "1.0.0";
const TUS_EXTENSIONS: &str = "creation,expiration,checksum";
const TUS_CHECKSUM_ALGORITHMS: &str = "sha1,sha256";
const MAX_UPLOAD_METADATA_BYTES: usize = 8_192;
const FILE_DIGEST_BUFFER_BYTES: usize = 1024 * 1024;

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
    application: Option<Arc<ApplicationService>>,
    blob_store: Option<Arc<BlobStore>>,
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
        application: Arc<ApplicationService>,
        display_name: impl Into<Arc<str>>,
        version: impl Into<Arc<str>>,
    ) -> Result<Self, ApiStateError> {
        Self::new_inner(Some(application), NodeProfile::Full, display_name, version)
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
        application: Option<Arc<ApplicationService>>,
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
            application,
            blob_store: None,
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

    /// Installs the node-profile immutable content store.
    ///
    /// Keeping this explicit prevents the stateless Saros profile from ever
    /// creating filesystem or database state as a side effect of HTTP setup.
    #[must_use]
    pub fn with_blob_store(mut self, blob_store: Arc<BlobStore>) -> Self {
        self.blob_store = Some(blob_store);
        self
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

    let application = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/api/v1/node", get(node))
        .route(
            "/api/v1/operations",
            get(operation_changes).post(submit_operation),
        )
        .route("/api/v1/entities/{entity_id}", get(entity_state))
        .route("/api/v1/uploads", post(create_upload))
        .route(
            "/api/v1/uploads/{upload_id}",
            head(upload_status).patch(append_upload_chunk),
        )
        .route("/api/v1/blobs/availability", post(blob_availability))
        .route("/api/v1/blobs/{content_id}", get(get_blob).head(head_blob))
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
                .allow_methods([
                    Method::GET,
                    Method::HEAD,
                    Method::OPTIONS,
                    Method::PATCH,
                    Method::POST,
                ])
                .allow_headers([
                    header::ACCEPT,
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    HeaderName::from_static("idempotency-key"),
                    HeaderName::from_static("range"),
                    HeaderName::from_static("tus-resumable"),
                    HeaderName::from_static("upload-checksum"),
                    HeaderName::from_static("upload-length"),
                    HeaderName::from_static("upload-metadata"),
                    HeaderName::from_static("upload-offset"),
                ])
                .expose_headers([
                    header::ACCEPT_RANGES,
                    header::CONTENT_LENGTH,
                    header::CONTENT_RANGE,
                    header::ETAG,
                    header::LOCATION,
                    HeaderName::from_static("repr-digest"),
                    HeaderName::from_static("content-digest"),
                    HeaderName::from_static("fractonica-content-id"),
                    HeaderName::from_static("tus-checksum-algorithm"),
                    HeaderName::from_static("tus-extension"),
                    HeaderName::from_static("tus-max-size"),
                    HeaderName::from_static("tus-resumable"),
                    HeaderName::from_static("tus-version"),
                    HeaderName::from_static("upload-expires"),
                    HeaderName::from_static("upload-length"),
                    HeaderName::from_static("upload-metadata"),
                    HeaderName::from_static("upload-offset"),
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
        .with_state(state.clone());

    // `CorsLayer` answers all OPTIONS requests itself. Keep protocol
    // discovery outside that layer so a plain tus OPTIONS request reaches the
    // capability handler rather than receiving an empty generic CORS reply.
    let upload_options = Router::new()
        .route("/api/v1/uploads", options(upload_capabilities))
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    application.merge(upload_options)
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperationChangesQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_change_limit")]
    limit: usize,
}

const fn default_change_limit() -> usize {
    DEFAULT_CHANGE_LIMIT
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityStateResponse {
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub operation_count: u64,
    pub conflicted: bool,
    pub heads: Vec<StoredOperation>,
}

impl From<EntityState> for EntityStateResponse {
    fn from(value: EntityState) -> Self {
        let conflicted = value.is_conflicted();
        Self {
            entity_id: value.entity_id,
            schema: value.schema,
            operation_count: value.operation_count,
            conflicted,
            heads: value.heads,
        }
    }
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
    response_headers: Vec<(HeaderName, HeaderValue)>,
}

impl ApiError {
    fn status(
        status: StatusCode,
        problem_type: &'static str,
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status,
            problem_type,
            code,
            title,
            detail: detail.into(),
            response_headers: Vec::new(),
        }
    }

    fn with_header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.response_headers
                .push((HeaderName::from_static(name), value));
        }
        self
    }

    fn bad_request(
        problem_type: &'static str,
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self::status(StatusCode::BAD_REQUEST, problem_type, code, title, detail)
    }

    fn unavailable(detail: impl Into<String>) -> Self {
        Self::status(
            StatusCode::SERVICE_UNAVAILABLE,
            "https://fractonica.com/problems/node-not-ready",
            "node_not_ready",
            "Node is not ready",
            detail,
        )
    }

    fn unauthorized() -> Self {
        Self::status(
            StatusCode::UNAUTHORIZED,
            "https://fractonica.com/problems/invalid-bootstrap-token",
            "invalid_bootstrap_token",
            "Authentication required",
            "Supply the bearer token issued by the local node supervisor.",
        )
    }

    fn unprocessable(
        problem_type: &'static str,
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self::status(
            StatusCode::UNPROCESSABLE_ENTITY,
            problem_type,
            code,
            title,
            detail,
        )
    }

    fn conflict(
        problem_type: &'static str,
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self::status(StatusCode::CONFLICT, problem_type, code, title, detail)
    }

    fn not_found(
        problem_type: &'static str,
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self::status(StatusCode::NOT_FOUND, problem_type, code, title, detail)
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
        for (name, value) in self.response_headers {
            response.headers_mut().insert(name, value);
        }
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
    let schema_version = match &state.application {
        Some(application) => {
            let application = Arc::clone(application);
            Some(
                tokio::task::spawn_blocking(move || application.readiness())
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
    let installation_id = match &state.application {
        Some(application) => {
            let application = Arc::clone(application);
            tokio::task::spawn_blocking(move || application.installation())
                .await
                .map_err(|error| ApiError::unavailable(format!("database task failed: {error}")))?
                .map_err(|error| ApiError::unavailable(error.to_string()))?
                .installation_id
                .to_string()
        }
        None => SAROS_PROFILE_INSTALLATION_ID.to_owned(),
    };
    let capabilities = match state.profile {
        NodeProfile::Full if state.blob_store.is_some() => FULL_NODE_CONTENT_CAPABILITIES,
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

async fn submit_operation(
    State(state): State<ApiState>,
    headers: HeaderMap,
    payload: Result<Json<SubmitOperationCommand>, JsonRejection>,
) -> Result<Response, ApiError> {
    let application = full_application(&state)?;
    let idempotency_key = headers
        .get("idempotency-key")
        .ok_or_else(|| {
            ApiError::unprocessable(
                "https://fractonica.com/problems/invalid-idempotency-key",
                "invalid_idempotency_key",
                "Invalid idempotency key",
                "Supply the Idempotency-Key header for every operation submission.",
            )
        })?
        .to_str()
        .map_err(|_| {
            ApiError::unprocessable(
                "https://fractonica.com/problems/invalid-idempotency-key",
                "invalid_idempotency_key",
                "Invalid idempotency key",
                "The Idempotency-Key header must contain visible ASCII characters.",
            )
        })?
        .to_owned();
    let Json(command) = payload.map_err(operation_json_error)?;

    let result = tokio::task::spawn_blocking(move || {
        application.submit_operation(command, &idempotency_key)
    })
    .await
    .map_err(|error| ApiError::unavailable(format!("operation task failed: {error}")))?
    .map_err(application_error)?;
    let status = if result.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(result.operation)).into_response())
}

async fn operation_changes(
    State(state): State<ApiState>,
    query: Result<Query<OperationChangesQuery>, QueryRejection>,
) -> Result<Json<OperationChangePage>, ApiError> {
    let application = full_application(&state)?;
    let Query(query) = query.map_err(operation_query_error)?;
    let page =
        tokio::task::spawn_blocking(move || application.changes_after(query.after, query.limit))
            .await
            .map_err(|error| ApiError::unavailable(format!("operation task failed: {error}")))?
            .map_err(application_error)?;
    Ok(Json(page))
}

async fn entity_state(
    State(state): State<ApiState>,
    Path(entity_id): Path<String>,
) -> Result<Json<EntityStateResponse>, ApiError> {
    let application = full_application(&state)?;
    let entity_id = EntityId::parse(&entity_id).map_err(|error| {
        ApiError::unprocessable(
            "https://fractonica.com/problems/invalid-entity-id",
            "invalid_entity_id",
            "Invalid entity ID",
            error.to_string(),
        )
    })?;
    let entity = tokio::task::spawn_blocking(move || application.entity_state(entity_id))
        .await
        .map_err(|error| ApiError::unavailable(format!("operation task failed: {error}")))?
        .map_err(application_error)?
        .ok_or_else(|| {
            ApiError::not_found(
                "https://fractonica.com/problems/entity-not-found",
                "entity_not_found",
                "Entity not found",
                format!("Entity {entity_id} does not exist on this node."),
            )
        })?;
    Ok(Json(entity.into()))
}

fn full_application(state: &ApiState) -> Result<Arc<ApplicationService>, ApiError> {
    state.application.as_ref().map(Arc::clone).ok_or_else(|| {
        ApiError::unavailable("The stateless Saros profile does not have an operation repository.")
    })
}

fn full_blob_store(state: &ApiState) -> Result<Arc<BlobStore>, ApiError> {
    state.blob_store.as_ref().map(Arc::clone).ok_or_else(|| {
        ApiError::unavailable("The selected profile does not have an immutable content repository.")
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlobAvailabilityRequest {
    content_ids: Vec<ContentId>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BlobAvailabilityResponse {
    available: Vec<ContentDescriptor>,
    missing: Vec<ContentId>,
}

#[derive(Default)]
struct UploadMetadata {
    content_id: Option<ContentId>,
    media_type: Option<String>,
    original_name: Option<String>,
}

#[derive(Clone, Copy)]
struct ByteRange {
    start: u64,
    length: u64,
}

async fn upload_capabilities(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    match upload_capabilities_inner(state).await {
        Ok(mut response) => {
            add_upload_options_cors_headers(&mut response, &headers);
            response
        }
        Err(error) => tus_error_response(error),
    }
}

async fn upload_capabilities_inner(state: ApiState) -> Result<Response, ApiError> {
    let store = full_blob_store(&state)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    insert_header(response.headers_mut(), "tus-resumable", TUS_VERSION)?;
    insert_header(response.headers_mut(), "tus-version", TUS_VERSION)?;
    insert_header(response.headers_mut(), "tus-extension", TUS_EXTENSIONS)?;
    insert_header(
        response.headers_mut(),
        "tus-checksum-algorithm",
        TUS_CHECKSUM_ALGORITHMS,
    )?;
    insert_header(
        response.headers_mut(),
        "tus-max-size",
        &store.max_blob_bytes().to_string(),
    )?;
    Ok(response)
}

async fn create_upload(State(state): State<ApiState>, request: Request) -> Response {
    match create_upload_inner(state, request).await {
        Ok(response) => response,
        Err(error) => tus_error_response(error),
    }
}

async fn create_upload_inner(state: ApiState, request: Request) -> Result<Response, ApiError> {
    let store = full_blob_store(&state)?;
    require_tus_version(request.headers())?;
    let upload_length = parse_required_u64_header(request.headers(), "upload-length")?;
    if upload_length > store.max_blob_bytes() {
        return Err(ApiError::status(
            StatusCode::PAYLOAD_TOO_LARGE,
            "https://fractonica.com/problems/upload-too-large",
            "upload_too_large",
            "Upload is too large",
            format!(
                "Upload-Length {upload_length} exceeds this node's maximum {} bytes.",
                store.max_blob_bytes()
            ),
        ));
    }
    let metadata_header = optional_ascii_header(request.headers(), "upload-metadata")?;
    let metadata = parse_upload_metadata(metadata_header.as_deref())?;
    let body = to_bytes(request.into_body(), 1).await.map_err(|_| {
        ApiError::bad_request(
            "https://fractonica.com/problems/invalid-upload-creation",
            "invalid_upload_creation",
            "Invalid upload creation",
            "Upload creation does not accept request content; append bytes with PATCH.",
        )
    })?;
    if !body.is_empty() {
        return Err(ApiError::bad_request(
            "https://fractonica.com/problems/invalid-upload-creation",
            "invalid_upload_creation",
            "Invalid upload creation",
            "Upload creation does not accept request content; append bytes with PATCH.",
        ));
    }

    let session = tokio::task::spawn_blocking(move || {
        store.create_upload(CreateUpload {
            upload_length,
            expected_content_id: metadata.content_id,
            upload_metadata: metadata_header,
            media_type: metadata.media_type,
            original_name: metadata.original_name,
        })
    })
    .await
    .map_err(|error| ApiError::unavailable(format!("content task failed: {error}")))?
    .map_err(blob_store_error)?;

    let mut response = StatusCode::CREATED.into_response();
    insert_header(
        response.headers_mut(),
        "location",
        &format!("/api/v1/uploads/{}", session.upload_id),
    )?;
    add_upload_headers(response.headers_mut(), &session, true)?;
    Ok(response)
}

async fn upload_status(
    State(state): State<ApiState>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match upload_status_inner(state, upload_id, headers).await {
        Ok(response) => response,
        Err(error) => tus_error_response(error),
    }
}

async fn upload_status_inner(
    state: ApiState,
    upload_id: String,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let store = full_blob_store(&state)?;
    require_tus_version(&headers)?;
    let upload_id = parse_upload_id(&upload_id)?;
    let session = tokio::task::spawn_blocking(move || store.upload(upload_id))
        .await
        .map_err(|error| ApiError::unavailable(format!("content task failed: {error}")))?
        .map_err(blob_store_error)?
        .ok_or_else(|| upload_not_found(upload_id))?;
    reject_expired_upload(&session)?;

    let mut response = StatusCode::OK.into_response();
    add_upload_headers(response.headers_mut(), &session, true)?;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn append_upload_chunk(
    State(state): State<ApiState>,
    Path(upload_id): Path<String>,
    request: Request,
) -> Response {
    let recovery_state = state.clone();
    let recovery_upload_id = upload_id.clone();
    match append_upload_chunk_inner(state, upload_id, request).await {
        Ok(response) => response,
        Err(error) => tus_error_with_upload_state(error, recovery_state, &recovery_upload_id).await,
    }
}

async fn append_upload_chunk_inner(
    state: ApiState,
    upload_id: String,
    request: Request,
) -> Result<Response, ApiError> {
    let store = full_blob_store(&state)?;
    require_tus_version(request.headers())?;
    let upload_id = parse_upload_id(&upload_id)?;
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if content_type != Some("application/offset+octet-stream") {
        return Err(ApiError::status(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "https://fractonica.com/problems/invalid-upload-content-type",
            "invalid_upload_content_type",
            "Invalid upload content type",
            "Content-Type must be application/offset+octet-stream.",
        ));
    }
    let supplied_offset = parse_required_u64_header(request.headers(), "upload-offset")?;
    let declared_length = parse_required_u64_header(request.headers(), "content-length")?;
    if declared_length == 0 || declared_length > MAX_PATCH_BYTES as u64 {
        return Err(ApiError::status(
            StatusCode::PAYLOAD_TOO_LARGE,
            "https://fractonica.com/problems/upload-chunk-too-large",
            "upload_chunk_too_large",
            "Upload chunk is too large",
            format!("PATCH chunks must contain 1-{MAX_PATCH_BYTES} bytes."),
        ));
    }
    let checksum_header = optional_ascii_header(request.headers(), "upload-checksum")?;
    let checksum = checksum_header
        .as_deref()
        .map(parse_upload_checksum)
        .transpose()?;
    let body = to_bytes(request.into_body(), MAX_PATCH_BYTES)
        .await
        .map_err(|_| {
            ApiError::status(
                StatusCode::PAYLOAD_TOO_LARGE,
                "https://fractonica.com/problems/upload-chunk-too-large",
                "upload_chunk_too_large",
                "Upload chunk is too large",
                format!("PATCH chunks must contain at most {MAX_PATCH_BYTES} bytes."),
            )
        })?;
    if body.is_empty() || body.len() as u64 != declared_length {
        return Err(ApiError::bad_request(
            "https://fractonica.com/problems/invalid-upload-chunk",
            "invalid_upload_chunk",
            "Invalid upload chunk",
            "Content-Length must equal the non-empty PATCH body length.",
        ));
    }
    let sha256 = verify_upload_checksum(checksum, &body)?;
    let bytes = body.to_vec();
    let outcome = tokio::task::spawn_blocking(move || {
        store.append_chunk(upload_id, supplied_offset, &bytes, sha256)
    })
    .await
    .map_err(|error| ApiError::unavailable(format!("content task failed: {error}")))?
    .map_err(blob_store_error)?;

    let mut response = StatusCode::NO_CONTENT.into_response();
    add_upload_headers(response.headers_mut(), &outcome.session, false)?;
    Ok(response)
}

async fn blob_availability(
    State(state): State<ApiState>,
    payload: Result<Json<BlobAvailabilityRequest>, JsonRejection>,
) -> Result<Json<BlobAvailabilityResponse>, ApiError> {
    let store = full_blob_store(&state)?;
    let Json(payload) = payload.map_err(|error| {
        ApiError::unprocessable(
            "https://fractonica.com/problems/invalid-content-query",
            "invalid_content_query",
            "Invalid content query",
            error.body_text(),
        )
    })?;
    if payload.content_ids.is_empty()
        || payload.content_ids.len() > MAX_AVAILABILITY_CONTENT_IDS
        || payload
            .content_ids
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            != payload.content_ids.len()
    {
        return Err(ApiError::unprocessable(
            "https://fractonica.com/problems/invalid-content-query",
            "invalid_content_query",
            "Invalid content query",
            format!("contentIds must contain 1-{MAX_AVAILABILITY_CONTENT_IDS} unique identifiers."),
        ));
    }
    let requested = payload.content_ids;
    let lookup_ids = requested.clone();
    let availability = tokio::task::spawn_blocking(move || store.availability(&lookup_ids))
        .await
        .map_err(|error| ApiError::unavailable(format!("content task failed: {error}")))?
        .map_err(blob_store_error)?;
    let mut descriptors: HashMap<ContentId, ContentDescriptor> = availability
        .available
        .into_iter()
        .map(|descriptor| (descriptor.content_id, descriptor))
        .collect();
    let mut available = Vec::new();
    let mut missing = Vec::new();
    for content_id in requested {
        if let Some(descriptor) = descriptors.remove(&content_id) {
            available.push(descriptor);
        } else {
            missing.push(content_id);
        }
    }
    Ok(Json(BlobAvailabilityResponse { available, missing }))
}

async fn head_blob(
    State(state): State<ApiState>,
    Path(content_id): Path<String>,
) -> Result<Response, ApiError> {
    let object = find_blob(&state, &content_id).await?;
    let mut response = Body::empty().into_response();
    add_blob_headers(
        response.headers_mut(),
        object.descriptor.content_id,
        object.descriptor.byte_length,
    )?;
    insert_header(
        response.headers_mut(),
        "repr-digest",
        &digest_header_value(object.descriptor.content_id.as_bytes()),
    )?;
    Ok(response)
}

async fn get_blob(
    State(state): State<ApiState>,
    Path(content_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let object = find_blob(&state, &content_id).await?;
    let total_length = object.descriptor.byte_length;
    let requested_range = optional_ascii_header(&headers, "range")?;
    let range = requested_range
        .as_deref()
        .map(|value| parse_byte_range(value, total_length))
        .transpose()?;
    let selected = range.unwrap_or(ByteRange {
        start: 0,
        length: total_length,
    });
    let digest = if range.is_some() {
        let path = object.path.clone();
        tokio::task::spawn_blocking(move || digest_file_range(path, selected))
            .await
            .map_err(|error| ApiError::unavailable(format!("content task failed: {error}")))?
            .map_err(|error| ApiError::unavailable(format!("failed to hash blob range: {error}")))?
    } else {
        object.descriptor.content_id.into_bytes()
    };

    let mut file = tokio::fs::File::open(&object.path)
        .await
        .map_err(|error| ApiError::unavailable(format!("failed to open blob: {error}")))?;
    file.seek(SeekFrom::Start(selected.start))
        .await
        .map_err(|error| ApiError::unavailable(format!("failed to seek blob: {error}")))?;
    let stream = ReaderStream::new(file.take(selected.length));
    let mut response = Body::from_stream(stream).into_response();
    if range.is_some() {
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
        let end = selected.start + selected.length - 1;
        insert_header(
            response.headers_mut(),
            "content-range",
            &format!("bytes {}-{end}/{total_length}", selected.start),
        )?;
    }
    add_blob_headers(
        response.headers_mut(),
        object.descriptor.content_id,
        selected.length,
    )?;
    insert_header(
        response.headers_mut(),
        "content-digest",
        &digest_header_value(&digest),
    )?;
    Ok(response)
}

async fn find_blob(
    state: &ApiState,
    content_id: &str,
) -> Result<fractonica_blob_store::BlobObject, ApiError> {
    let store = full_blob_store(state)?;
    let content_id = ContentId::parse(content_id).map_err(|error| {
        ApiError::unprocessable(
            "https://fractonica.com/problems/invalid-content-id",
            "invalid_content_id",
            "Invalid content ID",
            error.to_string(),
        )
    })?;
    tokio::task::spawn_blocking(move || store.blob(content_id))
        .await
        .map_err(|error| ApiError::unavailable(format!("content task failed: {error}")))?
        .map_err(blob_store_error)?
        .ok_or_else(|| {
            ApiError::not_found(
                "https://fractonica.com/problems/blob-not-found",
                "blob_not_found",
                "Blob not found",
                format!("Content {content_id} is not available on this node."),
            )
        })
}

fn parse_upload_id(value: &str) -> Result<UploadId, ApiError> {
    UploadId::parse(value).map_err(|error| {
        ApiError::not_found(
            "https://fractonica.com/problems/upload-not-found",
            "upload_not_found",
            "Upload not found",
            format!("Upload identifier is invalid: {error}"),
        )
    })
}

fn upload_not_found(upload_id: UploadId) -> ApiError {
    ApiError::not_found(
        "https://fractonica.com/problems/upload-not-found",
        "upload_not_found",
        "Upload not found",
        format!("Upload {upload_id} does not exist on this node."),
    )
}

fn parse_required_u64_header(headers: &HeaderMap, name: &'static str) -> Result<u64, ApiError> {
    let value = optional_ascii_header(headers, name)?.ok_or_else(|| {
        ApiError::bad_request(
            "https://fractonica.com/problems/invalid-upload-header",
            "invalid_upload_header",
            "Invalid upload header",
            format!("The {name} header is required."),
        )
    })?;
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(ApiError::bad_request(
            "https://fractonica.com/problems/invalid-upload-header",
            "invalid_upload_header",
            "Invalid upload header",
            format!("The {name} header must be a canonical non-negative integer."),
        ));
    }
    value.parse::<u64>().map_err(|_| {
        ApiError::bad_request(
            "https://fractonica.com/problems/invalid-upload-header",
            "invalid_upload_header",
            "Invalid upload header",
            format!("The {name} header must be a canonical non-negative integer."),
        )
    })
}

fn optional_ascii_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<Option<String>, ApiError> {
    headers
        .get(name)
        .map(|value| {
            value.to_str().map(str::to_owned).map_err(|_| {
                ApiError::bad_request(
                    "https://fractonica.com/problems/invalid-upload-header",
                    "invalid_upload_header",
                    "Invalid upload header",
                    format!("The {name} header must contain visible ASCII."),
                )
            })
        })
        .transpose()
}

fn require_tus_version(headers: &HeaderMap) -> Result<(), ApiError> {
    if optional_ascii_header(headers, "tus-resumable")?.as_deref() == Some(TUS_VERSION) {
        return Ok(());
    }
    Err(ApiError::status(
        StatusCode::PRECONDITION_FAILED,
        "https://fractonica.com/problems/unsupported-tus-version",
        "unsupported_tus_version",
        "Unsupported tus version",
        "Tus-Resumable must be 1.0.0.",
    )
    .with_header("tus-resumable", TUS_VERSION)
    .with_header("tus-version", TUS_VERSION))
}

fn parse_upload_metadata(value: Option<&str>) -> Result<UploadMetadata, ApiError> {
    let Some(value) = value else {
        return Ok(UploadMetadata::default());
    };
    if value.len() > MAX_UPLOAD_METADATA_BYTES {
        return Err(invalid_upload_metadata(format!(
            "Upload-Metadata exceeds {MAX_UPLOAD_METADATA_BYTES} bytes."
        )));
    }
    let mut seen = HashSet::new();
    let mut metadata = UploadMetadata::default();
    for item in value.split(',') {
        let (key, encoded) = item.split_once(' ').unwrap_or((item, ""));
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b',')
            || !seen.insert(key)
        {
            return Err(invalid_upload_metadata(
                "Metadata keys must be unique visible ASCII tokens.",
            ));
        }
        let decoded = BASE64_STANDARD.decode(encoded).map_err(|_| {
            invalid_upload_metadata(format!("Metadata value for {key} is not valid Base64."))
        })?;
        match key {
            "contentId" => {
                let text = String::from_utf8(decoded).map_err(|_| {
                    invalid_upload_metadata("contentId metadata must contain UTF-8 text.")
                })?;
                metadata.content_id = Some(ContentId::parse(&text).map_err(|error| {
                    invalid_upload_metadata(format!("contentId metadata is invalid: {error}"))
                })?);
            }
            "mediaType" => {
                let text = String::from_utf8(decoded).map_err(|_| {
                    invalid_upload_metadata("mediaType metadata must contain UTF-8 text.")
                })?;
                if text.is_empty()
                    || text.len() > MAX_MEDIA_TYPE_BYTES
                    || !text.is_ascii()
                    || text.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err(invalid_upload_metadata(format!(
                        "mediaType must contain 1-{MAX_MEDIA_TYPE_BYTES} visible ASCII bytes."
                    )));
                }
                metadata.media_type = Some(text);
            }
            "filename" | "originalName" => {
                let text = String::from_utf8(decoded).map_err(|_| {
                    invalid_upload_metadata("filename metadata must contain UTF-8 text.")
                })?;
                if text.is_empty()
                    || text.chars().count() > MAX_ORIGINAL_NAME_CHARS
                    || text.chars().any(char::is_control)
                {
                    return Err(invalid_upload_metadata(format!(
                        "filename must contain 1-{MAX_ORIGINAL_NAME_CHARS} non-control characters."
                    )));
                }
                if metadata.original_name.replace(text).is_some() {
                    return Err(invalid_upload_metadata(
                        "Supply only one of filename and originalName.",
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(metadata)
}

fn invalid_upload_metadata(detail: impl Into<String>) -> ApiError {
    ApiError::bad_request(
        "https://fractonica.com/problems/invalid-upload-metadata",
        "invalid_upload_metadata",
        "Invalid upload metadata",
        detail,
    )
}

enum UploadChecksum {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

fn parse_upload_checksum(value: &str) -> Result<UploadChecksum, ApiError> {
    let Some((algorithm, encoded)) = value.split_once(' ') else {
        return Err(invalid_upload_checksum(
            "Upload-Checksum must contain an algorithm and Base64 digest.",
        ));
    };
    if encoded.contains(' ') || encoded.is_empty() {
        return Err(invalid_upload_checksum(
            "Upload-Checksum must contain exactly one algorithm and digest.",
        ));
    }
    let digest = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| invalid_upload_checksum("Upload-Checksum does not contain valid Base64."))?;
    match algorithm {
        "sha1" => digest
            .try_into()
            .map(UploadChecksum::Sha1)
            .map_err(|_| invalid_upload_checksum("sha1 checksums must contain 20 bytes.")),
        "sha256" => digest
            .try_into()
            .map(UploadChecksum::Sha256)
            .map_err(|_| invalid_upload_checksum("sha256 checksums must contain 32 bytes.")),
        _ => Err(invalid_upload_checksum(
            "Supported checksum algorithms are sha1 and sha256.",
        )),
    }
}

fn invalid_upload_checksum(detail: impl Into<String>) -> ApiError {
    ApiError::bad_request(
        "https://fractonica.com/problems/invalid-upload-checksum",
        "invalid_upload_checksum",
        "Invalid upload checksum",
        detail,
    )
}

fn verify_upload_checksum(
    checksum: Option<UploadChecksum>,
    bytes: &[u8],
) -> Result<Option<[u8; 32]>, ApiError> {
    match checksum {
        None => Ok(None),
        Some(UploadChecksum::Sha1(expected)) => {
            let actual: [u8; 20] = Sha1::digest(bytes).into();
            if actual == expected {
                Ok(None)
            } else {
                Err(checksum_mismatch())
            }
        }
        Some(UploadChecksum::Sha256(expected)) => {
            let actual: [u8; 32] = Sha256::digest(bytes).into();
            if actual == expected {
                Ok(Some(expected))
            } else {
                Err(checksum_mismatch())
            }
        }
    }
}

fn checksum_mismatch() -> ApiError {
    ApiError::status(
        StatusCode::from_u16(460).expect("tus checksum mismatch is a valid extension status"),
        "https://fractonica.com/problems/upload-checksum-mismatch",
        "upload_checksum_mismatch",
        "Upload checksum mismatch",
        "The supplied chunk checksum did not match; no bytes were appended.",
    )
}

fn reject_expired_upload(session: &UploadSession) -> Result<(), ApiError> {
    if session.state != UploadState::Complete && unix_time_millis()? >= session.expires_at_unix_ms {
        return Err(ApiError::status(
            StatusCode::GONE,
            "https://fractonica.com/problems/upload-expired",
            "upload_expired",
            "Upload expired",
            format!("Upload {} is no longer resumable.", session.upload_id),
        ));
    }
    Ok(())
}

fn add_upload_headers(
    headers: &mut HeaderMap,
    session: &UploadSession,
    include_length_and_metadata: bool,
) -> Result<(), ApiError> {
    insert_header(headers, "tus-resumable", TUS_VERSION)?;
    insert_header(headers, "upload-offset", &session.upload_offset.to_string())?;
    insert_header(
        headers,
        "upload-expires",
        &format_http_date(session.expires_at_unix_ms)?,
    )?;
    if include_length_and_metadata {
        insert_header(headers, "upload-length", &session.upload_length.to_string())?;
        if let Some(metadata) = encode_upload_metadata(session) {
            insert_header(headers, "upload-metadata", &metadata)?;
        }
    }
    if let Some(content_id) = session.final_content_id {
        insert_header(headers, "fractonica-content-id", &content_id.to_string())?;
    }
    Ok(())
}

fn encode_upload_metadata(session: &UploadSession) -> Option<String> {
    session.upload_metadata.clone()
}

fn tus_error_response(error: ApiError) -> Response {
    let mut response = error.into_response();
    response
        .headers_mut()
        .insert("tus-resumable", HeaderValue::from_static(TUS_VERSION));
    if response.status() == StatusCode::PRECONDITION_FAILED {
        response
            .headers_mut()
            .insert("tus-version", HeaderValue::from_static(TUS_VERSION));
    }
    response
}

async fn tus_error_with_upload_state(
    error: ApiError,
    state: ApiState,
    upload_id: &str,
) -> Response {
    let mut response = tus_error_response(error);
    let (Some(store), Ok(upload_id)) = (state.blob_store, UploadId::parse(upload_id)) else {
        return response;
    };
    let session = tokio::task::spawn_blocking(move || store.upload(upload_id)).await;
    if let Ok(Ok(Some(session))) = session {
        let _ = add_upload_headers(response.headers_mut(), &session, false);
    }
    response
}

fn add_upload_options_cors_headers(response: &mut Response, request_headers: &HeaderMap) {
    const ALLOWED_ORIGINS: &[&str] = &[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:4173",
        "http://localhost:4173",
        "http://tauri.localhost",
        "tauri://localhost",
    ];
    let Some(origin) = request_headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|origin| ALLOWED_ORIGINS.contains(origin))
    else {
        return;
    };
    if let Ok(origin) = HeaderValue::from_str(origin) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        response
            .headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Origin"));
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST, OPTIONS"),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(
                "authorization, content-type, tus-resumable, upload-length, upload-metadata",
            ),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static(
                "location, fractonica-content-id, tus-checksum-algorithm, tus-extension, tus-max-size, tus-resumable, tus-version, upload-expires, upload-length, upload-metadata, upload-offset",
            ),
        );
    }
}

fn blob_store_error(error: BlobStoreError) -> ApiError {
    match error {
        BlobStoreError::UploadTooLarge { .. }
        | BlobStoreError::PatchTooLarge { .. }
        | BlobStoreError::UploadOverflow { .. } => ApiError::status(
            StatusCode::PAYLOAD_TOO_LARGE,
            "https://fractonica.com/problems/upload-too-large",
            "upload_too_large",
            "Upload is too large",
            error.to_string(),
        ),
        BlobStoreError::UploadNotFound(upload_id) => upload_not_found(upload_id),
        BlobStoreError::UploadExpired(_) => ApiError::status(
            StatusCode::GONE,
            "https://fractonica.com/problems/upload-expired",
            "upload_expired",
            "Upload expired",
            error.to_string(),
        ),
        BlobStoreError::UploadNotActive(_) | BlobStoreError::OffsetMismatch { .. } => {
            ApiError::conflict(
                "https://fractonica.com/problems/upload-conflict",
                "upload_conflict",
                "Upload conflict",
                error.to_string(),
            )
        }
        BlobStoreError::ChunkChecksumMismatch => checksum_mismatch(),
        BlobStoreError::ContentIdMismatch { .. } => ApiError::unprocessable(
            "https://fractonica.com/problems/content-id-mismatch",
            "content_id_mismatch",
            "Content ID mismatch",
            error.to_string(),
        ),
        BlobStoreError::Io(_)
        | BlobStoreError::Repository(_)
        | BlobStoreError::LockPoisoned
        | BlobStoreError::ClockBeforeUnixEpoch
        | BlobStoreError::Corrupt(_) => ApiError::unavailable(error.to_string()),
    }
}

fn add_blob_headers(
    headers: &mut HeaderMap,
    content_id: ContentId,
    content_length: u64,
) -> Result<(), ApiError> {
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    insert_header(headers, "content-length", &content_length.to_string())?;
    insert_header(headers, "etag", &format!("\"{content_id}\""))?;
    Ok(())
}

fn parse_byte_range(value: &str, total_length: u64) -> Result<ByteRange, ApiError> {
    let Some(specification) = value.strip_prefix("bytes=") else {
        return Err(range_not_satisfiable(total_length));
    };
    if specification.contains(',') || specification.is_empty() || total_length == 0 {
        return Err(range_not_satisfiable(total_length));
    }
    let Some((start, end)) = specification.split_once('-') else {
        return Err(range_not_satisfiable(total_length));
    };
    if start.is_empty() {
        let suffix = end
            .parse::<u64>()
            .ok()
            .filter(|suffix| *suffix > 0)
            .ok_or_else(|| range_not_satisfiable(total_length))?;
        let length = suffix.min(total_length);
        return Ok(ByteRange {
            start: total_length - length,
            length,
        });
    }
    let start = start
        .parse::<u64>()
        .map_err(|_| range_not_satisfiable(total_length))?;
    if start >= total_length {
        return Err(range_not_satisfiable(total_length));
    }
    let inclusive_end = if end.is_empty() {
        total_length - 1
    } else {
        end.parse::<u64>()
            .map_err(|_| range_not_satisfiable(total_length))?
            .min(total_length - 1)
    };
    if inclusive_end < start {
        return Err(range_not_satisfiable(total_length));
    }
    Ok(ByteRange {
        start,
        length: inclusive_end - start + 1,
    })
}

fn range_not_satisfiable(total_length: u64) -> ApiError {
    ApiError::status(
        StatusCode::RANGE_NOT_SATISFIABLE,
        "https://fractonica.com/problems/range-not-satisfiable",
        "range_not_satisfiable",
        "Range not satisfiable",
        format!("The requested byte range is not satisfiable for a {total_length}-byte blob."),
    )
    .with_header("content-range", format!("bytes */{total_length}"))
}

fn digest_file_range(path: PathBuf, range: ByteRange) -> std::io::Result<[u8; 32]> {
    let mut file = StdFile::open(path)?;
    file.seek(SeekFrom::Start(range.start))?;
    let mut remaining = range.length;
    let mut buffer = vec![0_u8; FILE_DIGEST_BUFFER_BYTES];
    let mut hasher = Sha256::new();
    while remaining > 0 {
        let capacity = u64::try_from(buffer.len()).expect("digest buffer length fits u64");
        let requested = usize::try_from(remaining.min(capacity)).expect("bounded by buffer length");
        let count = file.read(&mut buffer[..requested])?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "blob ended before the selected byte range",
            ));
        }
        hasher.update(&buffer[..count]);
        remaining -= u64::try_from(count).expect("read count fits u64");
    }
    Ok(hasher.finalize().into())
}

fn digest_header_value(digest: &[u8; 32]) -> String {
    format!("sha-256=:{}:", BASE64_STANDARD.encode(digest))
}

fn format_http_date(unix_ms: i64) -> Result<String, ApiError> {
    let milliseconds = u64::try_from(unix_ms)
        .map_err(|_| ApiError::unavailable("upload expiration precedes the Unix epoch"))?;
    Ok(httpdate::fmt_http_date(
        UNIX_EPOCH + Duration::from_millis(milliseconds),
    ))
}

fn unix_time_millis() -> Result<i64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::unavailable("system clock precedes the Unix epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| ApiError::unavailable("system clock is outside the supported range"))
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), ApiError> {
    let value = HeaderValue::from_str(value)
        .map_err(|error| ApiError::unavailable(format!("invalid response header: {error}")))?;
    headers.insert(HeaderName::from_static(name), value);
    Ok(())
}

fn operation_json_error(error: JsonRejection) -> ApiError {
    ApiError::unprocessable(
        "https://fractonica.com/problems/invalid-operation",
        "invalid_operation",
        "Invalid operation",
        error.body_text(),
    )
}

fn operation_query_error(error: QueryRejection) -> ApiError {
    ApiError::unprocessable(
        "https://fractonica.com/problems/invalid-operation-query",
        "invalid_operation_query",
        "Invalid operation query",
        error.body_text(),
    )
}

fn application_error(error: ApplicationError) -> ApiError {
    match error {
        ApplicationError::InvalidOperation(error) => ApiError::unprocessable(
            "https://fractonica.com/problems/invalid-operation",
            "invalid_operation",
            "Invalid operation",
            error.to_string(),
        ),
        ApplicationError::InvalidIdempotencyKey => ApiError::unprocessable(
            "https://fractonica.com/problems/invalid-idempotency-key",
            "invalid_idempotency_key",
            "Invalid idempotency key",
            "Idempotency-Key must satisfy the documented ASCII length and character bounds.",
        ),
        ApplicationError::InvalidChangeLimit => ApiError::unprocessable(
            "https://fractonica.com/problems/invalid-operation-query",
            "invalid_operation_query",
            "Invalid operation query",
            "The requested change-page limit is outside the supported range.",
        ),
        ApplicationError::SemanticEncoding(error) => {
            ApiError::unavailable(format!("failed to encode canonical operation: {error}"))
        }
        ApplicationError::Repository(repository_error) => match repository_error {
            conflict @ (RepositoryError::MissingParent(_)
            | RepositoryError::ParentMismatch { .. }
            | RepositoryError::EntityAlreadyExists(_)
            | RepositoryError::InvalidTopology(_)
            | RepositoryError::OperationConflict(_)
            | RepositoryError::IdempotencyConflict) => ApiError::conflict(
                "https://fractonica.com/problems/operation-conflict",
                "operation_conflict",
                "Operation conflict",
                conflict.to_string(),
            ),
            unavailable @ (RepositoryError::Corrupt(_) | RepositoryError::Unavailable(_)) => {
                ApiError::unavailable(unavailable.to_string())
            }
        },
    }
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
    use fractonica_data_model::ActorId;
    use fractonica_store_sqlite::SqliteStore;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::collections::HashSet;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let store = Arc::new(SqliteStore::open_in_memory().expect("database"));
        let state =
            ApiState::new(test_application(store), "Test Node", "0.1.0").expect("API state");
        router(state)
    }

    fn authenticated_test_app() -> Router {
        let store = Arc::new(SqliteStore::open_in_memory().expect("database"));
        let state = ApiState::new(test_application(store), "Test Node", "0.1.0")
            .expect("API state")
            .with_bearer_token("0123456789abcdef0123456789abcdef")
            .expect("bearer token");
        router(state)
    }

    fn content_test_app() -> (Router, TempDir) {
        let temporary = TempDir::new().expect("temporary content directory");
        let store = Arc::new(SqliteStore::open_in_memory().expect("database"));
        let blob_store = Arc::new(
            BlobStore::open(temporary.path().join("content"), Arc::clone(&store))
                .expect("blob store"),
        );
        let state = ApiState::new(test_application(store), "Test Node", "0.1.0")
            .expect("API state")
            .with_blob_store(blob_store);
        (router(state), temporary)
    }

    fn saros_only_app() -> Router {
        router(ApiState::new_saros_only("Saros test node", "0.1.0").expect("Saros-only API state"))
    }

    fn test_application(store: Arc<SqliteStore>) -> Arc<ApplicationService> {
        let installation = store.installation().expect("installation metadata");
        let actor_id = ActorId::new(installation.installation_id.as_uuid());
        Arc::new(ApplicationService::new(store, actor_id))
    }

    #[test]
    fn rejects_node_metadata_outside_the_public_contract() {
        let store = Arc::new(SqliteStore::open_in_memory().expect("database"));
        let application = test_application(Arc::clone(&store));
        assert!(matches!(
            ApiState::new(Arc::clone(&application), "", "0.1.0"),
            Err(ApiStateError::InvalidDisplayName)
        ));
        assert!(matches!(
            ApiState::new(Arc::clone(&application), "x".repeat(129), "0.1.0"),
            Err(ApiStateError::InvalidDisplayName)
        ));
        assert!(matches!(
            ApiState::new(application, "Test Node", ""),
            Err(ApiStateError::InvalidVersion)
        ));

        let store = Arc::new(SqliteStore::open_in_memory().expect("database"));
        assert!(matches!(
            ApiState::new(test_application(store), "Test Node", "0.1.0")
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
                let properties = schema.get("properties").and_then(Value::as_object);
                if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                    let properties = properties.expect("closed OpenAPI object properties");
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
                if let Some(properties) = properties {
                    for (key, property_schema) in properties {
                        if let Some(property) = object.get(key) {
                            assert_schema(property, property_schema, contract);
                        }
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
            Some("boolean") => assert!(value.is_boolean(), "OpenAPI boolean"),
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
        assert_eq!(
            body["storage"]["schemaVersion"],
            fractonica_store_sqlite::SCHEMA_VERSION
        );
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
    async fn appends_replays_pages_and_materializes_operations() {
        let app = test_app();
        let operation_id = "019f6f11-8e23-7b81-b923-71773bbd5132";
        let entity_id = "019f6f11-a1d7-72b1-8db1-6fa9e9c45b89";
        let operation = serde_json::json!({
            "protocolVersion": 1,
            "operationId": operation_id,
            "entityId": entity_id,
            "schema": "record.v1",
            "causalParents": [],
            "occurredAtUnixMs": 1_784_390_400_000_i64,
            "body": {
                "kind": "put",
                "document": {
                    "startAtUnixMs": 1_784_390_400_000_i64,
                    "visibility": "private",
                    "emoji": "🌀",
                    "metadata": {"source": "API test"}
                }
            }
        });
        let append_request = || {
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/operations")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "operation-create-0001")
                .body(Body::from(
                    serde_json::to_vec(&operation).expect("operation JSON"),
                ))
                .expect("request")
        };

        let accepted = app
            .clone()
            .oneshot(append_request())
            .await
            .expect("response");
        assert_eq!(accepted.status(), StatusCode::CREATED);
        let accepted = json(accepted).await;
        assert_contract_schema("StoredOperation", &accepted);
        assert_eq!(accepted["localSequence"], 1);
        assert_eq!(accepted["operation"]["operationId"], operation_id);
        assert!(accepted["operation"]["actorId"].is_string());

        let replayed = app
            .clone()
            .oneshot(append_request())
            .await
            .expect("response");
        assert_eq!(replayed.status(), StatusCode::OK);
        assert_eq!(json(replayed).await, accepted);

        let changes = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/operations?after=0&limit=1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(changes.status(), StatusCode::OK);
        let changes = json(changes).await;
        assert_contract_schema("OperationPage", &changes);
        assert_eq!(
            changes["operations"].as_array().expect("operations").len(),
            1
        );
        assert_eq!(changes["nextAfter"], 1);
        assert_eq!(changes["hasMore"], false);

        let entity = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/entities/{entity_id}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(entity.status(), StatusCode::OK);
        let entity = json(entity).await;
        assert_contract_schema("EntityState", &entity);
        assert_eq!(entity["entityId"], entity_id);
        assert_eq!(entity["operationCount"], 1);
        assert_eq!(entity["conflicted"], false);
        assert_eq!(entity["heads"][0], accepted);
    }

    #[tokio::test]
    async fn rejects_missing_parents_and_stateful_routes_in_saros_profile() {
        let operation = serde_json::json!({
            "protocolVersion": 1,
            "operationId": "019f6f12-2bf9-72b2-ac3f-8659537a2220",
            "entityId": "019f6f12-38ca-7f80-b4dd-cea4b2fa7f4b",
            "schema": "record.v1",
            "causalParents": ["019f6f12-45c1-7f40-a09c-622cf6bdba2b"],
            "occurredAtUnixMs": 1_784_390_400_000_i64,
            "body": {
                "kind": "put",
                "document": {
                    "startAtUnixMs": 1_784_390_400_000_i64,
                    "visibility": "public"
                }
            }
        });
        let request = || {
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/operations")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "missing-parent-0001")
                .body(Body::from(
                    serde_json::to_vec(&operation).expect("operation JSON"),
                ))
                .expect("request")
        };

        let conflict = test_app().oneshot(request()).await.expect("response");
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let conflict = json(conflict).await;
        assert_contract_schema("Problem", &conflict);
        assert_eq!(conflict["code"], "operation_conflict");

        let unavailable = saros_only_app().oneshot(request()).await.expect("response");
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        let unavailable = json(unavailable).await;
        assert_contract_schema("Problem", &unavailable);
        assert_eq!(unavailable["code"], "node_not_ready");

        let spoofed_actor = serde_json::json!({
            "protocolVersion": 1,
            "operationId": "019f6f12-6b24-76e3-b720-c51853671102",
            "entityId": "019f6f12-7553-7c10-991f-cb7d8ff7628f",
            "actorId": "019f6f12-7f3f-7801-b0cc-34311f8f370f",
            "schema": "record.v1",
            "causalParents": [],
            "occurredAtUnixMs": 1_784_390_400_000_i64,
            "body": {
                "kind": "put",
                "document": {
                    "startAtUnixMs": 1_784_390_400_000_i64,
                    "visibility": "public"
                }
            }
        });
        let spoofed = test_app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/operations")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "spoofed-actor-0001")
                    .body(Body::from(
                        serde_json::to_vec(&spoofed_actor).expect("operation JSON"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(spoofed.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let spoofed = json(spoofed).await;
        assert_eq!(spoofed["code"], "invalid_operation");
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
    async fn uploads_discovers_and_streams_content_with_ranges() {
        let (app, _temporary) = content_test_app();
        let bytes = b"hello world";
        let content_id = fractonica_content::hash_bytes(bytes);
        let capabilities = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/api/v1/uploads")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(capabilities.status(), StatusCode::NO_CONTENT);
        assert_eq!(capabilities.headers()["tus-version"], TUS_VERSION);
        assert_eq!(capabilities.headers()["tus-extension"], TUS_EXTENSIONS);
        assert_eq!(
            capabilities.headers()["tus-checksum-algorithm"],
            TUS_CHECKSUM_ALGORITHMS
        );
        let metadata = format!(
            "contentId {},mediaType {},filename {},agent {}",
            BASE64_STANDARD.encode(content_id.to_string()),
            BASE64_STANDARD.encode("text/plain"),
            BASE64_STANDARD.encode("greeting.txt"),
            BASE64_STANDARD.encode("exeligmos-importer")
        );
        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/uploads")
                    .header("tus-resumable", TUS_VERSION)
                    .header("upload-length", bytes.len())
                    .header("upload-metadata", metadata)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(created.headers()["tus-resumable"], TUS_VERSION);
        assert_eq!(created.headers()["upload-offset"], "0");
        let location = created.headers()[header::LOCATION]
            .to_str()
            .expect("location")
            .to_owned();

        let checksum = BASE64_STANDARD.encode(Sha256::digest(bytes));
        let patched = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PATCH)
                    .uri(&location)
                    .header("tus-resumable", TUS_VERSION)
                    .header(header::CONTENT_TYPE, "application/offset+octet-stream")
                    .header(header::CONTENT_LENGTH, bytes.len())
                    .header("upload-offset", 0)
                    .header("upload-checksum", format!("sha256 {checksum}"))
                    .body(Body::from(bytes.as_slice()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(patched.status(), StatusCode::NO_CONTENT);
        assert_eq!(patched.headers()["upload-offset"], bytes.len().to_string());
        assert_eq!(
            patched.headers()["fractonica-content-id"],
            content_id.to_string()
        );

        let upload_head = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri(&location)
                    .header("tus-resumable", TUS_VERSION)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(upload_head.status(), StatusCode::OK);
        assert_eq!(
            upload_head.headers()["upload-length"],
            bytes.len().to_string()
        );
        assert_eq!(
            upload_head.headers()["fractonica-content-id"],
            content_id.to_string()
        );
        assert_eq!(
            upload_head.headers()["upload-metadata"],
            format!(
                "contentId {},mediaType {},filename {},agent {}",
                BASE64_STANDARD.encode(content_id.to_string()),
                BASE64_STANDARD.encode("text/plain"),
                BASE64_STANDARD.encode("greeting.txt"),
                BASE64_STANDARD.encode("exeligmos-importer")
            )
        );

        let availability = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/blobs/availability")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "contentIds": [content_id]
                        }))
                        .expect("JSON"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(availability.status(), StatusCode::OK);
        let availability = json(availability).await;
        assert_eq!(
            availability["available"][0]["contentId"],
            content_id.to_string()
        );
        assert_eq!(availability["available"][0]["byteLength"], bytes.len());
        assert_eq!(availability["missing"], serde_json::json!([]));

        let blob_uri = format!("/api/v1/blobs/{content_id}");
        let blob_head = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri(&blob_uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(blob_head.status(), StatusCode::OK);
        assert_eq!(
            blob_head.headers()[header::CONTENT_LENGTH],
            bytes.len().to_string()
        );
        assert_eq!(
            blob_head.headers()["repr-digest"],
            digest_header_value(content_id.as_bytes())
        );

        let complete = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&blob_uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(complete.status(), StatusCode::OK);
        assert_eq!(
            complete.headers()["content-digest"],
            digest_header_value(content_id.as_bytes())
        );
        assert_eq!(
            complete
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
            bytes.as_slice()
        );

        let partial = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&blob_uri)
                    .header(header::RANGE, "bytes=1-4")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(partial.headers()[header::CONTENT_RANGE], "bytes 1-4/11");
        assert_eq!(
            partial.headers()["content-digest"],
            digest_header_value(&Sha256::digest(b"ello").into())
        );
        assert_eq!(
            partial
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
            b"ello".as_slice()
        );

        let unsatisfied = app
            .oneshot(
                Request::builder()
                    .uri(&blob_uri)
                    .header(header::RANGE, "bytes=99-")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unsatisfied.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(unsatisfied.headers()[header::CONTENT_RANGE], "bytes */11");
    }

    #[tokio::test]
    async fn rejects_bad_upload_checksums_without_advancing_and_content_in_saros() {
        let (app, _temporary) = content_test_app();
        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/uploads")
                    .header("tus-resumable", TUS_VERSION)
                    .header("upload-length", 3)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let location = created.headers()[header::LOCATION]
            .to_str()
            .expect("location")
            .to_owned();
        let mismatch = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PATCH)
                    .uri(&location)
                    .header("tus-resumable", TUS_VERSION)
                    .header(header::CONTENT_TYPE, "application/offset+octet-stream")
                    .header(header::CONTENT_LENGTH, 3)
                    .header("upload-offset", 0)
                    .header(
                        "upload-checksum",
                        format!("sha256 {}", BASE64_STANDARD.encode([0_u8; 32])),
                    )
                    .body(Body::from(&b"abc"[..]))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(mismatch.status().as_u16(), 460);
        assert_eq!(mismatch.headers()["tus-resumable"], TUS_VERSION);

        let upload_head = app
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri(&location)
                    .header("tus-resumable", TUS_VERSION)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(upload_head.headers()["upload-offset"], "0");

        let unavailable = saros_only_app()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/api/v1/uploads")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(unavailable.headers()["tus-resumable"], TUS_VERSION);
    }

    #[tokio::test]
    async fn rejected_empty_upload_digest_does_not_poison_a_restart() {
        let temporary = TempDir::new().expect("temporary node directory");
        let database_path = temporary.path().join("node.sqlite3");
        let content_root = temporary.path().join("content");
        let store = Arc::new(SqliteStore::open(&database_path).expect("database"));
        let blob_store =
            Arc::new(BlobStore::open(&content_root, Arc::clone(&store)).expect("content storage"));
        let state = ApiState::new(test_application(store), "Test Node", "0.1.0")
            .expect("API state")
            .with_blob_store(blob_store);
        let app = router(state);
        let wrong_content_id = fractonica_content::hash_bytes(b"not empty");
        let metadata = format!(
            "contentId {}",
            BASE64_STANDARD.encode(wrong_content_id.to_string())
        );

        let rejected = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/uploads")
                    .header("tus-resumable", TUS_VERSION)
                    .header("upload-length", 0)
                    .header("upload-metadata", metadata)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            std::fs::read_dir(content_root.join("staging"))
                .expect("staging directory")
                .count(),
            0
        );

        let reopened_store = Arc::new(SqliteStore::open(database_path).expect("reopen database"));
        BlobStore::open(content_root, reopened_store).expect("restart content storage");
    }

    #[tokio::test]
    async fn refuses_to_serve_or_advertise_same_length_corrupt_content() {
        let temporary = TempDir::new().expect("temporary content directory");
        let store = Arc::new(SqliteStore::open_in_memory().expect("database"));
        let blob_store = Arc::new(
            BlobStore::open(temporary.path().join("content"), Arc::clone(&store))
                .expect("blob store"),
        );
        let bytes = b"good";
        let content_id = fractonica_content::hash_bytes(bytes);
        let upload = blob_store
            .create_upload(CreateUpload {
                upload_length: bytes.len() as u64,
                expected_content_id: Some(content_id),
                upload_metadata: None,
                media_type: None,
                original_name: None,
            })
            .expect("create upload");
        blob_store
            .append_chunk(upload.upload_id, 0, bytes, None)
            .expect("complete upload");
        let blob_path = blob_store
            .blob(content_id)
            .expect("verify blob")
            .expect("blob")
            .path;
        std::fs::write(blob_path, b"evil").expect("same-length corruption");
        let state = ApiState::new(test_application(store), "Test Node", "0.1.0")
            .expect("API state")
            .with_blob_store(blob_store);
        let app = router(state);

        let blob = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/blobs/{content_id}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(blob.status(), StatusCode::SERVICE_UNAVAILABLE);

        let availability = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/blobs/availability")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "contentIds": [content_id]
                        }))
                        .expect("JSON"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(availability.status(), StatusCode::SERVICE_UNAVAILABLE);
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
