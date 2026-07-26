use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use http::{header::AUTHORIZATION, HeaderMap};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    Jwt,
    OAuth2,
    OpenIdConnect,
    Mtls,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SecurityConfig {
    #[serde(default)]
    pub enabled_modes: Vec<AuthMode>,
    #[serde(default)]
    pub rbac: Vec<RoleBinding>,
    #[serde(default)]
    pub group_rbac: Vec<GroupBinding>,
    #[serde(default)]
    pub jwt: JwtConfig,
    #[serde(default)]
    pub oauth2: OAuth2Config,
    #[serde(default)]
    pub openid_connect: OpenIdConnectConfig,
    #[serde(default)]
    pub mtls: MtlsConfig,
    #[serde(default)]
    pub subject_rbac: Vec<SubjectBinding>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct JwtConfig {
    #[serde(default)]
    pub secret: String,
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
}

fn default_roles_claim() -> String {
    "roles".to_string()
}

fn default_groups_claim() -> String {
    "groups".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct OAuth2Config {
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct OpenIdConnectConfig {
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
}

fn default_mtls_subject_header() -> String {
    "x-client-cert-subject".to_string()
}

fn default_mtls_roles_header() -> String {
    "x-client-cert-roles".to_string()
}

fn default_mtls_groups_header() -> String {
    "x-client-cert-groups".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct MtlsConfig {
    #[serde(default = "default_mtls_subject_header")]
    pub subject_header: String,
    #[serde(default = "default_mtls_roles_header")]
    pub roles_header: String,
    #[serde(default = "default_mtls_groups_header")]
    pub groups_header: String,
    #[serde(default)]
    pub allowed_subjects: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RoleBinding {
    pub role: String,
    pub route: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GroupBinding {
    pub group: String,
    pub route: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SubjectBinding {
    pub subject: String,
    pub route: String,
}

#[derive(Debug, Clone)]
pub struct AuthContext<'a> {
    pub mode: AuthMode,
    pub roles: &'a [String],
    pub groups: &'a [String],
    pub subject: Option<&'a str>,
    pub route_name: &'a str,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    pub mode: AuthMode,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub subject: Option<String>,
}

impl SecurityConfig {
    pub fn authenticate(&self, headers: &HeaderMap) -> Result<AuthenticatedIdentity, String> {
        if self.enabled_modes.is_empty() {
            return Ok(AuthenticatedIdentity {
                mode: AuthMode::Jwt,
                roles: vec![],
                groups: vec![],
                subject: None,
            });
        }

        let mut errors = Vec::with_capacity(self.enabled_modes.len());
        for mode in &self.enabled_modes {
            match self.authenticate_mode(mode, headers) {
                Ok(identity) => return Ok(identity),
                Err(err) => errors.push(format!("{mode:?}: {err}")),
            }
        }

        Err(format!(
            "authentication failed for all enabled modes: {}",
            errors.join(" | ")
        ))
    }

    fn authenticate_mode(
        &self,
        mode: &AuthMode,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedIdentity, String> {
        match mode {
            AuthMode::Jwt => {
                let claims = decode_token_claims(
                    headers,
                    &self.jwt.secret,
                    None,
                    None,
                    "invalid jwt",
                )?;
                Ok(AuthenticatedIdentity {
                    mode: mode.clone(),
                    roles: extract_claim_values(&claims, &self.jwt.roles_claim, true),
                    groups: extract_claim_values(&claims, &self.jwt.groups_claim, false),
                    subject: None,
                })
            }
            AuthMode::OAuth2 => {
                let claims = decode_token_claims(
                    headers,
                    &self.oauth2.secret,
                    non_empty(&self.oauth2.issuer),
                    non_empty(&self.oauth2.audience),
                    "invalid oauth2 token",
                )?;
                Ok(AuthenticatedIdentity {
                    mode: mode.clone(),
                    roles: extract_claim_values(&claims, &self.oauth2.roles_claim, false),
                    groups: extract_claim_values(&claims, &self.oauth2.groups_claim, false),
                    subject: None,
                })
            }
            AuthMode::OpenIdConnect => {
                let claims = decode_token_claims(
                    headers,
                    &self.openid_connect.secret,
                    non_empty(&self.openid_connect.issuer),
                    non_empty(&self.openid_connect.audience),
                    "invalid openid connect token",
                )?;
                Ok(AuthenticatedIdentity {
                    mode: mode.clone(),
                    roles: extract_claim_values(&claims, &self.openid_connect.roles_claim, false),
                    groups: extract_claim_values(&claims, &self.openid_connect.groups_claim, false),
                    subject: None,
                })
            }
            AuthMode::Mtls => {
                let subject = headers
                    .get(&self.mtls.subject_header)
                    .and_then(|value| value.to_str().ok())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "missing mTLS subject".to_string())?
                    .to_string();

                if !self.mtls.allowed_subjects.is_empty()
                    && !self.mtls.allowed_subjects.iter().any(|allowed| allowed == &subject)
                {
                    return Err("mTLS subject is not allowed".to_string());
                }

                Ok(AuthenticatedIdentity {
                    mode: mode.clone(),
                    roles: extract_header_values(headers, &self.mtls.roles_header),
                    groups: extract_header_values(headers, &self.mtls.groups_header),
                    subject: Some(subject),
                })
            }
        }
    }

    pub fn authorize(&self, auth: &AuthContext<'_>) -> bool {
        if !self.enabled_modes.is_empty() && !self.enabled_modes.contains(&auth.mode) {
            return false;
        }

        let required_roles: HashSet<&str> = self
            .rbac
            .iter()
            .filter(|binding| binding.route == auth.route_name)
            .map(|binding| binding.role.as_str())
            .collect();

        let required_groups: HashSet<&str> = self
            .group_rbac
            .iter()
            .filter(|binding| binding.route == auth.route_name)
            .map(|binding| binding.group.as_str())
            .collect();

        let required_subjects: HashSet<&str> = self
            .subject_rbac
            .iter()
            .filter(|binding| binding.route == auth.route_name)
            .map(|binding| binding.subject.as_str())
            .collect();

        let role_allowed = required_roles.is_empty()
            || auth
                .roles
                .iter()
                .any(|role| required_roles.contains(role.as_str()));

        let group_allowed = required_groups.is_empty()
            || auth
                .groups
                .iter()
                .any(|group| required_groups.contains(group.as_str()));

        let subject_allowed = required_subjects.is_empty()
            || auth
                .subject
                .map(|subject| required_subjects.contains(subject))
                .unwrap_or(false);

        role_allowed && group_allowed && subject_allowed
    }
}

fn non_empty(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn decode_token_claims(
    headers: &HeaderMap,
    secret: &str,
    issuer: Option<&str>,
    audience: Option<&str>,
    invalid_token_message: &str,
) -> Result<serde_json::Value, String> {
    if secret.is_empty() {
        return Err("token secret is not configured".to_string());
    }

    let bearer = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or_else(|| "missing bearer token".to_string())?;

    let mut validation = Validation::new(Algorithm::HS256);
    if let Some(issuer) = issuer {
        validation.set_issuer(&[issuer]);
    }
    if let Some(audience) = audience {
        validation.set_audience(&[audience]);
    }

    decode::<serde_json::Value>(
        bearer,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|err| format!("{invalid_token_message}: {err}"))
    .map(|decoded| decoded.claims)
}

fn extract_claim_values(claims: &serde_json::Value, claim_name: &str, include_legacy_role: bool) -> Vec<String> {
    let mut values = vec![];
    if let Some(value) = claims.get(claim_name) {
        if let Some(arr) = value.as_array() {
            for item in arr {
                if let Some(item) = item.as_str() {
                    values.extend(split_identity_values(item));
                }
            }
        } else if let Some(single) = value.as_str() {
            values.extend(split_identity_values(single));
        }
    }

    if include_legacy_role {
        if let Some(single_role) = claims.get("role").and_then(|v| v.as_str()) {
            values.push(single_role.to_string());
        }
    }

    values
}

fn extract_header_values(headers: &HeaderMap, header_name: &str) -> Vec<String> {
    headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            split_identity_values(value)
        })
        .unwrap_or_default()
}

fn split_identity_values(value: &str) -> Vec<String> {
    value
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use http::HeaderMap;
    use jsonwebtoken::{encode, EncodingKey, Header};

    use super::{
        AuthContext, AuthMode, GroupBinding, MtlsConfig, OpenIdConnectConfig, OAuth2Config, RoleBinding,
        SecurityConfig, SubjectBinding,
    };

    #[test]
    fn denies_disabled_auth_mode() {
        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Jwt],
            rbac: vec![],
            group_rbac: vec![],
            jwt: Default::default(),
            oauth2: Default::default(),
            openid_connect: Default::default(),
            mtls: Default::default(),
            subject_rbac: vec![],
        };

        let roles = vec!["reader".to_string()];
        let groups = vec![];
        let auth = AuthContext {
            mode: AuthMode::OAuth2,
            roles: &roles,
            groups: &groups,
            subject: None,
            route_name: "users",
        };

        assert!(!cfg.authorize(&auth));
    }

    #[test]
    fn enforces_route_rbac() {
        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Jwt],
            rbac: vec![RoleBinding {
                role: "admin".to_string(),
                route: "users".to_string(),
            }],
            group_rbac: vec![],
            jwt: Default::default(),
            oauth2: Default::default(),
            openid_connect: Default::default(),
            mtls: Default::default(),
            subject_rbac: vec![],
        };

        let roles = vec!["reader".to_string()];
        let groups = vec![];
        let auth = AuthContext {
            mode: AuthMode::Jwt,
            roles: &roles,
            groups: &groups,
            subject: None,
            route_name: "users",
        };

        assert!(!cfg.authorize(&auth));
    }

    #[test]
    fn authenticates_valid_jwt() {
        let token = encode(
            &Header::default(),
            &serde_json::json!({
                "roles": ["admin"],
                "exp": (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time should be valid")
                    .as_secs()
                    + 3600) as usize
            }),
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("token generation should succeed");

        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Jwt],
            rbac: vec![],
            group_rbac: vec![],
            jwt: super::JwtConfig {
                secret: "secret".to_string(),
                roles_claim: "roles".to_string(),
                groups_claim: "groups".to_string(),
            },
            oauth2: Default::default(),
            openid_connect: Default::default(),
            mtls: Default::default(),
            subject_rbac: vec![],
        };

        let auth_header = ["Bearer ", &token].concat();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth_header.parse().expect("header value should parse"));
        let identity = cfg.authenticate(&headers).expect("jwt auth should succeed");
        assert_eq!(identity.mode, AuthMode::Jwt);
        assert_eq!(identity.roles, vec!["admin"]);
    }

    #[test]
    fn authenticates_valid_oauth2_token() {
        let token = encode(
            &Header::default(),
            &serde_json::json!({
                "scope": "read write",
                "groups": ["engineering"],
                "iss": "https://issuer.example",
                "aud": "gateway-api",
                "exp": (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time should be valid")
                    .as_secs()
                    + 3600) as usize
            }),
            &EncodingKey::from_secret(b"oauth-secret"),
        )
        .expect("token generation should succeed");

        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::OAuth2],
            rbac: vec![],
            group_rbac: vec![],
            jwt: Default::default(),
            oauth2: OAuth2Config {
                secret: "oauth-secret".to_string(),
                issuer: "https://issuer.example".to_string(),
                audience: "gateway-api".to_string(),
                roles_claim: "scope".to_string(),
                groups_claim: "groups".to_string(),
            },
            openid_connect: Default::default(),
            mtls: Default::default(),
            subject_rbac: vec![],
        };

        let auth_header = ["Bearer ", &token].concat();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth_header.parse().expect("header value should parse"));
        let identity = cfg.authenticate(&headers).expect("oauth2 auth should succeed");
        assert_eq!(identity.mode, AuthMode::OAuth2);
        assert_eq!(identity.roles, vec!["read", "write"]);
        assert_eq!(identity.groups, vec!["engineering"]);
    }

    #[test]
    fn authenticates_valid_openid_connect_token() {
        let token = encode(
            &Header::default(),
            &serde_json::json!({
                "roles": ["admin"],
                "groups": ["sre"],
                "iss": "https://idp.example",
                "aud": "gateway-api",
                "exp": (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time should be valid")
                    .as_secs()
                    + 3600) as usize
            }),
            &EncodingKey::from_secret(b"oidc-secret"),
        )
        .expect("token generation should succeed");

        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::OpenIdConnect],
            rbac: vec![],
            group_rbac: vec![],
            jwt: Default::default(),
            oauth2: Default::default(),
            openid_connect: OpenIdConnectConfig {
                secret: "oidc-secret".to_string(),
                issuer: "https://idp.example".to_string(),
                audience: "gateway-api".to_string(),
                roles_claim: "roles".to_string(),
                groups_claim: "groups".to_string(),
            },
            mtls: Default::default(),
            subject_rbac: vec![],
        };

        let auth_header = ["Bearer ", &token].concat();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth_header.parse().expect("header value should parse"));
        let identity = cfg.authenticate(&headers).expect("oidc auth should succeed");
        assert_eq!(identity.mode, AuthMode::OpenIdConnect);
        assert_eq!(identity.roles, vec!["admin"]);
        assert_eq!(identity.groups, vec!["sre"]);
    }

    #[test]
    fn enforces_group_rbac() {
        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Jwt],
            rbac: vec![],
            group_rbac: vec![GroupBinding {
                group: "platform".to_string(),
                route: "users".to_string(),
            }],
            jwt: Default::default(),
            oauth2: Default::default(),
            openid_connect: Default::default(),
            mtls: Default::default(),
            subject_rbac: vec![],
        };

        let roles = vec![];
        let groups = vec!["platform".to_string()];
        let auth = AuthContext {
            mode: AuthMode::Jwt,
            roles: &roles,
            groups: &groups,
            subject: None,
            route_name: "users",
        };

        assert!(cfg.authorize(&auth));
    }

    #[test]
    fn authenticates_mtls_identity_from_headers() {
        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Mtls],
            rbac: vec![],
            group_rbac: vec![],
            jwt: Default::default(),
            oauth2: Default::default(),
            openid_connect: Default::default(),
            mtls: MtlsConfig {
                subject_header: "x-client-subject".to_string(),
                roles_header: "x-client-roles".to_string(),
                groups_header: "x-client-groups".to_string(),
                allowed_subjects: vec!["CN=svc-a".to_string()],
            },
            subject_rbac: vec![],
        };

        let mut headers = HeaderMap::new();
        headers.insert("x-client-subject", "CN=svc-a".parse().expect("header value should parse"));
        headers.insert("x-client-roles", "admin,writer".parse().expect("header value should parse"));
        headers.insert("x-client-groups", "platform ops".parse().expect("header value should parse"));

        let identity = cfg.authenticate(&headers).expect("mTLS auth should succeed");
        assert_eq!(identity.mode, AuthMode::Mtls);
        assert_eq!(identity.subject.as_deref(), Some("CN=svc-a"));
        assert_eq!(identity.roles, vec!["admin", "writer"]);
        assert_eq!(identity.groups, vec!["platform", "ops"]);
    }

    #[test]
    fn enforces_route_subject_binding() {
        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Mtls],
            rbac: vec![],
            group_rbac: vec![],
            jwt: Default::default(),
            oauth2: Default::default(),
            openid_connect: Default::default(),
            mtls: Default::default(),
            subject_rbac: vec![SubjectBinding {
                subject: "CN=svc-a".to_string(),
                route: "users".to_string(),
            }],
        };

        let roles = vec![];
        let groups = vec![];
        let auth = AuthContext {
            mode: AuthMode::Mtls,
            roles: &roles,
            groups: &groups,
            subject: Some("CN=svc-a"),
            route_name: "users",
        };

        assert!(cfg.authorize(&auth));
    }

    #[test]
    fn falls_back_to_later_enabled_auth_mode() {
        let token = encode(
            &Header::default(),
            &serde_json::json!({
                "scope": "read",
                "exp": (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time should be valid")
                    .as_secs()
                    + 3600) as usize
            }),
            &EncodingKey::from_secret(b"oauth-secret"),
        )
        .expect("token generation should succeed");

        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Jwt, AuthMode::OAuth2],
            rbac: vec![],
            group_rbac: vec![],
            jwt: super::JwtConfig {
                secret: "".to_string(),
                roles_claim: "roles".to_string(),
                groups_claim: "groups".to_string(),
            },
            oauth2: OAuth2Config {
                secret: "oauth-secret".to_string(),
                issuer: "".to_string(),
                audience: "".to_string(),
                roles_claim: "scope".to_string(),
                groups_claim: "groups".to_string(),
            },
            openid_connect: Default::default(),
            mtls: Default::default(),
            subject_rbac: vec![],
        };

        let auth_header = ["Bearer ", &token].concat();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth_header.parse().expect("header value should parse"));
        let identity = cfg.authenticate(&headers).expect("oauth2 fallback auth should succeed");
        assert_eq!(identity.mode, AuthMode::OAuth2);
        assert_eq!(identity.roles, vec!["read"]);
    }
}
