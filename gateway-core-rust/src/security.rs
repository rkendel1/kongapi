use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct JwtConfig {
    #[serde(default)]
    pub secret: String,
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
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

#[derive(Debug, Clone)]
pub struct AuthContext<'a> {
    pub mode: AuthMode,
    pub roles: &'a [String],
    pub groups: &'a [String],
    pub route_name: &'a str,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    pub mode: AuthMode,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
}

impl SecurityConfig {
    pub fn authenticate(&self, auth_header: Option<&str>) -> Result<AuthenticatedIdentity, String> {
        if self.enabled_modes.is_empty() {
            return Ok(AuthenticatedIdentity {
                mode: AuthMode::Jwt,
                roles: vec![],
                groups: vec![],
            });
        }

        let mode = self.enabled_modes[0].clone();
        match mode {
            AuthMode::Jwt => {
                let claims = decode_token_claims(
                    auth_header,
                    &self.jwt.secret,
                    None,
                    None,
                    "invalid jwt",
                )?;
                Ok(AuthenticatedIdentity {
                    mode,
                    roles: extract_claim_values(&claims, &self.jwt.roles_claim, true),
                    groups: extract_claim_values(&claims, &default_groups_claim(), false),
                })
            }
            AuthMode::OAuth2 => {
                let claims = decode_token_claims(
                    auth_header,
                    &self.oauth2.secret,
                    non_empty(&self.oauth2.issuer),
                    non_empty(&self.oauth2.audience),
                    "invalid oauth2 token",
                )?;
                Ok(AuthenticatedIdentity {
                    mode,
                    roles: extract_claim_values(&claims, &self.oauth2.roles_claim, false),
                    groups: extract_claim_values(&claims, &self.oauth2.groups_claim, false),
                })
            }
            AuthMode::OpenIdConnect => {
                let claims = decode_token_claims(
                    auth_header,
                    &self.openid_connect.secret,
                    non_empty(&self.openid_connect.issuer),
                    non_empty(&self.openid_connect.audience),
                    "invalid openid connect token",
                )?;
                Ok(AuthenticatedIdentity {
                    mode,
                    roles: extract_claim_values(&claims, &self.openid_connect.roles_claim, false),
                    groups: extract_claim_values(&claims, &self.openid_connect.groups_claim, false),
                })
            }
            AuthMode::Mtls => Err("mTLS auth mode is not implemented yet".to_string()),
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

        role_allowed && group_allowed
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
    auth_header: Option<&str>,
    secret: &str,
    issuer: Option<&str>,
    audience: Option<&str>,
    invalid_token_message: &str,
) -> Result<serde_json::Value, String> {
    if secret.is_empty() {
        return Err("token secret is not configured".to_string());
    }

    let bearer = auth_header
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
            values.extend(arr.iter().filter_map(|item| item.as_str().map(ToOwned::to_owned)));
        } else if let Some(single) = value.as_str() {
            values.extend(single.split_whitespace().map(ToOwned::to_owned));
        }
    }

    if include_legacy_role {
        if let Some(single_role) = claims.get("role").and_then(|v| v.as_str()) {
            values.push(single_role.to_string());
        }
    }

    values
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, EncodingKey, Header};

    use super::{AuthContext, AuthMode, GroupBinding, OpenIdConnectConfig, OAuth2Config, RoleBinding, SecurityConfig};

    #[test]
    fn denies_disabled_auth_mode() {
        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Jwt],
            rbac: vec![],
            group_rbac: vec![],
            jwt: Default::default(),
            oauth2: Default::default(),
            openid_connect: Default::default(),
        };

        let roles = vec!["reader".to_string()];
        let groups = vec![];
        let auth = AuthContext {
            mode: AuthMode::OAuth2,
            roles: &roles,
            groups: &groups,
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
        };

        let roles = vec!["reader".to_string()];
        let groups = vec![];
        let auth = AuthContext {
            mode: AuthMode::Jwt,
            roles: &roles,
            groups: &groups,
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
            },
            oauth2: Default::default(),
            openid_connect: Default::default(),
        };

        let auth_header = ["Bearer ", &token].concat();
        let identity = cfg.authenticate(Some(&auth_header)).expect("jwt auth should succeed");
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
        };

        let auth_header = ["Bearer ", &token].concat();
        let identity = cfg.authenticate(Some(&auth_header)).expect("oauth2 auth should succeed");
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
        };

        let auth_header = ["Bearer ", &token].concat();
        let identity = cfg.authenticate(Some(&auth_header)).expect("oidc auth should succeed");
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
        };

        let roles = vec![];
        let groups = vec!["platform".to_string()];
        let auth = AuthContext {
            mode: AuthMode::Jwt,
            roles: &roles,
            groups: &groups,
            route_name: "users",
        };

        assert!(cfg.authorize(&auth));
    }
}
