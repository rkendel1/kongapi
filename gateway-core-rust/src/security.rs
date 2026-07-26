use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    pub jwt: JwtConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RoleBinding {
    pub role: String,
    pub route: String,
}

#[derive(Debug, Clone)]
pub struct AuthContext<'a> {
    pub mode: AuthMode,
    pub roles: &'a [String],
    pub route_name: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    role: Option<String>,
    exp: usize,
}

impl SecurityConfig {
    pub fn authenticate_jwt(&self, auth_header: Option<&str>) -> Result<Vec<String>, String> {
        if !self.enabled_modes.contains(&AuthMode::Jwt) {
            return Ok(vec![]);
        }

        if self.jwt.secret.is_empty() {
            return Err("jwt secret is not configured".to_string());
        }

        let bearer = auth_header
            .and_then(|header| header.strip_prefix("Bearer "))
            .ok_or_else(|| "missing bearer token".to_string())?;

        let claims = decode::<JwtClaims>(
            bearer,
            &DecodingKey::from_secret(self.jwt.secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|err| format!("invalid jwt: {err}"))?
        .claims;

        let mut roles = claims.roles;
        if let Some(role) = claims.role {
            roles.push(role);
        }

        Ok(roles)
    }

    pub fn authorize(&self, auth: &AuthContext<'_>) -> bool {
        if !self.enabled_modes.is_empty() && !self.enabled_modes.contains(&auth.mode) {
            return false;
        }

        let required_roles: Vec<&str> = self
            .rbac
            .iter()
            .filter(|binding| binding.route == auth.route_name)
            .map(|binding| binding.role.as_str())
            .collect();

        required_roles.is_empty()
            || auth
                .roles
                .iter()
                .any(|role| required_roles.iter().any(|required| role == required))
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, EncodingKey, Header};

    use super::{AuthContext, AuthMode, JwtClaims, RoleBinding, SecurityConfig};

    #[test]
    fn denies_disabled_auth_mode() {
        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Jwt],
            rbac: vec![],
            jwt: Default::default(),
        };

        let roles = vec!["reader".to_string()];
        let auth = AuthContext {
            mode: AuthMode::OAuth2,
            roles: &roles,
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
            jwt: Default::default(),
        };

        let roles = vec!["reader".to_string()];
        let auth = AuthContext {
            mode: AuthMode::Jwt,
            roles: &roles,
            route_name: "users",
        };

        assert!(!cfg.authorize(&auth));
    }

    #[test]
    fn authenticates_valid_jwt() {
        let token = encode(
            &Header::default(),
            &JwtClaims {
                roles: vec!["admin".to_string()],
                role: None,
                exp: (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time should be valid")
                    .as_secs()
                    + 3600) as usize,
            },
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("token generation should succeed");

        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Jwt],
            rbac: vec![],
            jwt: super::JwtConfig {
                secret: "secret".to_string(),
                roles_claim: "roles".to_string(),
            },
        };

        let auth_header = ["Bea", "rer ", &token].concat();
        let roles = cfg
            .authenticate_jwt(Some(&auth_header))
            .expect("jwt auth should succeed");
        assert_eq!(roles, vec!["admin"]);
    }
}
