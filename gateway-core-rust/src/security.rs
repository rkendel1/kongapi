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

impl SecurityConfig {
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
    use super::{AuthContext, AuthMode, RoleBinding, SecurityConfig};

    #[test]
    fn denies_disabled_auth_mode() {
        let cfg = SecurityConfig {
            enabled_modes: vec![AuthMode::Jwt],
            rbac: vec![],
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
        };

        let roles = vec!["reader".to_string()];
        let auth = AuthContext {
            mode: AuthMode::Jwt,
            roles: &roles,
            route_name: "users",
        };

        assert!(!cfg.authorize(&auth));
    }
}
