// src/ldap/filter.rs

use crate::models::*;
use crate::directory_service::DirectoryService;

#[derive(Debug, Clone)]
pub enum Filter {
    Equality(String, String),
    GreaterOrEqual(String, String),
    LessOrEqual(String, String),
    ApproxMatch(String, String),
    Substring { attr: String, initial: Option<String>, any: Vec<String>, final_: Option<String> },
    Extensible {
        attr: String,
        rule: Option<String>,
        dn_attrs: bool,
        value: String,
    },
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Present(String),
}

impl Filter {
    pub fn parse(s: &str) -> Result<Self, LdapFilterError> {
        let s = s.trim();
        if !s.starts_with('(') || !s.ends_with(')') {
            return Err(LdapFilterError::InvalidSyntax);
        }
        Self::parse_inner(&s[1..s.len() - 1])
    }

    fn parse_inner(s: &str) -> Result<Self, LdapFilterError> {
        match s.chars().next() {
            Some('&') => Self::parse_list(&s[1..], Filter::And),
            Some('|') => Self::parse_list(&s[1..], Filter::Or),
            Some('!') => Ok(Filter::Not(Box::new(Self::parse_inner(&s[1..])?))),
            _ => Self::parse_simple(s),
        }
    }

    fn parse_simple(s: &str) -> Result<Self, LdapFilterError> {
        if let Some(eq_pos) = s.find('=') {
            let attr = s[..eq_pos].to_string();
            let value = s[eq_pos + 1..].to_string();

            if attr.ends_with(":dn") {
                return Ok(Filter::Extensible {
                    attr: attr.trim_end_matches(":dn").to_string(),
                    rule: None,
                    dn_attrs: true,
                    value,
                });
            }
            if let Some(rule_pos) = attr.rfind(':') {
                let rule = &attr[rule_pos + 1..];
                let base_attr = &attr[..rule_pos];
                if rule.ends_with("Match") {
                    return Ok(Filter::Extensible {
                        attr: base_attr.to_string(),
                        rule: Some(rule.to_string()),
                        dn_attrs: false,
                        value,
                    });
                }
            }

            if value == "*" {
                return Ok(Filter::Present(attr));
            }

            if value.contains('*') {
                return Self::parse_substring(&attr, &value);
            }

            if attr.ends_with(">=") {
                return Ok(Filter::GreaterOrEqual(attr.trim_end_matches(">=").to_string(), value));
            }
            if attr.ends_with("<=") {
                return Ok(Filter::LessOrEqual(attr.trim_end_matches("<=").to_string(), value));
            }

            Ok(Filter::Equality(attr, value))
        } else {
            Err(LdapFilterError::InvalidSyntax)
        }
    }

    fn parse_substring(attr: &str, pattern: &str) -> Result<Self, LdapFilterError> {
        let parts: Vec<&str> = pattern.split('*').collect();
        let mut any = Vec::new();
        let mut initial = None;
        let mut final_ = None;

        if !parts.is_empty() && !parts[0].is_empty() {
            initial = Some(parts[0].to_string());
        }
        for part in &parts[1..parts.len() - 1] {
            if !part.is_empty() {
                any.push(part.to_string());
            }
        }
        if let Some(last) = parts.last() {
            if !last.is_empty() {
                final_ = Some(last.to_string());
            }
        }

        Ok(Filter::Substring {
            attr: attr.to_string(),
            initial,
            any,
            final_,
        })
    }

    fn parse_list<F>(s: &str, constructor: F) -> Result<Filter, LdapFilterError>
    where
        F: FnOnce(Vec<Filter>) -> Filter,
    {
        let mut filters = Vec::new();
        let mut depth = 0;
        let mut start = 0;

        for (i, ch) in s.chars().enumerate() {
            match ch {
                '(' => {
                    if depth == 0 {
                        start = i;
                    }
                    depth += 1;
                }
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        let substr = &s[start..=i];
                        filters.push(Filter::parse(substr)?);
                    } else if depth < 0 {
                        return Err(LdapFilterError::InvalidSyntax);
                    }
                }
                _ => {}
            }
        }

        if depth != 0 {
            return Err(LdapFilterError::InvalidSyntax);
        }

        Ok(constructor(filters))
    }

    pub async fn matches_user_with_service(
        &self,
        user: &User,
        service: &DirectoryService,
    ) -> Result<bool, LdapFilterError> {
        match self {
            Filter::Present(attr) if attr == "tokenGroups" => {
                let tokens = service.get_token_groups(user.id).await?;
                Ok(!tokens.is_empty())
            }
            Filter::Equality(attr, value) if attr == "memberOf" => {
                let groups = service.find_groups_by_member(user.id).await?;
                let target_dn = value.to_uppercase();
                Ok(groups.iter().any(|g| {
                    DirectoryService::generate_group_dn(&g.sam_account_name, &Domain::default()).to_uppercase() == target_dn
                }))
            }
            Filter::And(filters) => {
                for f in filters {
                    if !f.matches_user_with_service(user, service).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Filter::Or(filters) => {
                for f in filters {
                    if f.matches_user_with_service(user, service).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Filter::Not(filter) => Ok(!filter.matches_user_with_service(user, service).await?),
            _ => Ok(self.matches_user(user)),
        }
    }

    pub fn matches_user(&self, user: &User) -> bool {
        match self {
            Filter::Equality(attr, value) => match attr.as_str() {
                "sAMAccountName" => user.username.eq_ignore_ascii_case(value),
                "cn" | "name" => user.display_name.as_ref().map_or(false, |n| n.eq_ignore_ascii_case(value)),
                "mail" | "email" => user.email.as_ref().map_or(false, |e| e.eq_ignore_ascii_case(value)),
                "userPrincipalName" => user.user_principal_name.eq_ignore_ascii_case(value),
                "objectClass" => matches_object_class(value, &["user", "person"]),
                _ => false,
            },
            Filter::Substring { attr, initial, any, final_ } => {
                let text = match attr.as_str() {
                    "sAMAccountName" => &user.username,
                    "cn" | "name" => user.display_name.as_deref().unwrap_or(""),
                    "mail" | "email" => user.email.as_deref().unwrap_or(""),
                    _ => return false,
                };
                let mut matched = true;
                if let Some(init) = initial {
                    matched &= text.starts_with(init);
                }
                for part in any {
                    matched &= text.contains(part);
                }
                if let Some(fin) = final_ {
                    matched &= text.ends_with(fin);
                }
                matched
            }
            Filter::GreaterOrEqual(attr, value) => {
                match attr.as_str() {
                    "created_at" => user.created_at >= chrono::DateTime::parse_from_rfc3339(value).ok().unwrap_or_default(),
                    _ => false,
                }
            }
            Filter::LessOrEqual(attr, value) => {
                match attr.as_str() {
                    "created_at" => user.created_at <= chrono::DateTime::parse_from_rfc3339(value).ok().unwrap_or_default(),
                    _ => false,
                }
            }
            Filter::Present(attr) => match attr.as_str() {
                "sAMAccountName" => !user.username.is_empty(),
                "cn" | "name" => user.display_name.is_some(),
                "mail" | "email" => user.email.is_some(),
                _ => false,
            },
            _ => false,
        }
    }
}

fn matches_object_class(value: &str, valid: &[&str]) -> bool {
    valid.iter().any(|&cls| cls.eq_ignore_ascii_case(value))
}

#[derive(Debug)]
pub enum LdapFilterError {
    InvalidSyntax,
    NotImplemented,
}