// src/ldap/filter.rs

use crate::models::*;
use crate::directory_service::DirectoryService;
use crate::ldap::asn1::Asn1;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum Filter {
    Equality(String, String),
    GreaterOrEqual(String, String),
    LessOrEqual(String, String),
    ApproxMatch(String, String),
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Present(String),
}

impl Filter {
    /// Разбирает фильтр из строки (например, "(sAMAccountName=jdoe)")
    pub fn parse(s: &str) -> Result<Self, LdapFilterError> {
        let s = s.trim();
        if !s.starts_with('(') || !s.ends_with(')') {
            return Err(LdapFilterError::InvalidSyntax);
        }

        let inner = &s[1..s.len() - 1];

        if inner.is_empty() {
            return Err(LdapFilterError::InvalidSyntax);
        }

        Self::parse_inner(inner)
    }

    fn parse_inner(s: &str) -> Result<Self, LdapFilterError> {
        match s.chars().next() {
            Some('&') => {
                Self::parse_list(&s[1..], |items| Ok(Filter::And(items)))
            }
            Some('|') => {
                Self::parse_list(&s[1..], |items| Ok(Filter::Or(items)))
            }
            Some('!') => {
                let filter = Self::parse_inner(&s[1..])?;
                Ok(Filter::Not(Box::new(filter)))
            }
            _ => {
                // Простой фильтр: attr=value
                if let Some(eq_pos) = s.find('=') {
                    let attr = s[..eq_pos].to_lowercase();
                    let value = s[eq_pos + 1..].to_string();

                    let filter = match attr.as_str() {
                        "objectclass" => Filter::Equality("objectClass".to_string(), value),
                        "samaccountname" => Filter::Equality("sAMAccountName".to_string(), value),
                        "cn" => Filter::Equality("cn".to_string(), value),
                        "name" => Filter::Equality("name".to_string(), value),
                        "mail" => Filter::Equality("mail".to_string(), value),
                        "userprincipalname" => Filter::Equality("userPrincipalName".to_string(), value),
                        _ if attr.ends_with(":dn") => {
                            // Поддержка: cn:dn:=John
                            Filter::ApproxMatch(attr, value)
                        }
                        _ => Filter::Equality(attr, value),
                    };

                    Ok(filter)
                } else if s.ends_with("=*") {
                    let attr = &s[..s.len() - 2];
                    Ok(Filter::Present(attr.to_string()))
                } else {
                    Err(LdapFilterError::InvalidSyntax)
                }
            }
        }
    }

    fn parse_list<F>(s: &str, constructor: F) -> Result<Filter, LdapFilterError>
    where
        F: FnOnce(Vec<Filter>) -> Result<Filter, LdapFilterError>,
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
                        let filter = Filter::parse(substr)?;
                        filters.push(filter);
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

        constructor(filters)
    }

    /// Проверяет, соответствует ли объект фильтру
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
            Filter::Present(attr) => match attr.as_str() {
                "sAMAccountName" => !user.username.is_empty(),
                "cn" | "name" => user.display_name.is_some(),
                "mail" | "email" => user.email.is_some(),
                _ => false,
            },
            Filter::And(filters) => filters.iter().all(|f| f.matches_user(user)),
            Filter::Or(filters) => filters.iter().any(|f| f.matches_user(user)),
            Filter::Not(filter) => !filter.matches_user(user),
            _ => false,
        }
    }

    /// Проверяет с учётом сервиса (например, tokenGroups)
    pub async fn matches_user_with_service(
        &self,
        user: &User,
        service: &DirectoryService,
    ) -> Result<bool, LdapFilterError> {
        match self {
            Filter::Present(attr) if attr == "tokenGroups" => {
                // tokenGroups всегда "присутствует", если запрошен
                Ok(true)
            }
            Filter::Equality(attr, _) if attr == "tokenGroups" => {
                // tokenGroups нельзя сравнивать по значению (упрощённо)
                Ok(false)
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

    pub fn matches_group(&self, group: &Group) -> bool {
        match self {
            Filter::Equality(attr, value) => match attr.as_str() {
                "sAMAccountName" => group.sam_account_name.eq_ignore_ascii_case(value),
                "cn" | "name" => group.name.eq_ignore_ascii_case(value),
                "objectClass" => matches_object_class(value, &["group"]),
                _ => false,
            },
            Filter::Present(attr) => match attr.as_str() {
                "sAMAccountName" => !group.sam_account_name.is_empty(),
                "cn" | "name" => !group.name.is_empty(),
                _ => false,
            },
            Filter::And(filters) => filters.iter().all(|f| f.matches_group(group)),
            Filter::Or(filters) => filters.iter().any(|f| f.matches_group(group)),
            Filter::Not(filter) => !filter.matches_group(group),
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

impl std::fmt::Display for LdapFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LdapFilterError::InvalidSyntax => write!(f, "Invalid filter syntax"),
            LdapFilterError::NotImplemented => write!(f, "Not implemented"),
        }
    }
}

impl std::error::Error for LdapFilterError {}