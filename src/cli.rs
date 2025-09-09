// src/cli.rs

use crate::directory_service::DirectoryService;
use crate::models::*;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;
use futures::future::join_all;

#[derive(Parser)]
#[command(name = "mextdomen")]
#[command(about = "Утилита управления Active Directory", long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE", default_value = "data")]
    pub data_dir: String,

    #[arg(short, long, value_name = "KEY", default_value = "0000000000000000000000000000000000000000000000000000000000000000")]
    pub key: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Clone)] // ✅ Добавлено Clone
pub enum Commands {
    /// Управление пользователями
    User {
        #[command(subcommand)]
        action: UserCommands,
    },
    /// Управление группами
    Group {
        #[command(subcommand)]
        action: GroupCommands,
    },
    /// Управление OU
    Ou {
        #[command(subcommand)]
        action: OuCommands,
    },
    /// Управление доменом
    Domain {
        #[command(subcommand)]
        action: DomainCommands,
    },
    /// Управление GPO
    Gpo {
        #[command(subcommand)]
        action: GpoCommands,
    },
}

#[derive(Subcommand, Clone)] // ✅
pub enum UserCommands {
    Create {
        username: String,
        #[arg(short, long)]
        email: Option<String>,
        #[arg(short, long)]
        display_name: Option<String>,
        #[arg(short, long)]
        given_name: Option<String>,
        #[arg(short, long)]
        surname: Option<String>,
        #[arg(short, long)]
        ou: Option<String>,
        #[arg(long, default_value = "513")]
        primary_group: u32,
    },
    List {
        #[arg(long, action)]
        json: bool,
        #[arg(long, action)]
        quiet: bool,
    },
    Show {
        username: String,
        #[arg(long, action)]
        json: bool,
    },
    Delete {
        username: String,
        #[arg(long, action)]
        quiet: bool,
    },
    Rename {
        username: String,
        #[arg(short, long)]
        new_username: Option<String>,
        #[arg(short, long)]
        display_name: Option<String>,
        #[arg(long, action)]
        quiet: bool,
    },
}

#[derive(Subcommand, Clone)] // ✅
pub enum GroupCommands {
    Create {
        name: String,
        #[arg(short, long)]
        sam_account_name: Option<String>,
    },
    AddMember {
        group: String,
        user: String,
    },
    RemoveMember {
        group: String,
        user: String,
    },
    ListMembers {
        group: String,
        #[arg(long, action)]
        json: bool,
        #[arg(long, action)]
        quiet: bool,
    },
    Delete {
        group: String,
        #[arg(long, action)]
        quiet: bool,
    },
}

#[derive(Subcommand, Clone)] // ✅
pub enum OuCommands {
    Create {
        name: String,
        #[arg(short, long)]
        parent: Option<String>,
    },
    List {
        #[arg(long, action)]
        json: bool,
        #[arg(long, action)]
        quiet: bool,
    },
}

#[derive(Subcommand, Clone)] // ✅
pub enum DomainCommands {
    Create {
        name: String,
        dns_name: String,
    },
    List,
}

#[derive(Subcommand, Clone)] // ✅
pub enum GpoCommands {
    Link {
        gpo_id: String,
        to: String,
    },
    Unlink {
        gpo_id: String,
        from: String,
    },
}

impl Cli {
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let key = Self::parse_key(&self.key)?;
        let service = Arc::new(DirectoryService::open(&self.data_dir, &key)?);

        // ✅ Убрано `ref action`, потому что теперь `action: UserCommands` можно переместить
        match self.command.clone() {
            Commands::User { action } => self.handle_user(action.clone(), &service).await?,
            Commands::Group { action } => self.handle_group(action.clone(), &service).await?,
            Commands::Ou { action } => self.handle_ou(action.clone(), &service).await?,
            Commands::Domain { action } => self.handle_domain(action.clone(), &service).await?,
            Commands::Gpo { action } => self.handle_gpo(action.clone(), &service).await?,
        }

        Ok(())
    }

    async fn handle_user(&self, cmd: UserCommands, service: &DirectoryService) -> Result<(), Box<dyn std::error::Error>> {
        match cmd {
            UserCommands::Create { username, email, display_name, given_name, surname, ou: ref _ou, primary_group } => { // ✅ `ref _ou`
                let domain_users_id = Uuid::from_u128(0x513);
                let _domain_users = service.get_group(domain_users_id).await?
                    .ok_or("Domain Users group not found")?;

                let user = User {
                    id: Uuid::new_v4(),
                    sid: SecurityIdentifier::new_nt_authority(1001),
                    username: username.clone(),
                    user_principal_name: format!("{}@corp.acme.com", username),
                    email,
                    display_name,
                    given_name,
                    surname,
                    password_hash: PasswordHash::new_bcrypt("P@ssw0rd!")?,
                    password_expires: None,
                    last_password_change: Utc::now(),
                    lockout_until: None,
                    failed_logins: 0,
                    enabled: true,
                    mfa_enabled: false,
                    mfa_methods: vec![],
                    domains: vec![],
                    groups: vec![domain_users_id],
                    organizational_unit: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    last_login: None,
                    profile_path: None,
                    script_path: None,
                    meta: std::collections::HashMap::new(),
                    primary_group_id: Some(primary_group),
                };

                service.create_user(&user).await?;
                service.add_member_to_group(domain_users_id, user.id).await?;

                println!("✅ User {} created and added to Domain Users", user.username);
            }
            UserCommands::List { json, quiet } => {
                let users = service.get_all_users().await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&users)?);
                } else if !quiet {
                    println!("📋 Users:");
                    for user in &users {
                        let name = user.display_name.as_deref().unwrap_or("No Name");
                        println!("  - {} ({})", user.username, name);
                    }
                    println!("Total: {} users", users.len());
                }
            }
            UserCommands::Show { username, json } => {
                if let Some(user) = service.find_user_by_username(&username).await? {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&user)?);
                    } else {
                        println!("{}", serde_json::to_string_pretty(&user)?);
                    }
                } else {
                    eprintln!("❌ User not found: {}", username);
                }
            }
            UserCommands::Delete { username, quiet } => {
                let user = service.find_user_by_username(&username).await?
                    .ok_or("User not found")?;

                service.delete_user(user.id).await?;

                if !quiet {
                    println!("✅ User {} deleted", username);
                }
            }
            UserCommands::Rename { username, new_username, display_name, quiet } => {
                let user = service.find_user_by_username(&username).await?
                    .ok_or("User not found")?;

                service.rename_user(user.id, new_username.clone(), display_name.clone()).await?;

                if !quiet {
                    println!("✅ User {} renamed", username);
                }
            }
        }
        Ok(())
    }

    async fn handle_group(&self, cmd: GroupCommands, service: &DirectoryService) -> Result<(), Box<dyn std::error::Error>> {
        match cmd {
            GroupCommands::Create { name, sam_account_name } => {
                let sam = sam_account_name.unwrap_or_else(|| name.to_uppercase());
                let group = Group::new(
                    name.clone(),
                    sam,
                    Uuid::nil(),
                    GroupTypeFlags::SECURITY,
                    GroupScope::Global,
                );
                service.create_group(&group).await?;
                println!("✅ Group {} created", group.name);
            }
            GroupCommands::AddMember { group, user } => {
                let group_obj = service.find_group_by_sam_account_name(&group).await?
                    .ok_or("Group not found")?;
                let user_obj = service.find_user_by_username(&user).await?
                    .ok_or("User not found")?;

                service.add_member_to_group(group_obj.id, user_obj.id).await?;
                println!("✅ {} added to {}", user, group);
            }
            GroupCommands::RemoveMember { group, user } => {
                let group_obj = service.find_group_by_sam_account_name(&group).await?
                    .ok_or("Group not found")?;
                let user_obj = service.find_user_by_username(&user).await?
                    .ok_or("User not found")?;

                service.remove_member_from_group(group_obj.id, user_obj.id).await?;
                println!("✅ {} removed from {}", user, group);
            }
            GroupCommands::ListMembers { group, json, quiet } => {
                let group_obj = service.find_group_by_sam_account_name(&group).await?
                    .ok_or("Group not found")?;

                // ✅ async move
                let members: Vec<String> = join_all(
                    group_obj.members.iter().map(|&id| async move {
                        service.get_user(id).await.ok().flatten().map(|u| u.username)
                    })
                ).await.into_iter().flatten().collect();

                if json {
                    println!("{}", serde_json::to_string_pretty(&members)?);
                } else if !quiet {
                    println!("👥 Members of '{}':", group_obj.name);
                    for username in &members {
                        println!("  - {}", username);
                    }
                    println!("Total: {} members", members.len());
                }
            }
            GroupCommands::Delete { group, quiet } => {
                let group_obj = service.find_group_by_sam_account_name(&group).await?
                    .ok_or("Group not found")?;

                service.delete_group(group_obj.id).await?;

                if !quiet {
                    println!("✅ Group {} deleted", group);
                }
            }
        }
        Ok(())
    }

    async fn handle_ou(&self, cmd: OuCommands, service: &DirectoryService) -> Result<(), Box<dyn std::error::Error>> {
        match cmd {
            OuCommands::Create { name, parent } => {
                let dn = DirectoryService::generate_ou_dn(&name, parent.as_deref());
                let ou = OrganizationalUnit::new(name, dn, None);
                service.create_ou(&ou).await?;
                println!("✅ OU created: {}", ou.dn);
            }
            OuCommands::List { json, quiet } => {
                let ous = service.get_all_ous().await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&ous)?);
                } else if !quiet {
                    println!("📁 Organizational Units:");
                    for ou in &ous {
                        println!("  - {} (DN: {})", ou.name, ou.dn);
                    }
                    println!("Total: {} OUs", ous.len());
                }
            }
        }
        Ok(())
    }

    async fn handle_domain(&self, cmd: DomainCommands, service: &DirectoryService) -> Result<(), Box<dyn std::error::Error>> {
        match cmd {
            DomainCommands::Create { name, dns_name } => {
                let domain = Domain::new_with_defaults(
                    name,
                    dns_name,
                    SecurityIdentifier::new_nt_authority(512),
                );
                service.create_domain(&domain).await?;
                println!("✅ Domain {} created", domain.dns_name);
            }
            DomainCommands::List => {
                println!("Domain list: not implemented");
            }
        }
        Ok(())
    }

    async fn handle_gpo(&self, cmd: GpoCommands, _service: &DirectoryService) -> Result<(), Box<dyn std::error::Error>> {
        match cmd {
            GpoCommands::Link { gpo_id, to: _to } => {
                let _gpo_id = Uuid::parse_str(&gpo_id)?;
                println!("GPO link: not implemented");
            }
            GpoCommands::Unlink { gpo_id: _gpo_id, from: _from } => {
                println!("GPO unlink: not implemented");
            }
        }
        Ok(())
    }

    pub fn parse_key(key_str: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        if key_str.len() >= 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_str.as_bytes()[..32]);
            Ok(arr)
        } else {
            Err("Key must be at least 32 bytes".into())
        }
    }
}