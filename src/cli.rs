// src/cli.rs

use crate::directory_service::DirectoryService;
use clap::Parser;
use std::sync::Arc;

/// Точка входа CLI — сам создаёт service
pub async fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let key = decode_key(&config.master_key_hex)?;
    
    // Создаём сервис внутри CLI
    let service = Arc::new(DirectoryService::open(&config.db_path, &key)?);

    let cli = Cli::parse();

    match cli.command {
        Command::User { cmd } => handle_user(cmd, &service).await?,
        Command::Group { cmd } => handle_group(cmd, &service).await?,
        Command::Ou { cmd } => handle_ou(cmd, &service).await?,
        Command::Gpo { cmd } => handle_gpo(cmd, &service).await?,
    }

    Ok(())
}

// === CLI ===

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Управление пользователями
    User {
        #[command(subcommand)]
        cmd: UserCommand,
    },
    /// Управление группами
    Group {
        #[command(subcommand)]
        cmd: GroupCommand,
    },
    /// Управление организационными подразделениями (OU)
    Ou {
        #[command(subcommand)]
        cmd: OuCommand,
    },
    /// Управление групповыми политиками (GPO)
    Gpo {
        #[command(subcommand)]
        cmd: GpoCommand,
    },
}

// === Подкоманды ===

#[derive(clap::Subcommand)]
enum UserCommand {
    Create {
        username: String,
        #[clap(short, long)]
        email: Option<String>,
        #[clap(short, long)]
        display_name: Option<String>,
    },
    Get { username: String },
    List { #[clap(short, long)] json: bool },
    Delete { username: String },
}

#[derive(clap::Subcommand)]
enum GroupCommand {
    Create {
        name: String,
        #[clap(long)]
        sam_account_name: Option<String>,
    },
    Get { sam: String },
    AddMember {
        sam: String,
        #[clap(long)]
        user_id: uuid::Uuid,
    },
    RemoveMember {
        sam: String,
        #[clap(long)]
        user_id: uuid::Uuid,
    },
    List { #[clap(short, long)] json: bool },
}

#[derive(clap::Subcommand)]
enum OuCommand {
    Create {
        name: String,
        #[clap(long)]
        parent: Option<String>,
    },
    List,
}

#[derive(clap::Subcommand)]
enum GpoCommand {
    Create {
        name: String,
        #[clap(long)]
        display_name: Option<String>,
        #[clap(long)]
        description: Option<String>,
        #[clap(long)]
        linked_to: Vec<uuid::Uuid>,
        #[clap(long)]
        enforced: bool,
        #[clap(long)]
        enabled: bool,
    },
    List { #[clap(short, long)] json: bool },
    Link {
        gpo_id: uuid::Uuid,
        ou_id: uuid::Uuid,
    },
    Unlink {
        gpo_id: uuid::Uuid,
        ou_id: uuid::Uuid,
    },
    SetInheritance {
        ou_id: uuid::Uuid,
        block: bool,
    },
    SetEnforced {
        ou_id: uuid::Uuid,
        enforced: bool,
    },
}

// === Конфигурация ===

/// Конфигурация из `config.yaml`
#[derive(serde::Deserialize)]
struct Config {
    db_path: String,
    master_key_hex: String,
}

fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let file = std::fs::File::open("config.yaml")?;
    let config: Config = serde_yaml::from_reader(file)?;
    Ok(config)
}

fn decode_key(hex: &str) -> Result<[u8; 32], hex::FromHexError> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(hex, &mut key)?;
    Ok(key)
}

// === Обработчики ===

async fn handle_user(
    cmd: UserCommand,
    service: &DirectoryService,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        UserCommand::Create { username, email, display_name } => {
            use crate::models::{User, SecurityIdentifier, PasswordHash, PasswordAlgorithm};
            let user = User {
                id: uuid::Uuid::new_v4(),
                sid: SecurityIdentifier::new_nt_authority(1001),
                username,
                user_principal_name: "placeholder@corp.acme.com".to_string(),
                email,
                display_name,
                given_name: None,
                surname: None,
                password_hash: PasswordHash {
                    hash: "default".to_string(),
                    algorithm: PasswordAlgorithm::Bcrypt,
                    salt: vec![],
                },
                password_expires: None,
                last_password_change: chrono::Utc::now(),
                lockout_until: None,
                failed_logins: 0,
                enabled: true,
                mfa_enabled: false,
                mfa_methods: vec![],
                domains: vec![],
                groups: vec![],
                organizational_unit: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                last_login: None,
                profile_path: None,
                script_path: None,
                meta: std::collections::HashMap::new(),
                primary_group_id: Some(513),
            };
            service.create_user(&user).await?;
            println!("✅ Пользователь создан: {}", user.username);
        }
        UserCommand::Get { username } => {
            if let Some(user) = service.find_user_by_username(&username).await? {
                println!("{:#?}", user);
            } else {
                eprintln!("❌ Пользователь не найден");
            }
        }
        UserCommand::List { json } => {
            let users = service.get_all_users().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&users)?);
            } else {
                for user in users {
                    println!("{} | {}", user.username, user.id);
                }
            }
        }
        UserCommand::Delete { username } => {
            if let Some(user) = service.find_user_by_username(&username).await? {
                service.delete_user(user.id).await?;
                println!("✅ Пользователь удалён: {}", username);
            } else {
                eprintln!("❌ Пользователь не найден");
            }
        }
    }
    Ok(())
}

async fn handle_group(
    cmd: GroupCommand,
    service: &DirectoryService,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        GroupCommand::Create { name, sam_account_name } => {
            use crate::models::{Group, GroupTypeFlags, GroupScope};
            let sam = sam_account_name.unwrap_or_else(|| name.to_uppercase());
            let group = Group::new(name, sam, uuid::Uuid::nil(), GroupTypeFlags::SECURITY, GroupScope::Global);
            service.create_group(&group).await?;
            println!("✅ Группа создана: {}", group.sam_account_name);
        }
        GroupCommand::Get { sam } => {
            if let Some(group) = service.find_group_by_sam_account_name(&sam).await? {
                println!("{:#?}", group);
            } else {
                eprintln!("❌ Группа не найдена");
            }
        }
        GroupCommand::AddMember { sam, user_id } => {
            if let Some(group) = service.find_group_by_sam_account_name(&sam).await? {
                service.add_member_to_group(group.id, user_id).await?;
                println!("✅ Участник добавлен в группу");
            } else {
                eprintln!("❌ Группа не найдена");
            }
        }
        GroupCommand::RemoveMember { sam, user_id } => {
            if let Some(group) = service.find_group_by_sam_account_name(&sam).await? {
                service.remove_member_from_group(group.id, user_id).await?;
                println!("✅ Участник удалён из группы");
            } else {
                eprintln!("❌ Группа не найдена");
            }
        }
        GroupCommand::List { json } => {
            let groups = service.get_all_groups().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&groups)?);
            } else {
                for group in groups {
                    println!("{} ({}) — {} участников", group.name, group.sam_account_name, group.members.len());
                }
            }
        }
    }
    Ok(())
}

async fn handle_ou(
    cmd: OuCommand,
    service: &DirectoryService,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        OuCommand::Create { name, parent } => {
            let dn = crate::directory_service::DirectoryService::generate_ou_dn(&name, parent.as_deref());
            let ou = crate::models::OrganizationalUnit::new(name, dn, None);
            service.create_ou(&ou).await?;
            println!("✅ OU создана: DN={}", ou.dn);
        }
        OuCommand::List => {
            let ous = service.get_all_ous().await?;
            for ou in ous {
                println!("OU={}, DN={}", ou.name, ou.dn);
            }
        }
    }
    Ok(())
}

async fn handle_gpo(
    cmd: GpoCommand,
    service: &DirectoryService,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        GpoCommand::Create {
            name,
            display_name,
            description,
            linked_to,
            enforced,
            enabled,
        } => {
            use crate::models::policy::{GroupPolicy, PolicyType, PolicyTarget};

            let gpo = GroupPolicy {
                id: uuid::Uuid::new_v4(),
                name,
                display_name,
                description,
                linked_to,
                enforced,
                security_filtering: vec![],
                order: 0,
                version: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                enabled,
                policy_type: PolicyType::Custom("Custom".to_string()),
                target: PolicyTarget::All,
                settings: std::collections::HashMap::new(),
                wmi_filter: None,
            };

            service.create_gpo(&gpo).await?;
            println!("✅ GPO создана: ID={}", gpo.id);
        }
        GpoCommand::List { json } => {
            let gpos = service.get_all_gpos().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&gpos)?);
            } else {
                for gpo in &gpos {
                    println!(
                        "GPO(id={}, name={}, enabled={})",
                        gpo.id,
                        gpo.name,
                        gpo.enabled
                    );
                }
            }
        }
        GpoCommand::Link { gpo_id, ou_id } => {
            service.link_gpo_to_ou(gpo_id, ou_id).await?;
            println!("✅ GPO привязана к OU");
        }
        GpoCommand::Unlink { gpo_id, ou_id } => {
            service.unlink_gpo_from_ou(gpo_id, ou_id).await?;
            println!("✅ GPO отвязана от OU");
        }
        GpoCommand::SetInheritance { ou_id, block } => {
            service.set_block_inheritance(ou_id, block).await?;
            println!("✅ Наследование GPO {}: {}", if block { "заблокировано" } else { "разрешено" }, ou_id);
        }
        GpoCommand::SetEnforced { ou_id, enforced } => {
            service.set_gpo_enforced(ou_id, enforced).await?;
            println!("✅ GPO принудительно применяемая: {} для OU {}", enforced, ou_id);
        }
    }
    Ok(())
}