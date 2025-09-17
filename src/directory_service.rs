// src/directory_service.rs

use crate::raddb::RadDB;
use crate::models::*;
use bincode;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::Utc;
use std::fs::OpenOptions;
use std::io::Write;

/// Ошибки каталога
#[derive(Debug)]
pub enum DirectoryError {
    DbError(crate::raddb::RadDbError),
    Serialization(String),
    NotFound(String),
    AlreadyExists(String),
    InvalidInput(String),
}

impl From<crate::raddb::RadDbError> for DirectoryError {
    fn from(e: crate::raddb::RadDbError) -> Self {
        DirectoryError::DbError(e)
    }
}

impl From<&str> for DirectoryError {
    fn from(s: &str) -> Self {
        DirectoryError::InvalidInput(s.to_string())
    }
}

impl From<String> for DirectoryError {
    fn from(s: String) -> Self {
        DirectoryError::InvalidInput(s)
    }
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryError::DbError(e) => write!(f, "DB error: {}", e),
            DirectoryError::Serialization(e) => write!(f, "Serialization error: {}", e),
            DirectoryError::NotFound(e) => write!(f, "Not found: {}", e),
            DirectoryError::AlreadyExists(e) => write!(f, "Already exists: {}", e),
            DirectoryError::InvalidInput(e) => write!(f, "Invalid input: {}", e),
        }
    }
}

impl std::error::Error for DirectoryError {}

/// Сервис каталога
pub struct DirectoryService {
    db: Arc<RwLock<RadDB>>,
    log_file: std::sync::Mutex<std::fs::File>,
}

#[allow(dead_code)]
impl DirectoryService {
    /// Открыть сервис с путём к базе и мастер-ключом
    pub fn open<P: AsRef<str>>(path: P, key: &[u8; 32]) -> Result<Self, DirectoryError> {
        let db = RadDB::open(path.as_ref(), key)?;
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("mextdomen.log")
            .map_err(|e| DirectoryError::InvalidInput(format!("Failed to open log file: {}", e)))?;

        Ok(Self {
            db: Arc::new(RwLock::new(db)),
            log_file: std::sync::Mutex::new(log_file),
        })
    }

    /// Сохранить объект в базу
    async fn store<T: serde::Serialize>(&self, key: String, value: &T) -> Result<(), DirectoryError> {
        let data = bincode::serialize(value)
            .map_err(|e| DirectoryError::Serialization(e.to_string()))?;
        let db = self.db.write().await;
        db.set(key, data)?;
        Ok(())
    }

    /// Загрузить объект из базы
    async fn load<T: for<'de> serde::Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, DirectoryError> {
        let db = self.db.read().await;
        if let Some(data) = db.get(key) {
            let obj = bincode::deserialize(&data[..])
                .map_err(|e| DirectoryError::Serialization(e.to_string()))?;
            Ok(Some(obj))
        } else {
            Ok(None)
        }
    }

    /// Логирование действий в файл
    async fn log_action(&self, action: &str, details: &str, user_id: Option<Uuid>) -> Result<(), DirectoryError> {
        let log_entry = format!(
            "{} | ACTION: {} | DETAILS: {} | USER: {:?}\n",
            Utc::now().to_rfc3339(),
            action,
            details,
            user_id
        );

        let mut file = self.log_file.lock().map_err(|_| DirectoryError::InvalidInput("Log file lock poisoned".to_string()))?;
        file.write_all(log_entry.as_bytes())
            .map_err(|e| DirectoryError::InvalidInput(e.to_string()))?;
        Ok(())
    }

    // ================= USERS =================

    pub async fn create_user(&self, user: &User) -> Result<(), DirectoryError> {
        if let Some(existing) = self.find_user_by_username(&user.username).await? {
            if existing.id != user.id {
                return Err(DirectoryError::AlreadyExists(format!(
                    "User with username {} already exists",
                    user.username
                )));
            }
        }

        if let Some(email) = &user.email {
            if let Some(existing) = self.find_user_by_email(email).await? {
                if existing.id != user.id {
                    return Err(DirectoryError::AlreadyExists(format!(
                        "User with email {} already exists",
                        email
                    )));
                }
            }
        }

        let key = format!("user:{}", user.id);
        self.store(key, user).await?;

        self.store(format!("username_index:{}", user.username), &user.id).await?;
        if let Some(email) = &user.email {
            self.store(format!("email_index:{}", email), &user.id).await?;
        }

        let all_users: Vec<Uuid> = self.load::<Vec<Uuid>>("all_users_index").await?.unwrap_or_default();
        if !all_users.contains(&user.id) {
            let mut updated = all_users;
            updated.push(user.id);
            self.store("all_users_index".to_string(), &updated).await?;
        }

        self.log_action("create_user", &format!("username:{}", user.username), Some(user.id)).await?;
        Ok(())
    }

    pub async fn get_user(&self, id: Uuid) -> Result<Option<User>, DirectoryError> {
        let key = format!("user:{}", id);
        self.load(&key).await
    }

    pub async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, DirectoryError> {
        let index_key = format!("username_index:{}", username);
        let user_id: Option<Uuid> = self.load(&index_key).await?;
        if let Some(id) = user_id {
            self.get_user(id).await
        } else {
            Ok(None)
        }
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, DirectoryError> {
        let index_key = format!("email_index:{}", email);
        let user_id: Option<Uuid> = self.load(&index_key).await?;
        if let Some(id) = user_id {
            self.get_user(id).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_all_users(&self) -> Result<Vec<User>, DirectoryError> {
        let ids: Vec<Uuid> = self.load::<Vec<Uuid>>("all_users_index").await?.unwrap_or_default();
        let mut users = Vec::new();
        for id in ids {
            if let Some(user) = self.get_user(id).await? {
                users.push(user);
            }
        }
        Ok(users)
    }

    pub async fn delete_user(&self, user_id: Uuid) -> Result<(), DirectoryError> {
        let user = self.get_user(user_id).await?.ok_or_else(|| DirectoryError::NotFound("User not found".to_string()))?;

        for group in self.find_groups_by_member(user_id).await? {
            self.remove_member_from_group(group.id, user_id).await?;
        }

        let username_index_key = format!("username_index:{}", user.username);
        let email_index_key = user.email.clone().map(|e| format!("email_index:{}", e));

        let all_users: Vec<Uuid> = self.load::<Vec<Uuid>>("all_users_index").await?.unwrap_or_default();
        let updated_users: Vec<Uuid> = all_users.into_iter().filter(|id| *id != user_id).collect();
        self.store("all_users_index".to_string(), &updated_users).await?;

        let key = format!("user:{}", user_id);
        let db = self.db.write().await;
        db.remove(&key);
        db.remove(&username_index_key);
        if let Some(email_key) = email_index_key {
            db.remove(&email_key);
        }
        drop(db);

        self.log_action("delete_user", &format!("username:{}", user.username), Some(user_id)).await?;
        Ok(())
    }

    pub async fn rename_user(&self, user_id: Uuid, new_username: Option<String>, new_display_name: Option<String>) -> Result<(), DirectoryError> {
        let mut user = self.get_user(user_id).await?.ok_or_else(|| DirectoryError::NotFound("User not found".to_string()))?;

        if let Some(username) = new_username {
            if let Some(existing) = self.find_user_by_username(&username).await? {
                if existing.id != user_id {
                    return Err(DirectoryError::AlreadyExists(format!("Username '{}' already taken", username)));
                }
            }
            let old_key = format!("username_index:{}", user.username);
            let db = self.db.write().await;
            db.remove(&old_key);
            drop(db);

            self.store(format!("username_index:{}", username), &user_id).await?;
            user.username = username;
        }

        if let Some(display_name) = new_display_name {
            user.display_name = Some(display_name);
        }

        user.updated_at = Utc::now();
        self.update_user(&user).await?;
        self.log_action("rename_user", &format!("user_id:{}", user_id), Some(user_id)).await?;
        Ok(())
    }

    pub async fn update_user(&self, user: &User) -> Result<(), DirectoryError> {
        self.create_user(user).await
    }

    // ================= GROUPS =================

    pub async fn create_group(&self, group: &Group) -> Result<(), DirectoryError> {
        if let Some(existing) = self.find_group_by_sam_account_name(&group.sam_account_name).await? {
            if existing.id != group.id {
                return Err(DirectoryError::AlreadyExists(format!(
                    "Group {} already exists",
                    group.sam_account_name
                )));
            }
        }

        let key = format!("group:{}", group.id);
        self.store(key, group).await?;
        self.store(format!("sam_account_name_index:{}", group.sam_account_name.to_uppercase()), &group.id).await?;

        for member_id in &group.members {
            self.add_member_to_index(*member_id, group.id).await?;
        }

        let all_groups: Vec<Uuid> = self.load::<Vec<Uuid>>("all_groups_index").await?.unwrap_or_default();
        if !all_groups.contains(&group.id) {
            let mut updated = all_groups;
            updated.push(group.id);
            self.store("all_groups_index".to_string(), &updated).await?;
        }

        self.log_action("create_group", &format!("sam_account_name:{}", group.sam_account_name), None).await?;
        Ok(())
    }

    pub async fn get_group(&self, id: Uuid) -> Result<Option<Group>, DirectoryError> {
        let key = format!("group:{}", id);
        self.load(&key).await
    }

    pub async fn find_group_by_sam_account_name(&self, sam_account_name: &str) -> Result<Option<Group>, DirectoryError> {
        let key = format!("sam_account_name_index:{}", sam_account_name.to_uppercase());
        let group_id: Option<Uuid> = self.load(&key).await?;
        if let Some(id) = group_id {
            self.get_group(id).await
        } else {
            Ok(None)
        }
    }

    pub async fn add_member_to_group(&self, group_id: Uuid, user_id: Uuid) -> Result<(), DirectoryError> {
        let mut group = self.get_group(group_id).await?.ok_or_else(|| DirectoryError::NotFound("Group not found".to_string()))?;
        if !group.members.contains(&user_id) {
            group.members.push(user_id);
            self.store(format!("group:{}", group.id), &group).await?;
            self.add_member_to_index(user_id, group.id).await?;
            self.log_action("add_member_to_group", &format!("group:{} user:{}", group.sam_account_name, user_id), Some(user_id)).await?;
        }
        Ok(())
    }

    pub async fn remove_member_from_group(&self, group_id: Uuid, user_id: Uuid) -> Result<(), DirectoryError> {
        let mut group = self.get_group(group_id).await?.ok_or_else(|| DirectoryError::NotFound("Group not found".to_string()))?;
        if group.members.contains(&user_id) {
            group.members.retain(|id| id != &user_id);
            self.store(format!("group:{}", group.id), &group).await?;
            self.remove_member_from_index(user_id, group.id).await?;
            self.log_action("remove_member_from_group", &format!("group:{} user:{}", group.sam_account_name, user_id), Some(user_id)).await?;
        }
        Ok(())
    }

    pub async fn delete_group(&self, group_id: Uuid) -> Result<(), DirectoryError> {
        let group = self.get_group(group_id).await?.ok_or_else(|| DirectoryError::NotFound("Group not found".to_string()))?;
        let sam_key = format!("sam_account_name_index:{}", group.sam_account_name.to_uppercase());

        let all_groups: Vec<Uuid> = self.load::<Vec<Uuid>>("all_groups_index").await?.unwrap_or_default();
        let updated_groups: Vec<Uuid> = all_groups.into_iter().filter(|id| *id != group_id).collect();
        self.store("all_groups_index".to_string(), &updated_groups).await?;

        for user_id in &group.members {
            self.remove_member_from_index(*user_id, group.id).await?;
        }

        let db = self.db.write().await;
        db.remove(&format!("group:{}", group_id));
        db.remove(&sam_key);
        drop(db);

        self.log_action("delete_group", &format!("group:{}", group.sam_account_name), None).await?;
        Ok(())
    }

    pub async fn find_groups_by_member(&self, user_id: Uuid) -> Result<Vec<Group>, DirectoryError> {
        let group_ids: HashSet<Uuid> = self.load::<HashSet<Uuid>>(&format!("member_index:{}", user_id)).await?.unwrap_or_else(|| HashSet::new());
        let mut groups = Vec::new();
        for id in group_ids {
            if let Some(group) = self.get_group(id).await? {
                groups.push(group);
            }
        }
        Ok(groups)
    }

    pub async fn get_all_groups(&self) -> Result<Vec<Group>, DirectoryError> {
        let ids: Vec<Uuid> = self.load::<Vec<Uuid>>("all_groups_index").await?.unwrap_or_default();
        let mut groups = Vec::new();
        for id in ids {
            if let Some(group) = self.get_group(id).await? {
                groups.push(group);
            }
        }
        Ok(groups)
    }

    async fn add_member_to_index(&self, user_id: Uuid, group_id: Uuid) -> Result<(), DirectoryError> {
        let key = format!("member_index:{}", user_id);
        let mut group_ids: HashSet<Uuid> = self.load::<HashSet<Uuid>>(&key).await?.unwrap_or_else(|| HashSet::new());
        group_ids.insert(group_id);
        self.store(key, &group_ids).await
    }

    async fn remove_member_from_index(&self, user_id: Uuid, group_id: Uuid) -> Result<(), DirectoryError> {
        let key = format!("member_index:{}", user_id);
        let mut group_ids: HashSet<Uuid> = self.load::<HashSet<Uuid>>(&key).await?.unwrap_or_else(|| HashSet::new());
        group_ids.remove(&group_id);
        self.store(key, &group_ids).await
    }

    // ================= ORGANIZATIONAL UNITS (OU) =================

    pub async fn create_ou(&self, ou: &OrganizationalUnit) -> Result<(), DirectoryError> {
        self.store(format!("ou:{}", ou.id), ou).await?;
        self.store(format!("dn_index:{}", ou.dn), &ou.id).await?;

        let all_ous: Vec<Uuid> = self.load::<Vec<Uuid>>("all_ous_index").await?.unwrap_or_default();
        if !all_ous.contains(&ou.id) {
            let mut updated = all_ous;
            updated.push(ou.id);
            self.store("all_ous_index".to_string(), &updated).await?;
        }

        self.log_action("create_ou", &format!("ou:{}", ou.dn), None).await?;
        Ok(())
    }

    pub async fn get_ou(&self, id: Uuid) -> Result<Option<OrganizationalUnit>, DirectoryError> {
        self.load(&format!("ou:{}", id)).await
    }

    pub async fn find_ou_by_dn(&self, dn: &str) -> Result<Option<OrganizationalUnit>, DirectoryError> {
        if let Some(ou_id) = self.load::<Uuid>(&format!("dn_index:{}", dn)).await? {
            self.get_ou(ou_id).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_all_ous(&self) -> Result<Vec<OrganizationalUnit>, DirectoryError> {
        let ids: Vec<Uuid> = self.load::<Vec<Uuid>>("all_ous_index").await?.unwrap_or_default();
        let mut ous = Vec::new();
        for id in ids {
            if let Some(ou) = self.get_ou(id).await? {
                ous.push(ou);
            }
        }
        Ok(ous)
    }

    pub async fn delete_ou(&self, ou_id: Uuid) -> Result<(), DirectoryError> {
        let ou = self.get_ou(ou_id).await?.ok_or_else(|| DirectoryError::NotFound("OU not found".to_string()))?;

        let all_ous: Vec<Uuid> = self.load::<Vec<Uuid>>("all_ous_index").await?.unwrap_or_default();
        let updated_ous: Vec<Uuid> = all_ous.into_iter().filter(|id| *id != ou_id).collect();
        self.store("all_ous_index".to_string(), &updated_ous).await?;

        let db = self.db.write().await;
        db.remove(&format!("ou:{}", ou_id));
        db.remove(&format!("dn_index:{}", ou.dn));
        drop(db);

        self.log_action("delete_ou", &format!("ou:{}", ou.dn), None).await?;
        Ok(())
    }

    // ================= GPO =================

    pub async fn create_gpo(&self, gpo: &GroupPolicy) -> Result<(), DirectoryError> {
        gpo.validate().map_err(|e| DirectoryError::InvalidInput(e))?;

        self.store(format!("gpo:{}", gpo.id), gpo).await?;
        for target_id in &gpo.linked_to {
            let key = format!("gpo_link:{}", target_id);
            let mut gpo_ids: HashSet<Uuid> = self.load::<HashSet<Uuid>>(&key).await?.unwrap_or_else(|| HashSet::new());
            gpo_ids.insert(gpo.id);
            self.store(key, &gpo_ids).await?;
        }

        let all_gpos: Vec<Uuid> = self.load::<Vec<Uuid>>("all_gpos_index").await?.unwrap_or_default();
        if !all_gpos.contains(&gpo.id) {
            let mut updated = all_gpos;
            updated.push(gpo.id);
            self.store("all_gpos_index".to_string(), &updated).await?;
        }

        self.log_action("create_gpo", &format!("gpo:{}", gpo.id), None).await?;
        Ok(())
    }

    pub async fn get_gpo(&self, id: Uuid) -> Result<Option<GroupPolicy>, DirectoryError> {
        self.load(&format!("gpo:{}", id)).await
    }

    pub async fn get_all_gpos(&self) -> Result<Vec<GroupPolicy>, DirectoryError> {
        let ids: Vec<Uuid> = self.load::<Vec<Uuid>>("all_gpos_index").await?.unwrap_or_default();
        let mut gpos = Vec::new();
        for id in ids {
            if let Some(gpo) = self.get_gpo(id).await? {
                gpos.push(gpo);
            }
        }
        Ok(gpos)
    }

    pub async fn find_gpos_for_ou(&self, ou_id: Uuid) -> Result<Vec<GroupPolicy>, DirectoryError> {
        let ids: HashSet<Uuid> = self.load::<HashSet<Uuid>>(&format!("gpo_link:{}", ou_id)).await?.unwrap_or_else(|| HashSet::new());
        let mut gpos = Vec::new();
        for id in ids {
            if let Some(gpo) = self.get_gpo(id).await? {
                gpos.push(gpo);
            }
        }
        Ok(gpos)
    }

    pub async fn find_gpos_for_domain(&self, domain_id: Uuid) -> Result<Vec<GroupPolicy>, DirectoryError> {
        let ids: HashSet<Uuid> = self.load::<HashSet<Uuid>>(&format!("gpo_link:{}", domain_id)).await?.unwrap_or_else(|| HashSet::new());
        let mut gpos = Vec::new();
        for id in ids {
            if let Some(gpo) = self.get_gpo(id).await? {
                gpos.push(gpo);
            }
        }
        Ok(gpos)
    }

    pub async fn link_gpo_to_ou(&self, gpo_id: Uuid, ou_id: Uuid) -> Result<(), DirectoryError> {
        let _gpo = self.get_gpo(gpo_id).await?.ok_or_else(|| DirectoryError::NotFound("GPO not found".to_string()))?;
        let mut ou = self.get_ou(ou_id).await?.ok_or_else(|| DirectoryError::NotFound("OU not found".to_string()))?;

        if !ou.linked_gpos.contains(&gpo_id) {
            ou.linked_gpos.push(gpo_id);
            ou.enforced = true;
            ou.update_gplink();
            ou.updated_at = Utc::now();

            self.store(format!("ou:{}", ou.id), &ou).await?;

            let index_key = format!("gpo_link:{}", ou_id);
            let mut gpo_ids: HashSet<Uuid> = self.load::<HashSet<Uuid>>(&index_key).await?.unwrap_or_else(|| HashSet::new());
            gpo_ids.insert(gpo_id);
            self.store(index_key, &gpo_ids).await?;
        }

        self.log_action("link_gpo_to_ou", &format!("gpo:{} ou:{}", gpo_id, ou_id), None).await?;
        Ok(())
    }

    pub async fn unlink_gpo_from_ou(&self, gpo_id: Uuid, ou_id: Uuid) -> Result<(), DirectoryError> {
        let mut ou = self.get_ou(ou_id).await?.ok_or_else(|| DirectoryError::NotFound("OU not found".to_string()))?;

        if ou.linked_gpos.contains(&gpo_id) {
            ou.linked_gpos.retain(|id| id != &gpo_id);
            ou.update_gplink();
            ou.updated_at = Utc::now();

            self.store(format!("ou:{}", ou.id), &ou).await?;

            let index_key = format!("gpo_link:{}", ou_id);
            let mut gpo_ids: HashSet<Uuid> = self.load::<HashSet<Uuid>>(&index_key).await?.unwrap_or_else(|| HashSet::new());
            gpo_ids.remove(&gpo_id);
            self.store(index_key, &gpo_ids).await?;
        }

        self.log_action("unlink_gpo_from_ou", &format!("gpo:{} ou:{}", gpo_id, ou_id), None).await?;
        Ok(())
    }

    pub async fn set_block_inheritance(&self, ou_id: Uuid, block: bool) -> Result<(), DirectoryError> {
        let mut ou = self.get_ou(ou_id).await?.ok_or_else(|| DirectoryError::NotFound("OU not found".to_string()))?;

        ou.block_inheritance = block;
        ou.update_gpoptions();
        ou.updated_at = Utc::now();

        self.store(format!("ou:{}", ou.id), &ou).await?;

        self.log_action("set_block_inheritance", &format!("ou:{} block:{}", ou_id, block), None).await?;
        Ok(())
    }

    pub async fn set_gpo_enforced(&self, ou_id: Uuid, enforced: bool) -> Result<(), DirectoryError> {
        let mut ou = self.get_ou(ou_id).await?.ok_or_else(|| DirectoryError::NotFound("OU not found".to_string()))?;

        ou.enforced = enforced;
        ou.update_gplink();
        ou.updated_at = Utc::now();

        self.store(format!("ou:{}", ou.id), &ou).await?;

        self.log_action("set_gpo_enforced", &format!("ou:{} enforced:{}", ou_id, enforced), None).await?;
        Ok(())
    }

    pub async fn is_gpo_applicable_to(
        &self,
        gpo: &GroupPolicy,
        principal_sid: &SecurityIdentifier,
    ) -> Result<bool, DirectoryError> {
        if gpo.security_filtering.is_empty() {
            return Ok(true);
        }

        for filter in &gpo.security_filtering {
            if let SidOrId::Sid(sid) = filter {
                if sid == principal_sid {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    pub async fn get_effective_gpos_for_ou(
        &self,
        ou_id: Uuid,
    ) -> Result<Vec<GroupPolicy>, DirectoryError> {
        let mut all_gpos = Vec::new();
        let mut visited_ou_ids = HashSet::new();
        let mut current_ou_id = Some(ou_id);

        while let Some(ou_id) = current_ou_id {
            if visited_ou_ids.contains(&ou_id) {
                return Err(DirectoryError::InvalidInput("Circular OU hierarchy detected".to_string()));
            }
            visited_ou_ids.insert(ou_id);

            let ou = self.get_ou(ou_id).await?.ok_or_else(|| DirectoryError::NotFound("OU not found".to_string()))?;

            if !all_gpos.is_empty() && ou.block_inheritance {
                let gpos = self.find_gpos_for_ou(ou_id).await?;
                let enforced: Vec<_> = gpos.into_iter().filter(|g| g.enforced).collect();
                all_gpos.extend(enforced);
                break;
            }

            let mut gpos = self.find_gpos_for_ou(ou_id).await?;
            gpos.sort_by(|a, b| b.enforced.cmp(&a.enforced).then_with(|| a.order.cmp(&b.order)));
            all_gpos.extend(gpos);

            current_ou_id = ou.parent;
        }

        let mut seen = HashSet::new();
        let mut unique = Vec::new();
        for gpo in all_gpos {
            if seen.insert(gpo.id) {
                unique.push(gpo);
            }
        }

        Ok(unique)
    }

    pub async fn get_effective_gpos_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<GroupPolicy>, DirectoryError> {
        let user = self.get_user(user_id).await?.ok_or_else(|| DirectoryError::NotFound("User not found".to_string()))?;

        let mut all_gpos = Vec::new();

        if let Some(ou_id) = user.organizational_unit {
            let gpos = self.get_effective_gpos_for_ou(ou_id).await?;
            all_gpos.extend(gpos);
        }

        let groups = self.find_groups_by_member(user_id).await?;
        for _group in groups {}

        if let Some(domain_id) = user.domains.get(0) {
            let gpos = self.find_gpos_for_domain(*domain_id).await?;
            all_gpos.extend(gpos);
        }

        let mut seen = HashSet::new();
        let mut unique = Vec::new();
        for gpo in all_gpos {
            if seen.insert(gpo.id) {
                unique.push(gpo);
            }
        }

        unique.sort_by(|a, b| b.enforced.cmp(&a.enforced).then_with(|| a.order.cmp(&b.order)));

        Ok(unique)
    }

    pub async fn find_group_by_rid(&self, rid: u32) -> Result<Option<Group>, DirectoryError> {
        let all_group_ids: Vec<Uuid> = self.load::<Vec<Uuid>>("all_groups_index").await?.unwrap_or_default();
        for group_id in all_group_ids {
            if let Some(group) = self.get_group(group_id).await? {
                if group.get_rid() == rid {
                    return Ok(Some(group));
                }
            }
        }
        Ok(None)
    }

    pub async fn get_token_groups(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SecurityIdentifier>, DirectoryError> {
        let mut tokens = Vec::new();

        let direct_groups = self.find_groups_by_member(user_id).await?;
        for group in &direct_groups {
            tokens.push(group.sid.clone());
        }

        if let Some(user) = self.get_user(user_id).await? {
            if let Some(primary_rid) = user.primary_group_id {
                if let Some(group) = self.find_group_by_rid(primary_rid).await? {
                    let token_sid = group.get_primary_group_token();
                    tokens.push(token_sid);
                }
            }
        }

        Ok(tokens)
    }

    pub fn generate_user_dn(user: &User, domain: &Domain) -> String {
        format!("CN={},{}", user.username, Self::domain_dn(domain))
    }

    pub fn generate_ou_dn(name: &str, parent: Option<&str>) -> String {
        let mut dn = format!("OU={}", name);
        if let Some(parent_dn) = parent {
            dn.push_str(",");
            dn.push_str(parent_dn);
        }
        dn
    }

    pub fn domain_dn(domain: &Domain) -> String {
        domain.name
            .split('.')
            .map(|part| format!("DC={}", part))
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl Drop for DirectoryService {
    fn drop(&mut self) {
        // Файл закроется автоматически
    }
}