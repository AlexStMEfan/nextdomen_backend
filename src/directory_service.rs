// src/directory_service.rs

use crate::raddb::RadDB;
use crate::models::*;
use bincode;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

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

// ✅ Добавлено: From<&str> и From<String>
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
}

#[allow(dead_code)]
impl DirectoryService {
    /// Открыть сервис с путём к базе и мастер-ключом
    pub fn open<P: AsRef<str>>(path: P, key: &[u8; 32]) -> Result<Self, DirectoryError> {
        let db = RadDB::open(path.as_ref(), key)?;
        Ok(Self {
            db: Arc::new(RwLock::new(db)),
        })
    }

    /// Сохранить объект в базу
    async fn store<T: serde::Serialize>(&self, key: String, value: &T) -> Result<(), DirectoryError> {
        let data = bincode::serialize(value)
            .map_err(|e| DirectoryError::Serialization(e.to_string()))?;
        let db = self.db.read().await;
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
            let obj = bincode::deserialize(&data)
                .map_err(|e| DirectoryError::Serialization(e.to_string()))?;
            Ok(Some(obj))
        } else {
            Ok(None)
        }
    }

    // === ORGANIZATION ===

    pub async fn create_organization(&self, org: &Organization) -> Result<(), DirectoryError> {
        let key = format!("org:{}", org.id);
        self.store(key, org).await
    }

    pub async fn get_organization(&self, id: Uuid) -> Result<Option<Organization>, DirectoryError> {
        let key = format!("org:{}", id);
        self.load(&key).await
    }

    // === DOMAIN ===

    pub async fn create_domain(&self, domain: &Domain) -> Result<(), DirectoryError> {
        let key = format!("domain:{}", domain.id);
        self.store(key, domain).await
    }

    pub async fn get_domain(&self, id: Uuid) -> Result<Option<Domain>, DirectoryError> {
        let key = format!("domain:{}", id);
        self.load(&key).await
    }

    // === USER ===

    pub async fn create_user(&self, user: &User) -> Result<(), DirectoryError> {
        // Проверка уникальности username
        if self.find_user_by_username(&user.username).await?.is_some() {
            return Err(DirectoryError::AlreadyExists(format!(
                "User with username {} already exists",
                user.username
            )));
        }

        // Проверка уникальности email
        if let Some(email) = &user.email {
            if self.find_user_by_email(email).await?.is_some() {
                return Err(DirectoryError::AlreadyExists(format!(
                    "User with email {} already exists",
                    email
                )));
            }
        }

        let key = format!("user:{}", user.id);
        self.store(key, user).await?;

        // Индекс: username → user_id
        let username_index_key = format!("username_index:{}", user.username);
        self.store(username_index_key, &user.id).await?;

        // Индекс: email → user_id
        if let Some(email) = &user.email {
            let email_index_key = format!("email_index:{}", email);
            self.store(email_index_key, &user.id).await?;
        }

        // Добавляем в общий индекс пользователей
        let mut all_users: Vec<Uuid> = self.load("all_users_index").await?.unwrap_or_default();
        all_users.push(user.id);
        self.store("all_users_index".to_string(), &all_users).await?;

        Ok(())
    }

    pub async fn get_user(&self, id: Uuid) -> Result<Option<User>, DirectoryError> {
        let key = format!("user:{}", id);
        self.load(&key).await
    }

    pub async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, DirectoryError> {
        let index_key = format!("username_index:{}", username);
        let user_id: Option<Uuid> = self.load(&index_key).await?;
        match user_id {
            Some(id) => self.get_user(id).await,
            None => Ok(None),
        }
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, DirectoryError> {
        let index_key = format!("email_index:{}", email);
        let user_id: Option<Uuid> = self.load(&index_key).await?;
        match user_id {
            Some(id) => self.get_user(id).await,
            None => Ok(None),
        }
    }

    /// Получить всех пользователей
    pub async fn get_all_users(&self) -> Result<Vec<User>, DirectoryError> {
        let ids: Vec<Uuid> = self.load("all_users_index").await?.unwrap_or_default();
        let mut users = Vec::new();
        for id in ids {
            if let Some(user) = self.get_user(id).await? {
                users.push(user);
            }
        }
        Ok(users)
    }

    /// Удалить пользователя
    pub async fn delete_user(&self, user_id: Uuid) -> Result<(), DirectoryError> {
        let user = self.get_user(user_id).await?.ok_or("User not found")?;

        // Удаляем из всех групп
        for group in self.find_groups_by_member(user_id).await? {
            self.remove_member_from_group(group.id, user_id).await?;
        }

        // Удаляем из индексов
        let username_index_key = format!("username_index:{}", user.username);
        let email_index_key = user.email.map(|e| format!("email_index:{}", e));

        // Удаляем из общего списка
        let mut all_users: Vec<Uuid> = self.load("all_users_index").await?.unwrap_or_default();
        all_users.retain(|id| *id != user_id);
        self.store("all_users_index".to_string(), &all_users).await?;

        // Удаляем сам объект
        let key = format!("user:{}", user_id);
        let db = self.db.read().await;
        db.remove(&key);

        // Удаляем индексы
        let db = self.db.read().await;
        db.remove(&username_index_key);
        if let Some(email_key) = email_index_key {
            db.remove(&email_key);
        }

        Ok(())
    }

    /// Переименовать пользователя
    pub async fn rename_user(&self, user_id: Uuid, new_username: Option<String>, new_display_name: Option<String>) -> Result<(), DirectoryError> {
        let mut user = self.get_user(user_id).await?.ok_or("User not found")?;

        // Обновляем username
        if let Some(username) = new_username {
            // Проверяем уникальность
            if self.find_user_by_username(&username).await?.map_or(false, |u| u.id != user_id) {
                return Err(DirectoryError::AlreadyExists(format!("Username '{}' already taken", username)));
            }

            // Удаляем старый индекс
            let old_username_key = format!("username_index:{}", user.username);
            let db = self.db.read().await;
            db.remove(&old_username_key);

            // Добавляем новый
            let new_username_key = format!("username_index:{}", username);
            self.store(new_username_key, &user_id).await?;

            user.username = username;
        }

        // Обновляем display_name
        if let Some(display_name) = new_display_name {
            user.display_name = Some(display_name);
        }

        user.updated_at = chrono::Utc::now();

        // Сохраняем
        let key = format!("user:{}", user_id);
        self.store(key, &user).await?;

        Ok(())
    }

    // === GROUP ===

    pub async fn create_group(&self, group: &Group) -> Result<(), DirectoryError> {
        // Проверка на дубли по sam_account_name
        if self.find_group_by_sam_account_name(&group.sam_account_name).await?.is_some() {
            return Err(DirectoryError::AlreadyExists(format!(
                "Group with sam_account_name {} already exists",
                group.sam_account_name
            )));
        }

        let key = format!("group:{}", group.id);
        self.store(key, group).await?;

        // Индекс: sam_account_name → group_id
        let sam_index_key = format!("sam_account_name_index:{}", group.sam_account_name.to_uppercase());
        self.store(sam_index_key, &group.id).await?;

        // Добавляем индекс для каждого участника
        for member_id in &group.members {
            self.add_member_to_index(*member_id, group.id).await?;
        }

        // Добавляем в общий индекс групп
        let mut all_groups: Vec<Uuid> = self.load("all_groups_index").await?.unwrap_or_default();
        all_groups.push(group.id);
        self.store("all_groups_index".to_string(), &all_groups).await?;

        Ok(())
    }

    pub async fn get_group(&self, id: Uuid) -> Result<Option<Group>, DirectoryError> {
        let key = format!("group:{}", id);
        self.load(&key).await
    }

    /// Найти группу по sam_account_name
    pub async fn find_group_by_sam_account_name(&self, sam_account_name: &str) -> Result<Option<Group>, DirectoryError> {
        let index_key = format!("sam_account_name_index:{}", sam_account_name.to_uppercase());
        let group_id: Option<Uuid> = self.load(&index_key).await?;
        match group_id {
            Some(id) => self.get_group(id).await,
            None => Ok(None),
        }
    }

    /// Добавить участника в группу + обновить индекс
    pub async fn add_member_to_group(&self, group_id: Uuid, user_id: Uuid) -> Result<(), DirectoryError> {
        let mut group = match self.get_group(group_id).await? {
            Some(g) => g,
            None => return Err(DirectoryError::NotFound("Group not found".to_string())),
        };

        if !group.members.contains(&user_id) {
            group.members.push(user_id);
            let key = format!("group:{}", group.id);
            self.store(key, &group).await?;

            // Обновить индекс member_index:user_id → [group_id]
            self.add_member_to_index(user_id, group_id).await?;
        }

        Ok(())
    }

    /// Удалить участника из группы + обновить индекс
    pub async fn remove_member_from_group(&self, group_id: Uuid, user_id: Uuid) -> Result<(), DirectoryError> {
        let mut group = match self.get_group(group_id).await? {
            Some(g) => g,
            None => return Err(DirectoryError::NotFound("Group not found".to_string())),
        };

        if group.members.contains(&user_id) {
            group.members.retain(|id| id != &user_id);
            let key = format!("group:{}", group.id);
            self.store(key, &group).await?;

            // Обновить индекс
            self.remove_member_from_index(user_id, group_id).await?;
        }

        Ok(())
    }

    /// Удалить группу
    pub async fn delete_group(&self, group_id: Uuid) -> Result<(), DirectoryError> {
        let group = self.get_group(group_id).await?.ok_or("Group not found")?;

        // Удаляем из индекса sam_account_name
        let sam_index_key = format!("sam_account_name_index:{}", group.sam_account_name.to_uppercase());
        let db = self.db.read().await;
        db.remove(&sam_index_key);

        // Удаляем из общего индекса групп
        let mut all_groups: Vec<Uuid> = self.load("all_groups_index").await?.unwrap_or_default();
        all_groups.retain(|id| *id != group_id);
        self.store("all_groups_index".to_string(), &all_groups).await?;

        // Удаляем из member_index каждого участника
        for user_id in &group.members {
            self.remove_member_from_index(*user_id, group_id).await?;
        }

        // Удаляем сам объект
        let key = format!("group:{}", group_id);
        let db = self.db.read().await;
        db.remove(&key);

        Ok(())
    }

    /// Найти все группы, в которых состоит пользователь
    pub async fn find_groups_by_member(&self, user_id: Uuid) -> Result<Vec<Group>, DirectoryError> {
        let group_ids: HashSet<Uuid> = self.load(&format!("member_index:{}", user_id)).await?
            .unwrap_or_else(HashSet::new);

        let mut groups = Vec::new();
        for group_id in group_ids {
            if let Some(_group) = self.get_group(group_id).await? {
                groups.push(_group);
            }
        }

        Ok(groups)
    }

    /// Получить всех групп
    pub async fn get_all_groups(&self) -> Result<Vec<Group>, DirectoryError> {
        let ids: Vec<Uuid> = self.load("all_groups_index").await?.unwrap_or_default();
        let mut groups = Vec::new();
        for id in ids {
            if let Some(group) = self.get_group(id).await? {
                groups.push(group);
            }
        }
        Ok(groups)
    }

    // === MEMBER INDEX ===

    /// Добавить ссылку: user_id → group_id в индекс
    async fn add_member_to_index(&self, user_id: Uuid, group_id: Uuid) -> Result<(), DirectoryError> {
        let key = format!("member_index:{}", user_id);
        let mut group_ids: HashSet<Uuid> = self.load(&key).await?.unwrap_or_else(HashSet::new);
        group_ids.insert(group_id);
        self.store(key, &group_ids).await
    }

    /// Удалить ссылку: user_id → group_id из индекса
    async fn remove_member_from_index(&self, user_id: Uuid, group_id: Uuid) -> Result<(), DirectoryError> {
        let key = format!("member_index:{}", user_id);
        let mut group_ids: HashSet<Uuid> = self.load(&key).await?.unwrap_or_else(HashSet::new);
        group_ids.remove(&group_id);
        self.store(key, &group_ids).await
    }

    // === ORGANIZATIONAL UNIT ===

    pub async fn create_ou(&self, ou: &OrganizationalUnit) -> Result<(), DirectoryError> {
        let key = format!("ou:{}", ou.id);
        self.store(key, ou).await?;

        // Индекс: DN → OU ID
        let dn_key = format!("dn_index:{}", ou.dn);
        self.store(dn_key, &ou.id).await?;

        // Добавляем в общий индекс OU
        let mut all_ous: Vec<Uuid> = self.load("all_ous_index").await?.unwrap_or_default();
        all_ous.push(ou.id);
        self.store("all_ous_index".to_string(), &all_ous).await?;

        Ok(())
    }

    pub async fn get_ou(&self, id: Uuid) -> Result<Option<OrganizationalUnit>, DirectoryError> {
        let key = format!("ou:{}", id);
        self.load(&key).await
    }

    pub async fn find_ou_by_dn(&self, dn: &str) -> Result<Option<OrganizationalUnit>, DirectoryError> {
        let index_key = format!("dn_index:{}", dn);
        let ou_id: Option<Uuid> = self.load(&index_key).await?;
        match ou_id {
            Some(id) => self.get_ou(id).await,
            None => Ok(None),
        }
    }

    /// Получить всех OU
    pub async fn get_all_ous(&self) -> Result<Vec<OrganizationalUnit>, DirectoryError> {
        let ids: Vec<Uuid> = self.load("all_ous_index").await?.unwrap_or_default();
        let mut ous = Vec::new();
        for id in ids {
            if let Some(ou) = self.get_ou(id).await? {
                ous.push(ou);
            }
        }
        Ok(ous)
    }

    /// Удалить OU
    pub async fn delete_ou(&self, ou_id: Uuid) -> Result<(), DirectoryError> {
        let ou = self.get_ou(ou_id).await?.ok_or("OU not found")?;

        // Удаляем из индекса DN
        let dn_key = format!("dn_index:{}", ou.dn);
        let db = self.db.read().await;
        db.remove(&dn_key);

        // Удаляем из общего индекса
        let mut all_ous: Vec<Uuid> = self.load("all_ous_index").await?.unwrap_or_default();
        all_ous.retain(|id| *id != ou_id);
        self.store("all_ous_index".to_string(), &all_ous).await?;

        // Удаляем сам объект
        let key = format!("ou:{}", ou_id);
        let db = self.db.read().await;
        db.remove(&key);

        Ok(())
    }

    // === GROUP POLICY (GPO) ===

    pub async fn create_gpo(&self, gpo: &GroupPolicy) -> Result<(), DirectoryError> {
        let key = format!("gpo:{}", gpo.id);
        self.store(key, gpo).await?;

        // Создаём индексы для каждого объекта, к которому привязан GPO
        for target_id in &gpo.linked_to {
            let index_key = format!("gpo_link:{}", target_id);
            let mut gpo_ids: HashSet<Uuid> = self.load(&index_key).await?.unwrap_or_else(HashSet::new);
            gpo_ids.insert(gpo.id);
            self.store(index_key, &gpo_ids).await?;
        }

        Ok(())
    }

    pub async fn get_gpo(&self, id: Uuid) -> Result<Option<GroupPolicy>, DirectoryError> {
        let key = format!("gpo:{}", id);
        self.load(&key).await
    }

    /// Найти все GPO, привязанные к OU
    pub async fn find_gpos_for_ou(&self, ou_id: Uuid) -> Result<Vec<GroupPolicy>, DirectoryError> {
        let gpo_ids: HashSet<Uuid> = self.load(&format!("gpo_link:{}", ou_id)).await?
            .unwrap_or_else(HashSet::new);

        let mut gpos = Vec::new();
        for gpo_id in gpo_ids {
            if let Some(gpo) = self.get_gpo(gpo_id).await? {
                gpos.push(gpo);
            }
        }

        Ok(gpos)
    }

    /// Найти все GPO, привязанные к домену
    pub async fn find_gpos_for_domain(&self, domain_id: Uuid) -> Result<Vec<GroupPolicy>, DirectoryError> {
        let gpo_ids: HashSet<Uuid> = self.load(&format!("gpo_link:{}", domain_id)).await?
            .unwrap_or_else(HashSet::new);

        let mut gpos = Vec::new();
        for gpo_id in gpo_ids {
            if let Some(gpo) = self.get_gpo(gpo_id).await? {
                gpos.push(gpo);
            }
        }

        Ok(gpos)
    }

    /// Привязать GPO к OU
    pub async fn link_gpo_to_ou(&self, gpo_id: Uuid, ou_id: Uuid) -> Result<(), DirectoryError> {
        let mut ou = match self.get_ou(ou_id).await? {
            Some(ou) => ou,
            None => return Err(DirectoryError::NotFound("OU not found".to_string())),
        };

        if !ou.linked_gpos.contains(&gpo_id) {
            ou.linked_gpos.push(gpo_id);
            ou.enforced = true;
            ou.update_gplink();
            ou.updated_at = chrono::Utc::now();

            let key = format!("ou:{}", ou.id);
            self.store(key, &ou).await?;

            // Обновить индекс GPO
            let index_key = format!("gpo_link:{}", ou_id);
            let mut gpo_ids: HashSet<Uuid> = self.load(&index_key).await?.unwrap_or_else(HashSet::new);
            gpo_ids.insert(gpo_id);
            self.store(index_key, &gpo_ids).await?;
        }

        Ok(())
    }

    /// Отвязать GPO от OU
    pub async fn unlink_gpo_from_ou(&self, gpo_id: Uuid, ou_id: Uuid) -> Result<(), DirectoryError> {
        let mut ou = match self.get_ou(ou_id).await? {
            Some(ou) => ou,
            None => return Err(DirectoryError::NotFound("OU not found".to_string())),
        };

        if ou.linked_gpos.contains(&gpo_id) {
            ou.linked_gpos.retain(|id| id != &gpo_id);
            ou.update_gplink();
            ou.updated_at = chrono::Utc::now();

            let key = format!("ou:{}", ou.id);
            self.store(key, &ou).await?;

            // Обновить индекс GPO
            let index_key = format!("gpo_link:{}", ou_id);
            let mut gpo_ids: HashSet<Uuid> = self.load(&index_key).await?.unwrap_or_else(HashSet::new);
            gpo_ids.remove(&gpo_id);
            self.store(index_key, &gpo_ids).await?;
        }

        Ok(())
    }

    /// Включить/отключить блокировку наследования GPO
    pub async fn set_block_inheritance(&self, ou_id: Uuid, block: bool) -> Result<(), DirectoryError> {
        let mut ou = match self.get_ou(ou_id).await? {
            Some(ou) => ou,
            None => return Err(DirectoryError::NotFound("OU not found".to_string())),
        };

        ou.block_inheritance = block;
        ou.update_gpoptions();
        ou.updated_at = chrono::Utc::now();

        let key = format!("ou:{}", ou.id);
        self.store(key, &ou).await?;

        Ok(())
    }

    /// Включить/отключить принудительное применение GPO
    pub async fn set_gpo_enforced(&self, ou_id: Uuid, enforced: bool) -> Result<(), DirectoryError> {
        let mut ou = match self.get_ou(ou_id).await? {
            Some(ou) => ou,
            None => return Err(DirectoryError::NotFound("OU not found".to_string())),
        };

        ou.enforced = enforced;
        ou.update_gplink();
        ou.updated_at = chrono::Utc::now();

        let key = format!("ou:{}", ou.id);
        self.store(key, &ou).await?;

        Ok(())
    }

    // === SECURITY FILTERING ===

    /// Проверить, может ли объект (пользователь/группа) применять GPO
    pub async fn is_gpo_applicable_to(
        &self,
        gpo: &GroupPolicy,
        principal_sid: &SecurityIdentifier,
    ) -> Result<bool, DirectoryError> {
        // Если security_filtering пуст — применяется ко всем
        if gpo.security_filtering.is_empty() {
            return Ok(true);
        }

        // Проверяем, есть ли совпадение по SID
        for filter in &gpo.security_filtering {
            if let SidOrId::Sid(sid) = filter {
                if sid == principal_sid {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    // === POLICY INHERITANCE ===

    /// Получить все GPO, применимые к OU (с учётом наследования)
    pub async fn get_effective_gpos_for_ou(
        &self,
        ou_id: Uuid,
    ) -> Result<Vec<GroupPolicy>, DirectoryError> {
        let mut all_gpos = Vec::new();
        let mut visited_ou_ids = HashSet::new();
        let mut current_ou_id = Some(ou_id);

        while let Some(ou_id) = current_ou_id {
            if visited_ou_ids.contains(&ou_id) {
                return Err(DirectoryError::InvalidInput(
                    "Circular OU hierarchy detected".to_string(),
                ));
            }
            visited_ou_ids.insert(ou_id);

            let ou = match self.get_ou(ou_id).await? {
                Some(ou) => ou,
                None => return Err(DirectoryError::NotFound("OU not found".to_string())),
            };

            // Если уже есть GPO и родительский блокирует наследование — останавливаемся
            if !all_gpos.is_empty() && ou.block_inheritance {
                // Но добавляем enforced GPO этого OU
                let gpos = self.find_gpos_for_ou(ou_id).await?;
                let enforced: Vec<_> = gpos.into_iter().filter(|g| g.enforced).collect();
                all_gpos.extend(enforced);
                break;
            }

            // Добавляем GPO этого OU
            let mut gpos = self.find_gpos_for_ou(ou_id).await?;
            gpos.sort_by(|a, b| b.enforced.cmp(&a.enforced).then_with(|| a.order.cmp(&b.order)));
            all_gpos.extend(gpos);

            // Переходим к родителю
            current_ou_id = ou.parent;
        }

        // Убираем дубликаты
        let mut seen = HashSet::new();
        let mut unique = Vec::new();
        for gpo in all_gpos {
            if seen.insert(gpo.id) {
                unique.push(gpo);
            }
        }

        Ok(unique)
    }

    /// Получить все GPO, применимые к пользователю
    pub async fn get_effective_gpos_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<GroupPolicy>, DirectoryError> {
        let user = match self.get_user(user_id).await? {
            Some(u) => u,
            None => return Err(DirectoryError::NotFound("User not found".to_string())),
        };

        let mut all_gpos = Vec::new();

        // 1. GPO из OU пользователя
        if let Some(ou_id) = user.organizational_unit {
            let gpos = self.get_effective_gpos_for_ou(ou_id).await?;
            all_gpos.extend(gpos);
        }

        // 2. GPO из групп пользователя
        
        let groups = self.find_groups_by_member(user_id).await?;
        for group in groups {
            // Группы не имеют OU — пропускаем
        }

        // 3. GPO из домена
        if let Some(domain_id) = user.domains.get(0) {
            let gpos = self.find_gpos_for_domain(*domain_id).await?;
            all_gpos.extend(gpos);
        }

        // Убираем дубликаты
        let mut seen = HashSet::new();
        let mut unique = Vec::new();
        for gpo in all_gpos {
            if seen.insert(gpo.id) {
                unique.push(gpo);
            }
        }

        // Сортируем: enforced в начало, затем по order
        unique.sort_by(|a, b| b.enforced.cmp(&a.enforced).then_with(|| a.order.cmp(&b.order)));

        Ok(unique)
    }

    // === TOKEN GROUPS ===

    /// Найти группу по RID (например, 513)
    pub async fn find_group_by_rid(&self, rid: u32) -> Result<Option<Group>, DirectoryError> {
        let all_group_ids: Vec<Uuid> = self.load("all_groups_index").await?.unwrap_or_default();
        for group_id in all_group_ids {
            if let Some(group) = self.get_group(group_id).await? {
                if group.get_rid() == rid {
                    return Ok(Some(group));
                }
            }
        }
        Ok(None)
    }

    /// Получить все группы, в которых состоит пользователь (включая вложенные)
    pub async fn get_token_groups(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SecurityIdentifier>, DirectoryError> {
        let mut tokens = Vec::new();

        // Прямые группы
        let direct_groups = self.find_groups_by_member(user_id).await?;
        for group in &direct_groups {
            tokens.push(group.sid.clone());
        }

        // Основная группа
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

    // === DN (Distinguished Name) ===

    /// Генерирует DN для пользователя
    pub fn generate_user_dn(user: &User, domain: &Domain) -> String {
        format!("CN={},{}", user.username, Self::domain_dn(domain))
    }

    /// Генерирует DN для OU
    pub fn generate_ou_dn(name: &str, parent: Option<&str>) -> String {
        let mut dn = format!("OU={}", name);
        if let Some(parent_dn) = parent {
            dn.push_str(",");
            dn.push_str(parent_dn);
        }
        dn
    }

    /// Генерирует DN для домена
    pub fn domain_dn(domain: &Domain) -> String {
        domain
            .name
            .split('.')
            .map(|part| format!("DC={}", part))
            .collect::<Vec<_>>()
            .join(",")
    }
}

// Автоматическое сохранение при выходе
impl Drop for DirectoryService {
    fn drop(&mut self) {
        // RadDB сам сохранится через Drop
    }
}