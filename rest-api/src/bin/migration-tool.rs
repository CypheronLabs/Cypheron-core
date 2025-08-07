use rest_api::{
    database::{DatabaseConfig, DatabaseManager},
    security::{
        auth::{ApiKey, AuthError, PostQuantumEncryption},
        repository::{postgres_repository::PostgresRepository, ApiKeyRepository},
    },
};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use clap::{Arg, Command};
use gcloud_sdk::{
    google::firestore::v1::{
        firestore_client::FirestoreClient,
        list_documents_request::ConsistencySelector,
        ListDocumentsRequest,
        Document,
        value::ValueType,
    },
    GoogleApi,
};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
struct MigrationStats {
    total_documents: i32,
    successful_migrations: i32,
    failed_migrations: i32,
    start_time: std::time::Instant,
}

impl MigrationStats {
    fn new() -> Self {
        Self {
            total_documents: 0,
            successful_migrations: 0,
            failed_migrations: 0,
            start_time: std::time::Instant::now(),
        }
    }

    fn record_success(&mut self) {
        self.successful_migrations += 1;
    }

    fn record_failure(&mut self) {
        self.failed_migrations += 1;
    }

    fn print_summary(&self) {
        let duration = self.start_time.elapsed();
        println!("\n=== Migration Summary ===");
        println!("Total documents processed: {}", self.total_documents);
        println!("Successful migrations: {}", self.successful_migrations);
        println!("Failed migrations: {}", self.failed_migrations);
        println!("Success rate: {:.2}%", 
                 (self.successful_migrations as f64 / self.total_documents.max(1) as f64) * 100.0);
        println!("Duration: {:.2}s", duration.as_secs_f64());
        println!("Rate: {:.2} docs/sec", 
                 self.total_documents as f64 / duration.as_secs_f64().max(0.001));
        println!("========================");
    }
}

/// Firestore to PostgreSQL migration tool
/// 
/// This tool migrates API keys and related data from Google Cloud Firestore
/// to PostgreSQL following the schema defined in db/schema.sql
struct MigrationTool {
    firestore_client: GoogleApi<FirestoreClient<gcloud_sdk::GoogleAuthMiddleware>>,
    postgres_repo: PostgresRepository,
    encryption: Arc<PostQuantumEncryption>,
    project_id: String,
    collection_name: String,
    dry_run: bool,
}

impl MigrationTool {
    /// Create a new migration tool instance
    async fn new(dry_run: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Load configuration
        let project_id = std::env::var("GOOGLE_CLOUD_PROJECT_ID")
            .map_err(|_| "GOOGLE_CLOUD_PROJECT_ID environment variable is required")?;
        
        let collection_name = std::env::var("FIRESTORE_COLLECTION")
            .unwrap_or_else(|_| "api_keys".to_string());

        // Initialize Firestore client
        let firestore_client = GoogleApi::from_function(
            FirestoreClient::new,
            "https://firestore.googleapis.com",
            None,
        ).await?;

        // Initialize PostgreSQL connection and repository
        let db_config = DatabaseConfig::from_env()?;
        let db_manager = DatabaseManager::new(db_config).await?;
        
        // Initialize encryption
        let password = std::env::var("PQ_ENCRYPTION_PASSWORD")
            .map_err(|_| "PQ_ENCRYPTION_PASSWORD environment variable is required")?;
        let encryption = Arc::new(PostQuantumEncryption::from_password(&password)?);
        
        let postgres_repo = PostgresRepository::new(db_manager.pool().clone(), encryption.clone());

        Ok(Self {
            firestore_client,
            postgres_repo,
            encryption,
            project_id,
            collection_name,
            dry_run,
        })
    }

    /// Run the migration process
    async fn run_migration(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting Firestore to PostgreSQL migration...");
        
        if self.dry_run {
            println!("⚠️  DRY RUN MODE - No data will be written to PostgreSQL");
        }

        let mut stats = MigrationStats::new();

        // Test PostgreSQL connectivity
        if !self.dry_run {
            println!("🔍 Testing PostgreSQL connectivity...");
            self.postgres_repo.health_check().await
                .map_err(|e| format!("PostgreSQL health check failed: {}", e.message))?;
            println!("✅ PostgreSQL connection successful");
        }

        // List all documents in the Firestore collection
        println!("📚 Listing Firestore documents...");
        let documents = self.list_firestore_documents().await?;
        stats.total_documents = documents.len() as i32;
        
        println!("📊 Found {} documents to migrate", stats.total_documents);

        if documents.is_empty() {
            println!("ℹ️  No documents found in Firestore collection");
            return Ok(());
        }

        // Process each document
        for (index, document) in documents.iter().enumerate() {
            println!("🔄 Processing document {}/{}: {}", 
                     index + 1, documents.len(), 
                     document.name.split('/').last().unwrap_or("unknown"));

            match self.migrate_document(document).await {
                Ok(_) => {
                    stats.record_success();
                    println!("  ✅ Migration successful");
                }
                Err(e) => {
                    stats.record_failure();
                    println!("  ❌ Migration failed: {}", e);
                }
            }
        }

        stats.print_summary();

        if stats.failed_migrations > 0 {
            println!("⚠️  Migration completed with {} failures", stats.failed_migrations);
        } else {
            println!("🎉 Migration completed successfully!");
        }

        Ok(())
    }

    /// List all documents in the Firestore collection
    async fn list_firestore_documents(&self) -> Result<Vec<Document>, Box<dyn std::error::Error>> {
        let request = ListDocumentsRequest {
            parent: format!("projects/{}/databases/(default)/documents", self.project_id),
            collection_id: self.collection_name.clone(),
            page_size: 1000, // Max page size
            page_token: String::new(),
            order_by: String::new(),
            mask: None,
            show_missing: false,
            consistency_selector: Some(ConsistencySelector::ReadTime(
                gcloud_sdk::prost_types::Timestamp::from(std::time::SystemTime::now())
            )),
        };

        let response = self.firestore_client.get().list_documents(request).await?;
        Ok(response.into_inner().documents)
    }

    /// Migrate a single Firestore document to PostgreSQL
    async fn migrate_document(&self, document: &Document) -> Result<(), Box<dyn std::error::Error>> {
        // Parse Firestore document to ApiKey
        let api_key = self.parse_firestore_document(document)?;
        
        // Extract and decrypt the raw API key
        let raw_key = self.extract_and_decrypt_key(document)?;

        if self.dry_run {
            println!("  📝 DRY RUN: Would migrate API key '{}' with {} permissions", 
                     api_key.name, api_key.permissions.len());
            return Ok(());
        }

        // Store in PostgreSQL
        self.postgres_repo.store_api_key(&api_key, &raw_key).await
            .map_err(|e| format!("Failed to store in PostgreSQL: {}", e.message))?;

        Ok(())
    }

    /// Parse Firestore document into ApiKey struct
    fn parse_firestore_document(&self, doc: &Document) -> Result<ApiKey, Box<dyn std::error::Error>> {
        let fields = &doc.fields;

        // Helper function to extract string values
        let extract_string = |key: &str| -> Result<String, Box<dyn std::error::Error>> {
            fields.get(key)
                .and_then(|v| v.value_type.as_ref())
                .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.clone()) } else { None })
                .ok_or_else(|| format!("Missing or invalid {} field", key).into())
        };

        // Helper function to extract optional string values
        let extract_optional_string = |key: &str| -> Option<String> {
            fields.get(key)
                .and_then(|v| v.value_type.as_ref())
                .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.clone()) } else { None })
        };

        // Parse required fields
        let id = Uuid::parse_str(&extract_string("id")?)
            .map_err(|_| "Invalid UUID format for id")?;
        
        let name = extract_string("name")?;
        let key_hash = extract_string("key_hash")?;

        // Parse permissions array
        let permissions = fields.get("permissions")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::ArrayValue(a) = vt { Some(a) } else { None })
            .ok_or("Missing permissions field")?
            .values
            .iter()
            .filter_map(|v| v.value_type.as_ref())
            .filter_map(|vt| if let ValueType::StringValue(s) = vt { Some(s.clone()) } else { None })
            .collect();

        // Parse numeric fields
        let rate_limit = fields.get("rate_limit")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::IntegerValue(i) = vt { Some(*i as u32) } else { None })
            .unwrap_or(60);

        let usage_count = fields.get("usage_count")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::IntegerValue(i) = vt { Some(*i as u64) } else { None })
            .unwrap_or(0);

        // Parse boolean fields
        let is_active = fields.get("is_active")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::BooleanValue(b) = vt { Some(*b) } else { None })
            .unwrap_or(true);

        // Parse timestamp fields
        let created_at = fields.get("created_at")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::TimestampValue(ts) = vt { Some(ts) } else { None })
            .map(|ts| chrono::Utc.timestamp_opt(ts.seconds, ts.nanos as u32).single())
            .flatten()
            .unwrap_or_else(|| Utc::now());

        let expires_at = fields.get("expires_at")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::TimestampValue(ts) = vt { Some(ts) } else { None })
            .map(|ts| chrono::Utc.timestamp_opt(ts.seconds, ts.nanos as u32).single())
            .flatten();

        let last_used = fields.get("last_used")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::TimestampValue(ts) = vt { Some(ts) } else { None })
            .map(|ts| chrono::Utc.timestamp_opt(ts.seconds, ts.nanos as u32).single())
            .flatten();

        Ok(ApiKey {
            id,
            name,
            key_hash,
            permissions,
            rate_limit,
            created_at,
            expires_at,
            is_active,
            last_used,
            usage_count,
        })
    }

    /// Extract and decrypt the raw API key from Firestore document
    fn extract_and_decrypt_key(&self, doc: &Document) -> Result<String, Box<dyn std::error::Error>> {
        let fields = &doc.fields;

        let encrypted_key_b64 = fields.get("encrypted_key")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.as_str()) } else { None })
            .ok_or("Missing encrypted_key field")?;

        let encrypted_key_bytes = general_purpose::STANDARD.decode(encrypted_key_b64)
            .map_err(|_| "Failed to decode encrypted key")?;

        let decrypted_bytes = self.encryption.decrypt(&encrypted_key_bytes)
            .map_err(|e| format!("Failed to decrypt key: {}", e.message))?;

        let raw_key = String::from_utf8(decrypted_bytes)
            .map_err(|_| "Decrypted key contains invalid UTF-8")?;

        Ok(raw_key)
    }

    /// Validate migration by comparing data between Firestore and PostgreSQL
    async fn validate_migration(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔍 Validating migration...");

        // Get document count from Firestore
        let firestore_docs = self.list_firestore_documents().await?;
        let firestore_count = firestore_docs.len();

        // Get API key count from PostgreSQL
        let postgres_keys = self.postgres_repo.list_api_keys(None, None).await
            .map_err(|e| format!("Failed to list PostgreSQL keys: {}", e.message))?;
        let postgres_count = postgres_keys.len();

        println!("📊 Firestore documents: {}", firestore_count);
        println!("📊 PostgreSQL records: {}", postgres_count);

        if firestore_count != postgres_count {
            return Err(format!(
                "Count mismatch: Firestore has {} documents, PostgreSQL has {} records",
                firestore_count, postgres_count
            ).into());
        }

        // Spot check a few random documents
        let sample_size = (firestore_count / 10).max(1).min(10);
        println!("🔬 Performing spot check on {} documents", sample_size);

        for doc in firestore_docs.iter().take(sample_size) {
            let api_key = self.parse_firestore_document(doc)?;
            
            let postgres_key = self.postgres_repo.get_api_key_by_hash(&api_key.key_hash).await
                .map_err(|e| format!("Failed to get PostgreSQL key: {}", e.message))?
                .ok_or_else(|| format!("Key not found in PostgreSQL: {}", api_key.key_hash))?;

            // Compare key fields
            if api_key.name != postgres_key.name ||
               api_key.permissions != postgres_key.permissions ||
               api_key.rate_limit != postgres_key.rate_limit ||
               api_key.is_active != postgres_key.is_active {
                return Err(format!("Data mismatch for key: {}", api_key.key_hash).into());
            }
        }

        println!("✅ Migration validation successful!");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let matches = Command::new("migration-tool")
        .about("Migrate API keys from Firestore to PostgreSQL")
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Perform a dry run without writing to PostgreSQL")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("validate")
                .long("validate")
                .help("Validate existing migration")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose logging")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    let dry_run = matches.get_flag("dry-run");
    let validate_only = matches.get_flag("validate");
    let _verbose = matches.get_flag("verbose");

    println!("🔧 Cypheron Firestore to PostgreSQL Migration Tool");
    println!("====================================================");

    // Create migration tool
    let migration_tool = MigrationTool::new(dry_run).await?;

    if validate_only {
        migration_tool.validate_migration().await?;
    } else {
        migration_tool.run_migration().await?;
        
        if !dry_run {
            println!("\n🔍 Running post-migration validation...");
            migration_tool.validate_migration().await?;
        }
    }

    Ok(())
}