# PostgreSQL Cloud SQL Database Infrastructure
# This file implements the PostgreSQL migration infrastructure as specified in instructions.json

# Random password generation for PostgreSQL user
resource "random_password" "postgres_password" {
  length  = 32
  special = true
}

# Secret Manager secret for PostgreSQL password
resource "google_secret_manager_secret" "postgres_password" {
  secret_id = "cypheron-postgres-password"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# Store the generated password in Secret Manager
resource "google_secret_manager_secret_version" "postgres_password" {
  secret      = google_secret_manager_secret.postgres_password.id
  secret_data = random_password.postgres_password.result
}

# Secret Manager secret for encryption salt (required by security fixes)
resource "google_secret_manager_secret" "encryption_salt" {
  secret_id = "pq-encryption-salt"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# Generate and store encryption salt
resource "random_password" "encryption_salt" {
  length  = 24
  special = false
}

resource "google_secret_manager_secret_version" "encryption_salt" {
  secret      = google_secret_manager_secret.encryption_salt.id
  secret_data = base64encode(random_password.encryption_salt.result)
}

# Private IP range for Cloud SQL
resource "google_compute_global_address" "postgres_private_ip" {
  name          = "cypheron-postgres-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc.id
}

# Private service connection for Cloud SQL
resource "google_service_networking_connection" "postgres_private_vpc" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.postgres_private_ip.name]

  depends_on = [google_project_service.apis]
}

# Cloud SQL PostgreSQL instance
resource "google_sql_database_instance" "cypheron_postgres" {
  name             = "cypheron-postgres-${var.environment}"
  database_version = var.postgres_version
  region           = var.region

  deletion_protection = var.enable_deletion_protection

  settings {
    tier                        = var.postgres_tier
    availability_type          = var.postgres_availability_type
    disk_type                  = "PD_SSD"
    disk_size                  = var.postgres_disk_size
    disk_autoresize            = true
    disk_autoresize_limit      = var.postgres_max_disk_size

    # Backup configuration
    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      location                       = var.region
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 30
        retention_unit   = "COUNT"
      }
    }

    # Network configuration - private IP only
    ip_configuration {
      ipv4_enabled                                  = false
      private_network                              = google_compute_network.vpc.id
      enable_private_path_for_google_cloud_services = true
      require_ssl                                  = true

      authorized_networks {
        name  = "vpc-connector"
        value = "10.8.0.0/28"
      }
    }

    # Maintenance window
    maintenance_window {
      day          = 7
      hour         = 3
      update_track = "stable"
    }

    # Security and monitoring
    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }

    database_flags {
      name  = "log_statement"
      value = "ddl"
    }

    database_flags {
      name  = "shared_preload_libraries"
      value = "pg_stat_statements"
    }

    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
      record_client_address   = true
    }

    user_labels = {
      environment = var.environment
      service     = "cypheron-api"
      managed_by  = "terraform"
    }
  }

  depends_on = [
    google_service_networking_connection.postgres_private_vpc
  ]
}

# PostgreSQL database
resource "google_sql_database" "cypheron_database" {
  name     = var.postgres_database_name
  instance = google_sql_database_instance.cypheron_postgres.name
  charset  = "UTF8"
  collation = "en_US.UTF8"
}

# PostgreSQL user
resource "google_sql_user" "cypheron_user" {
  name     = var.postgres_username
  instance = google_sql_database_instance.cypheron_postgres.name
  password = random_password.postgres_password.result

  depends_on = [google_sql_database.cypheron_database]
}

# IAM binding for Secret Manager access to PostgreSQL password
resource "google_secret_manager_secret_iam_member" "postgres_password_accessor" {
  secret_id = google_secret_manager_secret.postgres_password.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.firestore_accessor.email}"
}

# IAM binding for Secret Manager access to encryption salt
resource "google_secret_manager_secret_iam_member" "encryption_salt_accessor" {
  secret_id = google_secret_manager_secret.encryption_salt.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.firestore_accessor.email}"
}

# Cloud SQL IAM binding for the service account
resource "google_project_iam_member" "cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.firestore_accessor.email}"
}

# Additional Cloud SQL instance user for service account (for IAM authentication)
resource "google_sql_user" "iam_service_account_user" {
  name     = google_service_account.firestore_accessor.email
  instance = google_sql_database_instance.cypheron_postgres.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"

  depends_on = [google_sql_database.cypheron_database]
}

# Database connection monitoring
resource "google_monitoring_alert_policy" "postgres_connection_count" {
  display_name = "PostgreSQL High Connection Count"
  combiner     = "OR"

  conditions {
    display_name = "PostgreSQL connection count"

    condition_threshold {
      filter          = "resource.type=\"cloudsql_database\" AND resource.labels.database_id=\"${var.project_id}:${google_sql_database_instance.cypheron_postgres.name}\" AND metric.type=\"cloudsql.googleapis.com/database/postgresql/num_backends\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = var.postgres_max_connections * 0.8

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = []

  alert_strategy {
    auto_close = "86400s"
  }

  depends_on = [google_sql_database_instance.cypheron_postgres]
}