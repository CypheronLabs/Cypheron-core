terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    # Add this new provider block for beta resources
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  # Credentials are automatically sourced from the gcloud CLI's
  # application default credentials.
}
provider "google-beta" {
  project = var.project_id
  region  = var.region
  # Credentials are automatically sourced from the gcloud CLI's
  # application default credentials.
}

# Variables are defined in variables.tf

# Enable required APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "firestore.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudbuild.googleapis.com",
    "containerregistry.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "compute.googleapis.com",
    "vpcaccess.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com"
  ])
  
  project = var.project_id
  service = each.key
  disable_on_destroy = true
  disable_dependent_services = false
}

# Service Account for Firestore access
resource "google_service_account" "firestore_accessor" {
  account_id   = "firestore-accessor"
  display_name = "Firestore Accessor Service Account"
  description  = "Service account for Cypheron API to access Firestore with minimal permissions"

  depends_on = [google_project_service.apis]
}

# Custom IAM role for minimal Firestore permissions
resource "google_project_iam_custom_role" "firestore_limited" {
  role_id     = "firestoreLimitedAccess"
  title       = "Firestore Limited Access"
  description = "Minimal permissions for API key operations only"
  permissions = [
    "datastore.entities.get",
    "datastore.entities.update", 
    "datastore.entities.create",
    "datastore.entities.list"
  ]

  depends_on = [google_project_service.apis]
}

# Bind the custom role to the service account
resource "google_project_iam_member" "firestore_limited" {
  project = var.project_id
  role    = google_project_iam_custom_role.firestore_limited.name
  member  = "serviceAccount:${google_service_account.firestore_accessor.email}"
}

# Firestore Database with security settings
resource "google_firestore_database" "default" {
  project                           = var.project_id
  name                             = "(default)"
  location_id                      = var.region
  type                             = "FIRESTORE_NATIVE"
  concurrency_mode                 = "PESSIMISTIC"
  app_engine_integration_mode      = "DISABLED"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  delete_protection_state          = "DELETE_PROTECTION_ENABLED"

  depends_on = [google_project_service.apis]
}

# Secret Manager for admin key
resource "google_secret_manager_secret" "admin_key" {
  secret_id = "pq-master-admin-key"
  
  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "admin_key_version" {
  secret      = google_secret_manager_secret.admin_key.id
  secret_data = var.master_admin_key
}

# Secret Manager for encryption password
resource "google_secret_manager_secret" "encryption_password" {
  secret_id = "pq-encryption-password"
  
  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "encryption_password_version" {
  secret      = google_secret_manager_secret.encryption_password.id
  secret_data = var.encryption_password
}



# IAM for Secret Manager access
resource "google_secret_manager_secret_iam_member" "admin_key_accessor" {
  secret_id = google_secret_manager_secret.admin_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.firestore_accessor.email}"
}

resource "google_secret_manager_secret_iam_member" "encryption_password_accessor" {
  secret_id = google_secret_manager_secret.encryption_password.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.firestore_accessor.email}"
}

# Cloud Run service with security hardening
resource "google_cloud_run_service" "cypheron_api" {
  name     = var.service_name
  location = var.region
  autogenerate_revision_name = true
  template {
    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale"         = tostring(var.max_instances)
        "autoscaling.knative.dev/minScale"         = tostring(var.min_instances)
        "run.googleapis.com/execution-environment" = "gen2"
        "run.googleapis.com/cpu-throttling"        = "false"
        # Security annotations
        "run.googleapis.com/vpc-access-connector" = google_vpc_access_connector.connector.name
        "run.googleapis.com/vpc-access-egress"    = "private-ranges-only"
      }
    }

    spec {
      service_account_name = google_service_account.firestore_accessor.email
      
      containers {
        image = "gcr.io/${var.project_id}/cypheron-api"
        
        ports {
          container_port = 8080
        }

        resources {
          limits = {
            cpu    = var.cpu_limit
            memory = var.memory_limit
          }
        }

        # Environment variables
        env {
          name  = "FIRESTORE_PROJECT_ID"
          value = var.project_id
        }

        env {
          name  = "FIRESTORE_COLLECTION"
          value = "api_keys"
        }

        # Secrets from Secret Manager
        env {
          name = "PQ_MASTER_ADMIN_KEY"
          value_from {
            secret_key_ref {
              name = google_secret_manager_secret.admin_key.secret_id
              key  = "latest"
            }
          }
        }

        env {
          name = "PQ_ENCRYPTION_PASSWORD"
          value_from {
            secret_key_ref {
              name = google_secret_manager_secret.encryption_password.secret_id
              key  = "latest"
            }
          }
        }

        env {
          name = "PQ_ENCRYPTION_SALT"
          value_from {
            secret_key_ref {
              name = google_secret_manager_secret.encryption_salt.secret_id
              key  = "latest"
            }
          }
        }

        # PostgreSQL Configuration
        env {
          name  = "USE_POSTGRESQL"
          value = tostring(var.use_postgresql)
        }

        env {
          name = "DB_PASSWORD"
          value_from {
            secret_key_ref {
              name = google_secret_manager_secret.postgres_password.secret_id
              key  = "latest"
            }
          }
        }

        env {
          name  = "DB_HOST"
          value = google_sql_database_instance.cypheron_postgres.private_ip_address
        }

        env {
          name  = "DB_NAME"
          value = var.postgres_database_name
        }

        env {
          name  = "DB_USER"
          value = var.postgres_username
        }

        env {
          name  = "DB_PORT"
          value = "5432"
        }

        # Database connection settings
        env {
          name  = "DB_MAX_CONNECTIONS"
          value = "10"
        }

        env {
          name  = "DB_MIN_CONNECTIONS"
          value = "2"
        }

        # Security Controls
        env {
          name  = "SECURITY_VULNERABILITY_SCANNING_ENABLED"
          value = "true"
        }

        env {
          name  = "SECURITY_BACKUP_PROCEDURES_ACTIVE" 
          value = "true"
        }
      }

      timeout_seconds = 60
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [
    google_project_iam_member.firestore_limited,
    google_vpc_access_connector.connector
  ]
}

# VPC for network security
resource "google_compute_network" "vpc" {
  name                    = "cypheron-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "cypheron-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.vpc.id
}

# VPC Access Connector for Cloud Run
resource "google_vpc_access_connector" "connector" {
  name          = "cypheron-connector"
  region        = var.region
  ip_cidr_range = "10.8.0.0/28"
  network       = google_compute_network.vpc.name

  depends_on = [google_project_service.apis]
}

# Cloud Run IAM - Restricted access
resource "google_cloud_run_service_iam_binding" "authenticated_invokers" {
  location = google_cloud_run_service.cypheron_api.location
  service  = google_cloud_run_service.cypheron_api.name
  role     = "roles/run.invoker"
  
  members = concat([
    "serviceAccount:${google_service_account.firestore_accessor.email}"
  ], var.allowed_users)
}

# Firewall rules for additional security
resource "google_compute_firewall" "deny_all_ingress" {
  name    = "cypheron-deny-all-ingress"
  network = google_compute_network.vpc.name

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  priority      = 1000
}

resource "google_compute_firewall" "allow_internal" {
  name    = "cypheron-allow-internal"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = ["10.0.0.0/8"]
  priority      = 500
}
resource "google_firebaserules_release" "firestore_release" {
  provider = google-beta
  project      = var.project_id
  ruleset_name = google_firebaserules_ruleset.security_rules.name
  name         = "cloud.firestore"
  depends_on = [
    google_firebaserules_ruleset.security_rules
  ]
}

resource "google_firebaserules_ruleset" "security_rules" {
  provider = google-beta 
  project = var.project_id
  source {
    files {
      content = file("../firestore.rules")
      name    = "firestore.rules"
    }
  }
  depends_on = [google_firestore_database.default]
}
# Outputs are defined in outputs.tf