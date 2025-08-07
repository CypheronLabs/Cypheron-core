# terraform/variables.tf

variable "project_id" {
  description = "The GCP project ID where resources will be created"
  type        = string
  validation {
    condition     = length(var.project_id) > 0
    error_message = "Project ID must not be empty."
  }
}

variable "region" {
  description = "The GCP region for resources"
  type        = string
  default     = "us-central1"
  validation {
    condition = contains([
      "us-central1", "us-east1", "us-west1", "us-west2",
      "europe-west1", "europe-west2", "europe-west3",
      "asia-east1", "asia-northeast1", "asia-southeast1"
    ], var.region)
    error_message = "Region must be a valid GCP region."
  }
}

variable "service_name" {
  description = "The name of the Cloud Run service"
  type        = string
  default     = "cypheron-api"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", var.service_name))
    error_message = "Service name must be lowercase alphanumeric with hyphens."
  }
}

variable "master_admin_key" {
  description = "The master admin key for API access (must be at least 32 characters)"
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.master_admin_key) >= 32
    error_message = "Master admin key must be at least 32 characters long."
  }
}

variable "encryption_password" {
  description = "The encryption password for post-quantum encryption (must be at least 32 characters)"
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.encryption_password) >= 32
    error_message = "Encryption password must be at least 32 characters long."
  }
}

variable "allowed_users" {
  description = "List of users/service accounts allowed to invoke the API (format: user:email@domain.com or serviceAccount:name@project.iam.gserviceaccount.com)"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for user in var.allowed_users : can(regex("^(user:|serviceAccount:).+", user))
    ])
    error_message = "Each allowed user must start with 'user:' or 'serviceAccount:' prefix."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for critical resources"
  type        = bool
  default     = true
}

variable "max_instances" {
  description = "Maximum number of Cloud Run instances"
  type        = number
  default     = 10
  validation {
    condition     = var.max_instances >= 1 && var.max_instances <= 100
    error_message = "Max instances must be between 1 and 100."
  }
}

variable "min_instances" {
  description = "Minimum number of Cloud Run instances"
  type        = number
  default     = 1
  validation {
    condition     = var.min_instances >= 0 && var.min_instances <= 100
    error_message = "Min instances must be between 0 and 100."
  }
}

variable "memory_limit" {
  description = "Memory limit for Cloud Run containers"
  type        = string
  default     = "1Gi"
  validation {
    condition     = can(regex("^[0-9]+(Mi|Gi)$", var.memory_limit))
    error_message = "Memory limit must be in format like '1Gi' or '512Mi'."
  }
}

variable "cpu_limit" {
  description = "CPU limit for Cloud Run containers"
  type        = string
  default     = "1000m"
  validation {
    condition     = can(regex("^[0-9]+m?$", var.cpu_limit))
    error_message = "CPU limit must be in format like '1000m' or '2'."
  }
}

# PostgreSQL Configuration Variables

variable "postgres_version" {
  description = "PostgreSQL version for Cloud SQL"
  type        = string
  default     = "POSTGRES_15"
  validation {
    condition = contains([
      "POSTGRES_13", "POSTGRES_14", "POSTGRES_15", "POSTGRES_16"
    ], var.postgres_version)
    error_message = "PostgreSQL version must be a supported Cloud SQL version."
  }
}

variable "postgres_tier" {
  description = "Machine type for PostgreSQL instance"
  type        = string
  default     = "db-f1-micro"
  validation {
    condition = contains([
      "db-f1-micro", "db-g1-small", "db-n1-standard-1", "db-n1-standard-2",
      "db-n1-standard-4", "db-n1-standard-8", "db-n1-standard-16",
      "db-n1-highmem-2", "db-n1-highmem-4", "db-n1-highmem-8"
    ], var.postgres_tier)
    error_message = "PostgreSQL tier must be a valid Cloud SQL machine type."
  }
}

variable "postgres_availability_type" {
  description = "Availability type for PostgreSQL instance"
  type        = string
  default     = "ZONAL"
  validation {
    condition     = contains(["ZONAL", "REGIONAL"], var.postgres_availability_type)
    error_message = "Availability type must be ZONAL or REGIONAL."
  }
}

variable "postgres_disk_size" {
  description = "Initial disk size for PostgreSQL instance in GB"
  type        = number
  default     = 20
  validation {
    condition     = var.postgres_disk_size >= 10 && var.postgres_disk_size <= 30720
    error_message = "PostgreSQL disk size must be between 10 GB and 30720 GB."
  }
}

variable "postgres_max_disk_size" {
  description = "Maximum disk size for PostgreSQL autoresize in GB"
  type        = number
  default     = 100
  validation {
    condition     = var.postgres_max_disk_size >= var.postgres_disk_size
    error_message = "Maximum disk size must be greater than or equal to initial disk size."
  }
}

variable "postgres_database_name" {
  description = "Name of the PostgreSQL database"
  type        = string
  default     = "cypheron_prod"
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]*$", var.postgres_database_name))
    error_message = "Database name must start with a letter and contain only letters, numbers, and underscores."
  }
}

variable "postgres_username" {
  description = "Username for PostgreSQL database access"
  type        = string
  default     = "cypheron_user"
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]*$", var.postgres_username))
    error_message = "Username must start with a letter and contain only letters, numbers, and underscores."
  }
}

variable "postgres_max_connections" {
  description = "Maximum number of connections for PostgreSQL monitoring"
  type        = number
  default     = 25
  validation {
    condition     = var.postgres_max_connections >= 5 && var.postgres_max_connections <= 1000
    error_message = "Maximum connections must be between 5 and 1000."
  }
}

variable "use_postgresql" {
  description = "Enable PostgreSQL backend (true) or use Firestore legacy (false)"
  type        = bool
  default     = false
}

variable "encryption_salt" {
  description = "The encryption salt for post-quantum encryption (base64 encoded, minimum 16 bytes)"
  type        = string
  sensitive   = true
  default     = ""
  validation {
    condition = var.encryption_salt == "" || (
      can(base64decode(var.encryption_salt)) && 
      length(base64decode(var.encryption_salt)) >= 16
    )
    error_message = "Encryption salt must be empty (auto-generated) or a valid base64-encoded string of at least 16 bytes."
  }
}
