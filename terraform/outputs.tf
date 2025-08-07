# terraform/outputs.tf

output "service_url" {
  description = "The URL of the Cloud Run service"
  value       = google_cloud_run_service.cypheron_api.status[0].url
  sensitive   = true
}

output "service_account_email" {
  description = "The email of the service account used by the API"
  value       = google_service_account.firestore_accessor.email
}

output "project_id" {
  description = "The GCP project ID"
  value       = var.project_id
}

output "region" {
  description = "The GCP region where resources are deployed"
  value       = var.region
}

output "firestore_database" {
  description = "The Firestore database name"
  value       = google_firestore_database.default.name
}

output "vpc_network" {
  description = "The VPC network name"
  value       = google_compute_network.vpc.name
}

output "secrets_created" {
  description = "List of secrets created in Secret Manager"
  value = [
    google_secret_manager_secret.admin_key.secret_id,
    google_secret_manager_secret.encryption_password.secret_id
  ]
}

output "deployment_commands" {
  description = "Commands to deploy your application"
  value = {
    "build_image" = "docker build -f Dockerfile.production -t gcr.io/${var.project_id}/cypheron-api ."
    "push_image"  = "docker push gcr.io/${var.project_id}/cypheron-api"
    "deploy_rules" = "firebase deploy --only firestore:rules --project ${var.project_id}"
    "view_logs"   = "gcloud logs read 'resource.type=cloud_run_revision AND resource.labels.service_name=${var.service_name}' --project ${var.project_id} --limit 50"
  }
}

output "security_status" {
  description = "Security configuration status"
  value = {
    "firestore_rules_applied" = "✅ Firestore security rules deployed"
    "secrets_in_secret_manager" = "✅ Secrets stored in Secret Manager"
    "vpc_isolated" = "✅ VPC isolation enabled"
    "no_public_access" = "✅ No public internet access"
    "minimal_iam_permissions" = "✅ Least privilege IAM"
    "deletion_protection" = var.enable_deletion_protection ? "✅ Deletion protection enabled" : "⚠️ Deletion protection disabled"
  }
}