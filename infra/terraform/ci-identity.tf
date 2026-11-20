# Keyless CI/CD: GitHub OIDC → Workload Identity Federation → short-lived token.

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github"
  display_name              = "GitHub Actions"
  depends_on                = [google_project_service.apis]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub OIDC"

  attribute_mapping = {
    "google.subject"          = "assertion.sub"
    "attribute.repository_id" = "assertion.repository_id"
    "attribute.environment"   = "assertion.environment"
  }

  # Only this repo's protected `production` environment. Pinned to the numeric
  # repo ID so a re-created repo with the same name can't inherit access.
  attribute_condition = <<-EOT
    assertion.repository_id == "${var.github_repository_id}" &&
    assertion.environment == "production"
  EOT

  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
}

resource "google_service_account" "deployer" {
  account_id   = "radar-deployer"
  display_name = "GitHub Actions deployer"
}

resource "google_service_account_iam_member" "deployer_wif" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository_id/${var.github_repository_id}"
}

resource "google_artifact_registry_repository_iam_member" "deployer_push" {
  repository = google_artifact_registry_repository.images.name
  location   = var.region
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_cloud_run_v2_service_iam_member" "deployer_web" {
  name     = google_cloud_run_v2_service.web.name
  location = var.region
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_cloud_run_v2_job_iam_member" "deployer_job" {
  name     = google_cloud_run_v2_job.collector.name
  location = var.region
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_service_account_iam_member" "deployer_actas" {
  for_each = {
    web       = google_service_account.web.name
    collector = google_service_account.collector.name
  }
  service_account_id = each.value
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_project_iam_member" "deployer_project" {
  for_each = toset(["roles/firebasehosting.admin", "roles/run.viewer"])
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.deployer.email}"
}
