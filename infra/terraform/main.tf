terraform {
  required_version = ">= 1.6"
  required_providers {
    google      = { source = "hashicorp/google", version = "~> 6.0" }
    google-beta = { source = "hashicorp/google-beta", version = "~> 6.0" }
  }
  # Bucket passed at init: terraform init -backend-config="bucket=<project>-tfstate"
  backend "gcs" {
    prefix = "incident-radar"
  }
}

provider "google" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}

provider "google-beta" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}

data "google_project" "this" {}

locals {
  services = [
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "firestore.googleapis.com",
    "cloudscheduler.googleapis.com",
    "secretmanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "firebase.googleapis.com",
    "firebasehosting.googleapis.com",
    "billingbudgets.googleapis.com",
  ]
  image_placeholder = "us-docker.pkg.dev/cloudrun/container/hello"
}

resource "google_project_service" "apis" {
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}

# ── Images ────────────────────────────────────────────────────────────────────
resource "google_artifact_registry_repository" "images" {
  repository_id = "incident-radar"
  location      = var.region
  format        = "DOCKER"
  docker_config { immutable_tags = true }
  cleanup_policy_dry_run = false
  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"
    most_recent_versions { keep_count = 5 }
  }
  cleanup_policies {
    id     = "delete-old"
    action = "DELETE"
    condition { older_than = "2592000s" }
  }
  depends_on = [google_project_service.apis]
}

# ── Database: Firestore (free tier covers this workload many times over) ──────
resource "google_firestore_database" "default" {
  name                    = "(default)"
  location_id             = var.firestore_location
  type                    = "FIRESTORE_NATIVE"
  delete_protection_state = "DELETE_PROTECTION_ENABLED"
  depends_on              = [google_project_service.apis]
}

# ── Secret: the personal ntfy topic name (the name itself is the credential) ─
# Terraform creates the secret container only. The value is added out-of-band
# (gcloud secrets versions add) so it never lands in Terraform state.
resource "google_secret_manager_secret" "ntfy_topic" {
  secret_id = "ntfy-topic"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

# ── Identities: one per workload, least privilege ─────────────────────────────
resource "google_service_account" "web" {
  account_id   = "radar-web"
  display_name = "Incident Radar web (read-only Firestore)"
}

resource "google_service_account" "collector" {
  account_id   = "radar-collector"
  display_name = "Incident Radar collector (Firestore write, ntfy secret)"
}

resource "google_service_account" "scheduler" {
  account_id   = "radar-scheduler"
  display_name = "Cloud Scheduler trigger for the collector job"
}

resource "google_project_iam_member" "web_firestore_read" {
  project = var.project_id
  role    = "roles/datastore.viewer"
  member  = "serviceAccount:${google_service_account.web.email}"
}

resource "google_project_iam_member" "collector_firestore_write" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.collector.email}"
}

resource "google_secret_manager_secret_iam_member" "collector_ntfy" {
  secret_id = google_secret_manager_secret.ntfy_topic.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.collector.email}"
}

# ── Web service ───────────────────────────────────────────────────────────────
resource "google_cloud_run_v2_service" "web" {
  name                = "radar-web"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false

  template {
    service_account                  = google_service_account.web.email
    max_instance_request_concurrency = 80
    scaling {
      min_instance_count = 0
      max_instance_count = var.max_instances
    }
    containers {
      image = local.image_placeholder
      ports { container_port = 8080 }
      env {
        name  = "RADAR_STORE"
        value = "firestore"
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "DASHBOARD_URL"
        value = var.dashboard_url
      }
      resources {
        limits            = { cpu = "1", memory = "512Mi" }
        cpu_idle          = true
        startup_cpu_boost = true
      }
      startup_probe {
        tcp_socket { port = 8080 }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version, scaling]
  }
  depends_on = [google_project_service.apis]
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.web.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ── Collector job + schedule ──────────────────────────────────────────────────
resource "google_cloud_run_v2_job" "collector" {
  name                = "radar-collector"
  location            = var.region
  deletion_protection = false

  template {
    parallelism = 1
    task_count  = 1
    template {
      service_account = google_service_account.collector.email
      timeout         = "300s"
      max_retries     = 1
      containers {
        image   = local.image_placeholder
        command = ["python", "-m", "radar.collector"]
        env {
          name  = "RADAR_STORE"
          value = "firestore"
        }
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project_id
        }
        env {
          name  = "DASHBOARD_URL"
          value = var.dashboard_url
        }
        env {
          name  = "SEND_ALERTS"
          value = "true"
        }
        env {
          name = "NTFY_TOPIC"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.ntfy_topic.secret_id
              version = "latest"
            }
          }
        }
        resources {
          limits = { cpu = "1", memory = "512Mi" }
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].template[0].containers[0].image, client, client_version]
  }
  depends_on = [google_secret_manager_secret_iam_member.collector_ntfy]
}

resource "google_cloud_run_v2_job_iam_member" "scheduler_runs_collector" {
  name     = google_cloud_run_v2_job.collector.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

resource "google_cloud_scheduler_job" "collector" {
  name             = "radar-collector-every-15m"
  region           = var.region
  schedule         = "*/15 * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "60s"

  http_target {
    http_method = "POST"
    uri         = "https://run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/${google_cloud_run_v2_job.collector.name}:run"
    oauth_token {
      service_account_email = google_service_account.scheduler.email
    }
  }
  depends_on = [google_cloud_run_v2_job_iam_member.scheduler_runs_collector]
}

# ── Firebase Hosting (CDN + TLS + custom domain in front of radar-web) ────────
resource "google_firebase_project" "this" {
  provider   = google-beta
  project    = var.project_id
  depends_on = [google_project_service.apis]
}

# ── Budget ────────────────────────────────────────────────────────────────────
resource "google_billing_budget" "monthly" {
  count           = var.billing_account_id == "" ? 0 : 1
  billing_account = var.billing_account_id
  display_name    = "incident-radar-monthly"
  budget_filter { projects = ["projects/${data.google_project.this.number}"] }
  amount {
    specified_amount {
      currency_code = "USD"
      units         = tostring(var.monthly_budget_usd)
    }
  }
  threshold_rules { threshold_percent = 0.5 }
  threshold_rules { threshold_percent = 0.9 }
  threshold_rules { threshold_percent = 1.0 }
  depends_on = [google_project_service.apis]
}
