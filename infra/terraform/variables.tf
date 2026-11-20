variable "project_id" {
  type        = string
  description = "GCP project ID (dedicated to Incident Radar)."
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "firestore_location" {
  type    = string
  default = "us-central1"
}

variable "github_repository_id" {
  type        = string
  description = "Numeric GitHub repo ID: gh api repos/OWNER/incident-radar --jq .id"
}

variable "dashboard_url" {
  type        = string
  description = "Public URL of the dashboard (used in alert links and the Atom feed)."
}

variable "max_instances" {
  type    = number
  default = 2
}

variable "billing_account_id" {
  type    = string
  default = ""
}

variable "monthly_budget_usd" {
  type    = number
  default = 5
}
