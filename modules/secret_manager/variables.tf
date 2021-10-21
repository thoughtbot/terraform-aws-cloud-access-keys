variable "initial_value" {
  description = "Initial value for this secret"
  type        = string
}

variable "description" {
  description = "Description for this secret"
  type        = string
  default     = null
}

variable "name" {
  description = "Name for this secret"
  type        = string
}

variable "resource_tags" {
  description = "Tags to be applied to created resources"
  type        = map(string)
  default     = {}
}

variable "rotation_days" {
  description = "Number of days after which the secret is rotated"
  type        = number
  default     = 30
}

variable "handler" {
  description = "Handler to invoke in the function package"
  type        = string
}

variable "runtime" {
  description = "Runtime of the rotation function"
  type        = string
}

variable "source_dir" {
  description = "Directory containing the rotatation handler"
  type        = string
}

variable "env_variables" {
  description = "Environment variables for the rotation function"
  type        = map(string)
  default     = {}
}

variable "trust_principal" {
  description = "Principal allowed to access the secret (default: current account)"
  type        = string
  default     = null
}
