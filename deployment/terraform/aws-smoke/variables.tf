variable "aws_profile" {
  description = "AWS CLI profile used by Terraform."
  type        = string
  default     = "arladkr-sso"
}

variable "aws_region" {
  description = "AWS region for the single-region smoke experiment."
  type        = string
  default     = "us-east-1"
}

variable "availability_zone_id" {
  description = "Stable physical AZ identifier for all smoke nodes."
  type        = string
  default     = "use1-az5"
}

variable "vpc_cidr" {
  description = "VPC CIDR for this regional experiment stack."
  type        = string
  default     = "10.42.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR."
  }
}

variable "node_subnet_cidr" {
  description = "Node subnet CIDR. Keep the existing /24 for smoke; pass a /23 or larger for n=256."
  type        = string
  default     = "10.42.1.0/24"

  validation {
    condition     = can(cidrnetmask(var.node_subnet_cidr))
    error_message = "node_subnet_cidr must be a valid IPv4 CIDR."
  }
}

variable "node_private_ip_offset" {
  description = "First usable host offset assigned to NodeSlot zero in this subnet."
  type        = number
  default     = 10

  validation {
    condition     = var.node_private_ip_offset >= 5 && var.node_private_ip_offset == floor(var.node_private_ip_offset)
    error_message = "node_private_ip_offset must be an integer of at least 5."
  }
}

variable "node_slot_offset" {
  description = "Global NodeSlot offset; use a distinct range for each regional stack."
  type        = number
  default     = 0

  validation {
    condition     = var.node_slot_offset >= 0 && var.node_slot_offset == floor(var.node_slot_offset)
    error_message = "node_slot_offset must be a non-negative integer."
  }
}

variable "instance_type" {
  description = "Homogeneous benchmark instance type."
  type        = string
  default     = "c7g.xlarge"
}

variable "ami_id" {
  description = "Pinned benchmark AMI. Leave empty to use the current Amazon Linux 2023 ARM64 base image."
  type        = string
  default     = ""
}

variable "instance_count" {
  description = "Physical EC2 instance count for an AWS experiment (maximum 128)."
  type        = number
  default     = 0

  validation {
    condition     = var.instance_count >= 0 && var.instance_count <= 128
    error_message = "instance_count must be between 0 and 128."
  }
}

variable "logical_node_ids_by_instance" {
  description = "Comma-separated logical node IDs hosted by each physical instance. One ID per instance in production."
  type        = list(string)
  default     = []
}

variable "associate_public_ip_address" {
  description = "Assign public IPv4 to experiment instances. Private SSM mode disables this and uses VPC endpoints."
  type        = bool
  default     = false
}

variable "enable_private_management_endpoints" {
  description = "Create SSM, SSM Messages, EC2 Messages interface endpoints and an S3 gateway endpoint."
  type        = bool
  default     = true
}

variable "protocol_suite" {
  description = "Canonical discovery tag value."
  type        = string
  default     = "rla"
}

variable "experiment_group" {
  description = "Unique tag used to discover and destroy only this experiment."
  type        = string
  default     = "smoke-n10-use1-20260817-142937"

  validation {
    condition     = length(var.experiment_group) >= 3 && length(var.experiment_group) <= 37 && can(regex("^[A-Za-z0-9-]+$", var.experiment_group))
    error_message = "experiment_group must be 3-37 alphanumeric/dash characters so IAM name prefixes remain valid."
  }
}

variable "root_volume_gb" {
  description = "Per-node gp3 root volume size."
  type        = number
  default     = 30
}

variable "enable_public_protocol" {
  description = "Allow protocol TCP over public IPv4 from this fleet and explicit peer CIDRs."
  type        = bool
  default     = false
}

variable "protocol_public_port_from" {
  description = "First public protocol TCP port."
  type        = number
  default     = 30000

  validation {
    condition     = var.protocol_public_port_from >= 1 && var.protocol_public_port_from <= 65535
    error_message = "protocol_public_port_from must be between 1 and 65535."
  }
}

variable "protocol_public_port_to" {
  description = "Last public protocol TCP port, including derived protocol namespace ports."
  type        = number
  default     = 60000

  validation {
    condition     = var.protocol_public_port_to >= var.protocol_public_port_from && var.protocol_public_port_to <= 65535
    error_message = "protocol_public_port_to must be between 1 and 65535."
  }
}

variable "protocol_public_peer_cidrs" {
  description = "Additional public peer /32 CIDRs, normally from other regional stacks. Exclude this stack's own public IPs."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.protocol_public_peer_cidrs :
      can(cidrnetmask(cidr)) && can(regex("/32$", cidr))
    ])
    error_message = "protocol_public_peer_cidrs must contain IPv4 /32 CIDRs only."
  }
}

variable "protocol_public_cidrs_per_group" {
  description = "Maximum exact /32 sources placed in one protocol security group."
  type        = number
  default     = 48

  validation {
    condition     = var.protocol_public_cidrs_per_group >= 1 && var.protocol_public_cidrs_per_group <= 60
    error_message = "protocol_public_cidrs_per_group must be between 1 and 60."
  }
}

variable "protocol_public_world_ingress" {
  description = "Legacy escape hatch for an explicitly configured non-world CIDR. 0.0.0.0/0 is rejected."
  type        = bool
  default     = false
}

variable "protocol_public_ingress_cidr" {
  description = "CIDR used by protocol_public_world_ingress. World ingress is deliberately forbidden."
  type        = string
  default     = "192.0.2.0/32"

  validation {
    condition = can(cidrnetmask(var.protocol_public_ingress_cidr)) && (
      !var.protocol_public_world_ingress || var.protocol_public_ingress_cidr != "0.0.0.0/0"
    )
    error_message = "protocol_public_ingress_cidr must be valid and cannot be 0.0.0.0/0."
  }
}
