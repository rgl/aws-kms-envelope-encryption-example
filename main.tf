terraform {
  required_version = "1.11.2"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.63.1"
    }
  }
}


provider "aws" {
  default_tags {
    tags = {
      Project = trim(var.name_prefix, "-")
    }
  }
}


variable "name_prefix" {
  type    = string
  default = "rgl-aws-kms-playground-"
}


resource "aws_iam_user" "alice" {
  name = "${var.name_prefix}alice"
}

resource "aws_iam_access_key" "alice" {
  user = aws_iam_user.alice.name
}

resource "aws_kms_key" "alice" {
  description         = "Alice"
  enable_key_rotation = true
}

resource "aws_kms_alias" "alice" {
  name          = "alias/${var.name_prefix}alice"
  target_key_id = aws_kms_key.alice.key_id
}

resource "aws_iam_policy" "alice_kms_key" {
  name        = "${var.name_prefix}alice-kms-key"
  description = "Alice Key"
  policy      = data.aws_iam_policy_document.alice_kms_key.json
}

data "aws_iam_policy_document" "alice_kms_key" {
  statement {
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      aws_kms_key.alice.arn,
    ]
  }
}

resource "aws_iam_user_policy_attachment" "alice_kms_key" {
  user       = aws_iam_user.alice.name
  policy_arn = aws_iam_policy.alice_kms_key.arn
}


resource "aws_iam_policy" "kms_key_wrap" {
  name        = "${var.name_prefix}kms-key-wrap"
  description = "Key Wrap"
  policy      = data.aws_iam_policy_document.kms_key_wrap.json
}

data "aws_iam_policy_document" "kms_key_wrap" {
  statement {
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
    ]
    resources = [
      aws_kms_key.alice.arn,
      aws_kms_key.bob.arn,
    ]
  }
}

resource "aws_iam_user_policy_attachment" "alice_kms_key_wrap" {
  user       = aws_iam_user.alice.name
  policy_arn = aws_iam_policy.kms_key_wrap.arn
}

resource "aws_iam_user_policy_attachment" "bob_kms_key_wrap" {
  user       = aws_iam_user.bob.name
  policy_arn = aws_iam_policy.kms_key_wrap.arn
}


resource "aws_iam_user" "bob" {
  name = "${var.name_prefix}bob"
}

resource "aws_iam_access_key" "bob" {
  user = aws_iam_user.bob.name
}

resource "aws_kms_key" "bob" {
  description         = "Bob"
  enable_key_rotation = true
}

resource "aws_kms_alias" "bob" {
  name          = "alias/${var.name_prefix}bob"
  target_key_id = aws_kms_key.bob.key_id
}

resource "aws_iam_policy" "bob_kms_key" {
  name        = "${var.name_prefix}bob-kms-key"
  description = "Bob Key"
  policy      = data.aws_iam_policy_document.bob_kms_key.json
}

data "aws_iam_policy_document" "bob_kms_key" {
  statement {
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      aws_kms_key.bob.arn,
    ]
  }
}

resource "aws_iam_user_policy_attachment" "bob_kms_key" {
  user       = aws_iam_user.bob.name
  policy_arn = aws_iam_policy.bob_kms_key.arn
}


output "alice_arn" {
  value = aws_iam_user.alice.arn
}

output "alice_access_key_id" {
  value = aws_iam_access_key.alice.id
}

output "alice_secret_access_key" {
  value     = aws_iam_access_key.alice.secret
  sensitive = true
}

output "alice_key_arn" {
  value = aws_kms_key.alice.arn
}

output "alice_key_alias" {
  value = aws_kms_alias.alice.name
}

output "bob_access_key_id" {
  value = aws_iam_access_key.bob.id
}

output "bob_secret_access_key" {
  value     = aws_iam_access_key.bob.secret
  sensitive = true
}

output "bob_arn" {
  value = aws_iam_user.bob.arn
}

output "bob_key_arn" {
  value = aws_kms_key.bob.arn
}

output "bob_key_alias" {
  value = aws_kms_alias.bob.name
}
