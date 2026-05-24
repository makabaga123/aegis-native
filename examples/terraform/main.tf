resource "aws_security_group" "bad" {
  name = "bad-open-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public" {
  bucket = "demo-public-bucket"
  acl    = "public-read"
}

resource "aws_iam_policy" "admin" {
  name = "admin-like-policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
}
EOF
}

variable "secret_key" {
  default = "hardcoded-secret"
}
