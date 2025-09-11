resource "aws_s3_bucket" "backup_bucket" {
  bucket        = "backup-bucket-1234583728291"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "backup_bucket" {
  bucket = aws_s3_bucket.backup_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "backup_bucket" {
  bucket = aws_s3_bucket.backup_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "backup_bucket" {
  depends_on = [
    aws_s3_bucket_ownership_controls.backup_bucket,
    aws_s3_bucket_public_access_block.backup_bucket,
  ]

  bucket = aws_s3_bucket.backup_bucket.id
  acl    = "public-read"
}

resource "aws_s3_bucket_policy" "backup_bucket" {
  depends_on = [
    aws_s3_bucket_ownership_controls.backup_bucket,
    aws_s3_bucket_public_access_block.backup_bucket,
  ]

  bucket = aws_s3_bucket.backup_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::backup-bucket-1234583728291/*"
      },
    ]
  })
}
