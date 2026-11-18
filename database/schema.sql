-- PhishGuard MySQL 8 schema (equivalent to backend/app/models/models.py).
-- The app also creates these tables automatically via SQLAlchemy (create_all); use this file for manual/managed setups.
CREATE DATABASE IF NOT EXISTS phishguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE phishguard;

CREATE TABLE IF NOT EXISTS users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(50)  NOT NULL,
  email         VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,            -- salted scrypt/pbkdf2 hash, never plaintext
  role          VARCHAR(20)  NOT NULL DEFAULT 'user',
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY ix_users_username (username),
  UNIQUE KEY ix_users_email (email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS email_scans (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  user_id       INT NOT NULL,
  sender_email  VARCHAR(255) NOT NULL DEFAULT '',
  subject       VARCHAR(500) NOT NULL DEFAULT '',
  email_content TEXT,                              -- short PII-redacted excerpt only (privacy minimisation)
  prediction    VARCHAR(20) NOT NULL,              -- PHISHING | SUSPICIOUS | LEGITIMATE
  risk_score    DOUBLE NOT NULL,
  report_json   LONGTEXT,                          -- extra column: full analysis report for the detail view
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_email_scans_user_id (user_id), KEY ix_email_scans_prediction (prediction), KEY ix_email_scans_created_at (created_at),
  CONSTRAINT fk_email_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS website_scans (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL,
  url         VARCHAR(2048) NOT NULL,
  domain      VARCHAR(255)  NOT NULL,
  prediction  VARCHAR(20)   NOT NULL,              -- SAFE | SUSPICIOUS | PHISHING | UNKNOWN
  risk_score  DOUBLE NOT NULL,
  ssl_status  VARCHAR(30) NOT NULL DEFAULT 'unknown',
  report_json LONGTEXT,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_website_scans_user_id (user_id), KEY ix_website_scans_domain (domain), KEY ix_website_scans_prediction (prediction), KEY ix_website_scans_created_at (created_at),
  CONSTRAINT fk_website_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS scan_history (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  user_id           INT NOT NULL,
  scan_type         VARCHAR(10) NOT NULL,          -- email | website
  scan_reference_id INT NOT NULL,                  -- id in email_scans / website_scans (polymorphic, so no FK)
  status            VARCHAR(20) NOT NULL DEFAULT 'completed',
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_scan_history_user_id (user_id), KEY ix_scan_history_created_at (created_at), KEY ix_history_type_ref (scan_type, scan_reference_id),
  CONSTRAINT fk_history_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS scan_features (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  scan_id       INT NOT NULL,                      -- -> scan_history.id
  feature_name  VARCHAR(100) NOT NULL,
  feature_value TEXT,
  risk_reason   VARCHAR(500) NOT NULL DEFAULT '',
  KEY ix_scan_features_scan_id (scan_id),
  CONSTRAINT fk_features_history FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS model_metrics (
  id               INT AUTO_INCREMENT PRIMARY KEY,
  model_name       VARCHAR(100) NOT NULL,
  accuracy         DOUBLE NOT NULL,
  `precision`      DOUBLE NOT NULL,
  recall           DOUBLE NOT NULL,
  f1_score         DOUBLE NOT NULL,
  roc_auc          DOUBLE NULL,
  trained_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  confusion_matrix VARCHAR(200) NOT NULL DEFAULT '[]',   -- extras: be transparent about provenance of the numbers
  dataset          VARCHAR(255) NOT NULL DEFAULT '',
  is_demo_data     INT NOT NULL DEFAULT 0,
  KEY ix_model_metrics_model_name (model_name)
) ENGINE=InnoDB;
