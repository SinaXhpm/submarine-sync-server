-- Submarine sync server — database tables (MariaDB 10.6+ or MySQL 8.0+).
--
-- Safe to run again: every statement only adds what is missing. bin/migrate.php
-- runs this file (the Docker image does that at every start); on a shared host
-- you can import it with phpMyAdmin instead.

CREATE TABLE IF NOT EXISTS users (
  id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
  email              VARCHAR(191) NOT NULL,
  password_hash      VARCHAR(255) DEFAULT NULL,
  status             ENUM('pending','active','banned') NOT NULL DEFAULT 'pending',
  created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  failed_login_count INT UNSIGNED NOT NULL DEFAULT 0,
  locked_until       BIGINT UNSIGNED DEFAULT NULL,
  last_login_at      BIGINT UNSIGNED DEFAULT NULL,
  last_login_ip      VARCHAR(45) DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sign-ins: one row per signed-in device. Only an HMAC of the token is kept.
CREATE TABLE IF NOT EXISTS auth_tokens (
  token_hash   CHAR(64) NOT NULL,
  user_id      INT UNSIGNED NOT NULL,
  device_label VARCHAR(64) DEFAULT NULL,
  ip_address   VARCHAR(45) DEFAULT NULL,
  expires_at   BIGINT UNSIGNED NOT NULL,
  last_used_at BIGINT UNSIGNED DEFAULT NULL,
  created_at   BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (token_hash),
  KEY idx_user (user_id),
  KEY idx_expires (expires_at),
  CONSTRAINT fk_auth_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One-time codes: verify (sign-up or invitation), claim (choosing the
-- password), reset, login. Only an HMAC of the code is kept.
CREATE TABLE IF NOT EXISTS verify_tokens (
  token_hash CHAR(64) NOT NULL,
  user_id    INT UNSIGNED NOT NULL,
  purpose    ENUM('verify','invite','claim','reset','login') NOT NULL,
  expires_at BIGINT UNSIGNED NOT NULL,
  used_at    BIGINT UNSIGNED DEFAULT NULL,
  PRIMARY KEY (token_hash),
  KEY idx_user (user_id),
  KEY idx_expires (expires_at),
  KEY idx_used (used_at),
  CONSTRAINT fk_verify_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rate_limits (
  bucket       VARCHAR(191) NOT NULL,
  window_start BIGINT UNSIGNED NOT NULL,
  hits         INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, window_start),
  KEY idx_window (window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The event log (sign-ins, syncs, admin actions). Never a profile's contents.
CREATE TABLE IF NOT EXISTS auth_events (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id    INT UNSIGNED DEFAULT NULL,
  email      VARCHAR(191) DEFAULT NULL,
  ip_address VARCHAR(45) NOT NULL,
  event      VARCHAR(32) NOT NULL,
  success    TINYINT(1) NOT NULL DEFAULT 0,
  detail     VARCHAR(255) DEFAULT NULL,
  created_at BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (id),
  KEY idx_email_time (email, created_at),
  KEY idx_ip_time (ip_address, created_at),
  KEY idx_user_time (user_id, created_at),
  KEY idx_event_time (event, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- A personal profile's records. `blob` is the encrypted record as hex; the
-- server never decrypts it. `profile` is the app's partition id.
CREATE TABLE IF NOT EXISTS sync_records (
  user_id     BIGINT UNSIGNED NOT NULL,
  profile     VARCHAR(32) NOT NULL,
  uuid        VARCHAR(64) NOT NULL,
  entity_type VARCHAR(24) NOT NULL,
  updated_at  VARCHAR(48) NOT NULL,
  deleted     TINYINT(1) NOT NULL DEFAULT 0,
  `blob`      MEDIUMTEXT DEFAULT NULL,
  rev         BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, profile, uuid),
  KEY idx_since (user_id, profile, updated_at),
  KEY idx_rev (user_id, profile, rev)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

-- Each personal profile's revision counter (delta sync).
CREATE TABLE IF NOT EXISTS sync_revs (
  user_id BIGINT UNSIGNED NOT NULL,
  profile VARCHAR(32) NOT NULL,
  rev     BIGINT UNSIGNED NOT NULL DEFAULT 0,
  epoch   CHAR(16) NOT NULL,
  PRIMARY KEY (user_id, profile)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

-- A personal profile's name, for the picker on a new device.
CREATE TABLE IF NOT EXISTS sync_profiles (
  user_id BIGINT UNSIGNED NOT NULL,
  profile VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  name    VARCHAR(64) NOT NULL,
  PRIMARY KEY (user_id, profile)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- An account's sharing key: the public key, and the private key encrypted with
-- the user's sharing passphrase (which never reaches the server).
CREATE TABLE IF NOT EXISTS user_keys (
  user_id         BIGINT UNSIGNED NOT NULL,
  public_key      VARCHAR(64) NOT NULL,
  wrapped_privkey MEDIUMTEXT NOT NULL,
  enc_salt        VARCHAR(64) NOT NULL,
  updated_at      BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

CREATE TABLE IF NOT EXISTS shared_profiles (
  share_id      VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  owner_user_id BIGINT UNSIGNED NOT NULL,
  name          VARCHAR(64) NOT NULL,
  created_at    BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (share_id),
  KEY idx_owner (owner_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- A shared profile's members. sealed_dek is the profile's key sealed to the
-- member's public key: only that member's device can open it.
CREATE TABLE IF NOT EXISTS profile_members (
  share_id       VARCHAR(64) NOT NULL,
  member_user_id BIGINT UNSIGNED NOT NULL,
  role           ENUM('owner','editor','user') NOT NULL,
  sealed_dek     MEDIUMTEXT NOT NULL,
  status         ENUM('pending','active') NOT NULL DEFAULT 'pending',
  invited_by     BIGINT UNSIGNED NOT NULL,
  created_at     BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (share_id, member_user_id),
  KEY idx_member (member_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

CREATE TABLE IF NOT EXISTS shared_records (
  share_id    VARCHAR(64) NOT NULL,
  uuid        VARCHAR(64) NOT NULL,
  entity_type VARCHAR(24) NOT NULL,
  updated_at  VARCHAR(48) NOT NULL,
  deleted     TINYINT(1) NOT NULL DEFAULT 0,
  `blob`      MEDIUMTEXT DEFAULT NULL,
  last_writer BIGINT UNSIGNED DEFAULT NULL,
  rev         BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (share_id, uuid),
  KEY idx_since (share_id, updated_at),
  KEY idx_rev (share_id, rev)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

CREATE TABLE IF NOT EXISTS shared_revs (
  share_id VARCHAR(64) NOT NULL,
  rev      BIGINT UNSIGNED NOT NULL DEFAULT 0,
  epoch    CHAR(16) NOT NULL,
  PRIMARY KEY (share_id)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

-- A deleted share's id, so nobody can register it again.
CREATE TABLE IF NOT EXISTS deleted_shares (
  share_id   VARCHAR(64) NOT NULL,
  deleted_at BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (share_id)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

-- Admin panel sign-ins. Only an HMAC of the session cookie is kept.
CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash CHAR(64) NOT NULL,
  csrf       CHAR(64) NOT NULL,
  pw_tag     CHAR(16) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  created_at BIGINT UNSIGNED NOT NULL,
  seen_at    BIGINT UNSIGNED NOT NULL,
  flash      VARCHAR(255) CHARACTER SET utf8mb4 DEFAULT NULL,
  PRIMARY KEY (token_hash),
  KEY idx_seen (seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;
