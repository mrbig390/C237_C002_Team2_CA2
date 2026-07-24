-- ============================================================
-- Restaurant Reservation System — Database Schema + Seed Data
-- PORTABLE build: runs on MySQL 5.7+/8.x AND MariaDB (XAMPP).
-- No STORED generated column (that tripped on the target engine).
-- Double-booking is enforced in the APP layer (see BUILD.md §6).
-- Run:  mysql -u root -p < schema.sql   (or paste whole file in Workbench)
-- ============================================================

DROP DATABASE IF EXISTS c237_002_team2_restaurant_reservation_system;
CREATE DATABASE c237_002_team2_restaurant_reservation_system
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE c237_002_team2_restaurant_reservation_system;

-- ------------------------------------------------------------
-- USERS
-- role gates admin routes in the app (requireAdmin middleware)
-- ------------------------------------------------------------
CREATE TABLE users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(100)  NOT NULL,
  email         VARCHAR(255)  NOT NULL,
  password_hash VARCHAR(255)  NOT NULL,          -- SHA1 hex digest (matches app.js / MySQL SHA1(), as taught in L19), NEVER plain text
  role          ENUM('user','admin') NOT NULL DEFAULT 'user',
  created_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- RESTAURANT TABLES
-- Named restaurant_tables (not `tables`) to avoid confusion with
-- the SQL keyword and INFORMATION_SCHEMA.TABLES.
-- ------------------------------------------------------------
CREATE TABLE restaurant_tables (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  table_number  VARCHAR(20)  NOT NULL,
  capacity      INT          NOT NULL,           -- max party_size allowed
  location      VARCHAR(50)  DEFAULT NULL,       -- e.g. Indoor / Outdoor / Window
  image         VARCHAR(255) DEFAULT NULL,       -- uploaded table photo filename in public/images (admin sets via multer)
  UNIQUE KEY uq_table_number (table_number)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- RESERVATIONS  (the CRUD resource)
--
-- Double-booking prevention lives in the APP, not the DB:
-- before INSERT/UPDATE, query live bookings for the chosen
-- table + date and reject a slot that is already taken --
--   WHERE table_id=? AND reservation_date=?
--     AND status IN ('pending','confirmed')
-- Cancelled/rejected rows stay for history but free the slot.
-- Wrap the availability check + write in a transaction so two
-- simultaneous bookings can't both pass the check.
-- ------------------------------------------------------------
CREATE TABLE reservations (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  user_id           INT   NOT NULL,
  table_id          INT   NOT NULL,
  reservation_date  DATE  NOT NULL,
  time_slot         TIME  NOT NULL,              -- one of the fixed app slots, e.g. 18:00:00
  party_size        INT   NOT NULL,
  remarks           VARCHAR(255) DEFAULT NULL,   -- optional customer note (seating, occasion, allergies)
  status            ENUM('pending','confirmed','rejected','cancelled')
                        NOT NULL DEFAULT 'pending',
  cancellation_reason VARCHAR(255) DEFAULT NULL, -- optional note captured when a booking is cancelled

  CONSTRAINT fk_res_user
      FOREIGN KEY (user_id)  REFERENCES users(id)             ON DELETE CASCADE,
  CONSTRAINT fk_res_table
      FOREIGN KEY (table_id) REFERENCES restaurant_tables(id) ON DELETE CASCADE,

  KEY idx_res_user   (user_id),
  KEY idx_res_lookup (table_id, reservation_date, time_slot)
) ENGINE=InnoDB;

-- ============================================================
-- SEED DATA
-- ============================================================

-- Accounts (passwords hashed with SHA1(password), same as app.js login/register)
--   admin@restaurant.com  /  admin        (role: admin — CHANGE THIS after first login via
--                                           Admin -> Change Password; it's a weak default
--                                           on purpose, not meant to stay in place)
--   demo@example.com      /  User@123    (role: user)
INSERT INTO users (name, email, password_hash, role) VALUES
('Site Admin',    'admin@restaurant.com', SHA1('admin'), 'admin'),
('Demo Customer', 'demo@example.com',     SHA1('User@123'),  'user');

-- Dining tables
INSERT INTO restaurant_tables (table_number, capacity, location) VALUES
('T1', 2,  'Window'),
('T2', 2,  'Indoor'),
('T3', 4,  'Indoor'),
('T4', 4,  'Outdoor'),
('T5', 6,  'Indoor'),
('T6', 8,  'Private Room');

-- Sample reservations (demo customer = user_id 2)
-- One confirmed + one pending so admin dashboard has data to manage.
INSERT INTO reservations
  (user_id, table_id, reservation_date, time_slot, party_size, remarks, status) VALUES
(2, 3, CURDATE() + INTERVAL 1 DAY, '19:00:00', 4, 'Window seat if possible', 'confirmed'),
(2, 1, CURDATE() + INTERVAL 2 DAY, '18:00:00', 2, NULL, 'pending');

-- ============================================================
-- Handy check query (optional, for manual testing)
-- Live bookings for a given table + date:
--   SELECT time_slot FROM reservations
--   WHERE table_id = 3 AND reservation_date = CURDATE() + INTERVAL 1 DAY
--     AND status IN ('pending','confirmed');
-- ============================================================

-- ============================================================
-- EXTRA DEMO DATA
-- More accounts, tables and reservations so every screen has
-- realistic content and the filters/sorting have data to work on.
-- ============================================================

-- ---- 3 more customers (all log in with password: User@123, hashed with SHA1) ----
INSERT INTO users (name, email, password_hash, role) VALUES
('Alice Tan',  'alice@example.com',
 SHA1('User@123'), 'user'),
('Ben Lee',    'ben@example.com',
 SHA1('User@123'), 'user'),
('Cara Wong',  'cara@example.com',
 SHA1('User@123'), 'user');

-- ---- 2 more tables (capacity variety) ----
INSERT INTO restaurant_tables (table_number, capacity, location) VALUES
('T7', 4,  'Outdoor'),
('T8', 10, 'Private Room');

-- ---- More reservations across every status + past/future dates ----
-- user_id / table_id resolved via sub-selects (id-safe).
INSERT INTO reservations (user_id, table_id, reservation_date, time_slot, party_size, remarks, status) VALUES
-- Demo Customer: a fuller personal history
((SELECT id FROM users WHERE email='demo@example.com'),  (SELECT id FROM restaurant_tables WHERE table_number='T5'), CURDATE() - INTERVAL 7 DAY,  '20:00:00', 5, 'Anniversary dinner',     'confirmed'),
((SELECT id FROM users WHERE email='demo@example.com'),  (SELECT id FROM restaurant_tables WHERE table_number='T2'), CURDATE() - INTERVAL 3 DAY,  '19:00:00', 2, NULL,                     'cancelled'),
((SELECT id FROM users WHERE email='demo@example.com'),  (SELECT id FROM restaurant_tables WHERE table_number='T4'), CURDATE() + INTERVAL 5 DAY,  '21:00:00', 4, 'Highchair needed',       'pending'),
-- Alice
((SELECT id FROM users WHERE email='alice@example.com'), (SELECT id FROM restaurant_tables WHERE table_number='T3'), CURDATE() + INTERVAL 1 DAY,  '18:00:00', 3, NULL,                     'confirmed'),
((SELECT id FROM users WHERE email='alice@example.com'), (SELECT id FROM restaurant_tables WHERE table_number='T6'), CURDATE() + INTERVAL 3 DAY,  '20:00:00', 7, 'Birthday - cake at 9pm', 'confirmed'),
((SELECT id FROM users WHERE email='alice@example.com'), (SELECT id FROM restaurant_tables WHERE table_number='T2'), CURDATE() + INTERVAL 4 DAY,  '17:00:00', 2, NULL,                     'rejected'),
-- Ben
((SELECT id FROM users WHERE email='ben@example.com'),   (SELECT id FROM restaurant_tables WHERE table_number='T4'), CURDATE() + INTERVAL 1 DAY,  '20:00:00', 4, 'Wheelchair access',      'pending'),
((SELECT id FROM users WHERE email='ben@example.com'),   (SELECT id FROM restaurant_tables WHERE table_number='T7'), CURDATE() + INTERVAL 6 DAY,  '19:00:00', 3, NULL,                     'confirmed'),
-- Cara
((SELECT id FROM users WHERE email='cara@example.com'),  (SELECT id FROM restaurant_tables WHERE table_number='T5'), CURDATE() + INTERVAL 2 DAY,  '18:00:00', 5, 'Nut allergy',            'confirmed'),
((SELECT id FROM users WHERE email='cara@example.com'),  (SELECT id FROM restaurant_tables WHERE table_number='T8'), CURDATE() + INTERVAL 10 DAY, '21:00:00', 9, 'Corporate dinner',       'pending');

-- Quick sanity counts after running:
--   SELECT status, COUNT(*) FROM reservations GROUP BY status;
