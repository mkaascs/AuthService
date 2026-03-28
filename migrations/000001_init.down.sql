-- Drop tables for user, user roles and refresh tokens

SET GLOBAL time_zone = 'SYSTEM';
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS users;