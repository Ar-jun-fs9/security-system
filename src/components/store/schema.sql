DROP TABLE IF EXISTS password_history;
DROP TABLE IF  EXISTS login_attempts; 
DROP TABLE IF  EXISTS otp_verification; 
DROP TABLE IF  EXISTS audit_log; 
DROP TABLE IF EXISTS added_user_by_admin;
DROP TABLE IF EXISTS deleted_user_by_admin;
DROP TABLE IF EXISTS forgot_password;
DROP TABLE IF EXISTS admin_users;
DROP TABLE IF EXISTS user_login;
DROP TABLE IF EXISTS user_register;
DROP TABLE IF EXISTS profile_update_history;



-- Create audit_log table
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    actor_id INTEGER,
    actor_type VARCHAR(10) CHECK (actor_type IN ('user', 'admin')),
    actor_username VARCHAR(50),
    target_email VARCHAR(100),
    target_username VARCHAR(50),
    action VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'
);

-- Add indexes for better performance
CREATE INDEX IF NOT EXISTS idx_audit_log_actor_id ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor_type ON audit_log(actor_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_time ON audit_log(event_time);
 

CREATE TABLE admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'admin',
    last_login TIMESTAMP WITHOUT TIME ZONE,
    login_count INTEGER DEFAULT 0,
    ip_address VARCHAR(45),
    user_agent TEXT,
    reset_token VARCHAR(255),
    reset_token_expiry TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    password_expiry TIMESTAMP WITHOUT TIME ZONE
);

-- Insert default admin user with the provided password hash and plain passowrd is aAbc@123
INSERT INTO admin_users (username, email, password_hash, role)
VALUES ('a@Admin', 'secure.seecurity.system@gmail.com', '$argon2id$v=19$m=16,t=2,p=1$YkVmZHR2TTRhTjdNeU44UQ$Eq5KQne1dUeCRT6pV4zzDw', 'super_admin');

CREATE TABLE user_register (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    register_method VARCHAR(20) NOT NULL CHECK (register_method IN ('email', 'google', 'github', 'local')),
    email_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255),
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    password_expiry TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE user_login (
    user_id INTEGER PRIMARY KEY REFERENCES user_register(id),
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    login_method VARCHAR(20) NOT NULL,
    login_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    login_count INTEGER DEFAULT 1,
    ip_address VARCHAR(45),
    user_agent TEXT
);


CREATE TABLE forgot_password (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES user_register(id),
    email VARCHAR(100) NOT NULL,
    reset_token VARCHAR(255),
    token_expiry TIMESTAMP WITHOUT TIME ZONE,
    password_change_date TIMESTAMP WITHOUT TIME ZONE DEFAULT NULL,
    password_change_count INTEGER DEFAULT 1,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE added_user_by_admin (
    id SERIAL PRIMARY KEY,
    admin_id INTEGER REFERENCES admin_users(id),
    user_id INTEGER REFERENCES user_register(id),
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    register_method VARCHAR(20) NOT NULL,
    role VARCHAR(10) NOT NULL CHECK (role IN ('admin', 'user')),
    admin_ip_address VARCHAR(45),
    admin_user_agent TEXT,
    added_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE deleted_user_by_admin (
    id SERIAL PRIMARY KEY,
    admin_id INTEGER REFERENCES admin_users(id),
    user_id INTEGER,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    register_method VARCHAR(20) NOT NULL,
    admin_ip_address VARCHAR(45),
    admin_user_agent TEXT,
    deleted_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create login_attempts table
CREATE TABLE  login_attempts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES user_register(id),
    username VARCHAR(255) NOT NULL,
    attempt_count INTEGER DEFAULT 0,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT FALSE,
    block_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_id ON login_attempts(user_id); 


-- Create otp_verification table
CREATE TABLE IF NOT EXISTS otp_verification (
    id SERIAL PRIMARY KEY,
     user_id INTEGER REFERENCES user_register(id),
    email VARCHAR(100) NOT NULL UNIQUE,
    otp VARCHAR(6) NOT NULL,
    expiry TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_otp_verification_email ON otp_verification(email);
CREATE INDEX IF NOT EXISTS idx_otp_verification_expiry ON otp_verification(expiry); 

-- Create password_history table
CREATE TABLE password_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES user_register(id),
    password_hash VARCHAR(255) NOT NULL,
    changed_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    changed_by VARCHAR(20) NOT NULL CHECK (changed_by IN ('user', 'admin', 'system')),
    metadata JSONB DEFAULT '{}'
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
CREATE INDEX IF NOT EXISTS idx_password_history_changed_at ON password_history(changed_at);

-- Create profile_update_history table
CREATE TABLE profile_update_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES user_register(id),
    old_username VARCHAR(50),
    new_username VARCHAR(50),
    old_email VARCHAR(100),
    new_email VARCHAR(100),
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    next_update_allowed TIMESTAMP WITHOUT TIME ZONE DEFAULT (CURRENT_TIMESTAMP + INTERVAL '2 months'),
    ip_address VARCHAR(45),
    user_agent TEXT
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_profile_update_history_user_id ON profile_update_history(user_id);
CREATE INDEX IF NOT EXISTS idx_profile_update_history_next_update ON profile_update_history(next_update_allowed);





