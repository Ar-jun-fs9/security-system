-- User registration trigger
DROP TRIGGER IF EXISTS after_user_register ON user_register;

-- User login trigger
DROP TRIGGER IF EXISTS after_user_login ON user_login;

-- Admin add/delete user triggers
DROP TRIGGER IF EXISTS after_admin_add_user ON added_user_by_admin;
DROP TRIGGER IF EXISTS after_admin_delete_user ON deleted_user_by_admin;

-- Login attempt trigger
DROP TRIGGER IF EXISTS after_login_attempt ON login_attempts;

-- OTP verification trigger
DROP TRIGGER IF EXISTS after_otp_verification ON otp_verification;

-- Admin login trigger
DROP TRIGGER IF EXISTS after_admin_login ON admin_users;

-- Admin password change trigger
DROP TRIGGER IF EXISTS after_admin_password_change ON admin_users;

-- User password change trigger
DROP TRIGGER IF EXISTS after_user_password_change ON user_register;


-- Drop Triggers
DROP TRIGGER IF EXISTS after_user_register ON user_register;
DROP TRIGGER IF EXISTS after_email_verification ON user_register;
DROP TRIGGER IF EXISTS after_admin_add_user ON added_user_by_admin;
DROP TRIGGER IF EXISTS after_admin_delete_user ON deleted_user_by_admin;
DROP TRIGGER IF EXISTS after_otp_verification ON otp_verification;
DROP TRIGGER IF EXISTS after_login_attempt ON login_attempts;
DROP TRIGGER IF EXISTS after_admin_login ON admin_users;
DROP TRIGGER IF EXISTS after_admin_password_change ON admin_users;
DROP TRIGGER IF EXISTS after_user_password_change ON user_register;
DROP TRIGGER IF EXISTS after_role_change ON added_user_by_admin;
DROP TRIGGER IF EXISTS after_profile_update ON user_register;

-- Drop Functions
DROP FUNCTION IF EXISTS log_user_registration();
DROP FUNCTION IF EXISTS log_email_verification_success();
DROP FUNCTION IF EXISTS log_admin_action();
DROP FUNCTION IF EXISTS log_otp_verification();
DROP FUNCTION IF EXISTS log_login_attempt();
DROP FUNCTION IF EXISTS log_admin_login();
DROP FUNCTION IF EXISTS log_admin_password_change();
DROP FUNCTION IF EXISTS log_user_password_change();
DROP FUNCTION IF EXISTS log_role_change();
DROP FUNCTION IF EXISTS log_profile_update();


CREATE OR REPLACE FUNCTION log_user_registration()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (
        actor_id,
        actor_type,
        actor_username,
        target_email,
        target_username,
        action,
        description,
        ip_address,
        user_agent,
        metadata
    ) VALUES (
        NEW.id,
        'user',
        NEW.username,
        NEW.email,
        NEW.username,
        'registration',
        'Registration attempt - email verification pending',
        '127.0.0.1',  -- You may replace this with a dynamic IP if available
        NULL,
        jsonb_build_object(
            'register_method', NEW.register_method,
            'verificationStatus', 'pending'
        )
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER after_user_register
AFTER INSERT ON user_register
FOR EACH ROW
EXECUTE FUNCTION log_user_registration();

CREATE OR REPLACE FUNCTION log_email_verification_success()
RETURNS TRIGGER AS $$
BEGIN
    -- Only log when the email_verified flag is changed from false to true
    IF NEW.email_verified = true AND OLD.email_verified IS DISTINCT FROM true THEN
        INSERT INTO audit_log (
            actor_id,
            actor_type,
            actor_username,
            target_email,
            target_username,
            action,
            description,
            ip_address,
            user_agent,
            metadata
        ) VALUES (
            NEW.id,
            'user',
            NEW.username,
            NEW.email,
            NEW.username,
            'email_verification',
            'Registration successful - email verified',
            '127.0.0.1',  -- Replace with actual IP if available
            NULL,
            jsonb_build_object(
                'register_method', NEW.register_method,
                'verificationStatus', 'verified'
            )
        );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER after_email_verification
AFTER UPDATE ON user_register
FOR EACH ROW
EXECUTE FUNCTION log_email_verification_success();

CREATE OR REPLACE FUNCTION log_admin_action()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (
        actor_id, actor_type, actor_username, target_email, target_username,
        action, description, ip_address, user_agent, metadata
    ) VALUES (
        NEW.admin_id, 'admin', (SELECT username FROM admin_users WHERE id = NEW.admin_id),
        NEW.email, NEW.username,
        CASE
            WHEN TG_TABLE_NAME = 'added_user_by_admin' THEN 'admin_add_user'
            WHEN TG_TABLE_NAME = 'deleted_user_by_admin' THEN 'admin_delete_user'
        END,
        CASE
            WHEN TG_TABLE_NAME = 'added_user_by_admin' THEN 'Admin added new user'
            WHEN TG_TABLE_NAME = 'deleted_user_by_admin' THEN 'Admin deleted user'
        END,
        NEW.admin_ip_address, NEW.admin_user_agent,
        jsonb_build_object('register_method', NEW.register_method, 'admin_id', NEW.admin_id)
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER after_admin_add_user
AFTER INSERT ON added_user_by_admin
FOR EACH ROW
EXECUTE FUNCTION log_admin_action();

CREATE TRIGGER after_admin_delete_user
AFTER INSERT ON deleted_user_by_admin
FOR EACH ROW
EXECUTE FUNCTION log_admin_action();

CREATE OR REPLACE FUNCTION log_otp_verification()
RETURNS TRIGGER AS $$
DECLARE
    user_name TEXT;
    user_id INTEGER;
BEGIN
    -- Look up the user ID and username from the user_register table using the email
    SELECT id, username INTO user_id, user_name FROM user_register WHERE email = NEW.email;

    -- Insert into audit_log with the fetched username and user_id
    INSERT INTO audit_log (
        actor_id, actor_type, actor_username, target_email, target_username,
        action, description, ip_address, user_agent, metadata
    ) VALUES (
        user_id,
        'user',
        user_name,
        NEW.email,
        user_name,
        'otp_verification',
        'OTP verification attempt',
        '127.0.0.1',
        NULL,
        jsonb_build_object('otp', NEW.otp, 'expiry', NEW.expiry)
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER after_otp_verification
AFTER INSERT OR UPDATE ON otp_verification
FOR EACH ROW
EXECUTE FUNCTION log_otp_verification();

CREATE OR REPLACE FUNCTION log_login_attempt()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (
        actor_id, actor_type, actor_username, target_email, target_username,
        action, description, ip_address, user_agent, metadata
    ) VALUES (
        NEW.user_id, 'user', NEW.username, NEW.email, NEW.username,
        CASE
            WHEN NEW.is_blocked THEN 'login_blocked'
            ELSE 'login_attempt'
        END,
        CASE
            WHEN NEW.is_blocked THEN 'User login attempt blocked'
            ELSE 'User login attempt'
        END,
        NEW.ip_address, NEW.user_agent,
        jsonb_build_object('attempt_count', NEW.attempt_count, 'is_blocked', NEW.is_blocked)
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create function to log admin login
CREATE OR REPLACE FUNCTION log_admin_login()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (
        actor_id,
        actor_type,
        actor_username,
        target_email,
        target_username,
        action,
        description,
        ip_address,
        user_agent,
        metadata
    ) VALUES (
        NEW.id,
        'admin',
        NEW.username,
        NEW.email,
        NEW.username,
        'admin_login',
        'Admin login via local',
        NEW.ip_address,
        NEW.user_agent,
        jsonb_build_object(
            'login_count', NEW.login_count,
            'last_login', NEW.last_login
        )
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for admin login
CREATE TRIGGER after_admin_login
    AFTER UPDATE OF last_login ON admin_users
    FOR EACH ROW
    WHEN (NEW.last_login IS NOT NULL)
    EXECUTE FUNCTION log_admin_login();

-- Update admin password change function
CREATE OR REPLACE FUNCTION log_admin_password_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.password_hash IS DISTINCT FROM NEW.password_hash THEN
        -- Insert into password history
        INSERT INTO password_history (user_id, password_hash, changed_by)
        VALUES (NEW.id, NEW.password_hash, 'admin');

        -- Set password expiry to 90 days from now
        NEW.password_expiry = CURRENT_TIMESTAMP + INTERVAL '90 days';

        INSERT INTO audit_log (
            actor_id,
            actor_type,
            actor_username,
            target_email,
            target_username,
            action,
            description,
            ip_address,
            user_agent,
            metadata
        ) VALUES (
            NEW.id,
            'admin',
            NEW.username,
            NEW.email,
            NEW.username,
            'admin_password_change',
            'Admin changed password',
            '127.0.0.1',
            NULL,
            jsonb_build_object(
                'change_time', CURRENT_TIMESTAMP
            )
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for admin password change
CREATE TRIGGER after_admin_password_change
    AFTER UPDATE OF password_hash ON admin_users
    FOR EACH ROW
    EXECUTE FUNCTION log_admin_password_change();

-- Create function to log user password change
CREATE OR REPLACE FUNCTION log_user_password_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.password_hash IS DISTINCT FROM NEW.password_hash THEN
        INSERT INTO audit_log (
            actor_id,
            actor_type,
            actor_username,
            target_email,
            target_username,
            action,
            description,
            ip_address,
            user_agent,
            metadata
        ) VALUES (
            NEW.id,
            'user',
            NEW.username,
            NEW.email,
            NEW.username,
            'password_change',
            'User changed password',
            '127.0.0.1',
            NULL,
            jsonb_build_object(
                'change_time', CURRENT_TIMESTAMP,
                'change_method', 'forgot_password'
            )
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for user password change
CREATE TRIGGER after_user_password_change
    AFTER UPDATE OF password_hash ON user_register
    FOR EACH ROW
    EXECUTE FUNCTION log_user_password_change();



-- Create function to log role changes
CREATE OR REPLACE FUNCTION log_role_change()
RETURNS TRIGGER AS $$
BEGIN
    -- Only log when role is actually changed
    IF OLD.role IS DISTINCT FROM NEW.role THEN
        INSERT INTO audit_log (
            actor_id,
            actor_type,
            actor_username,
            target_email,
            target_username,
            action,
            description,
            ip_address,
            user_agent,
            metadata
        ) VALUES (
            NEW.admin_id,
            'admin',
            (SELECT username FROM admin_users WHERE id = NEW.admin_id),
            NEW.email,
            NEW.username,
            'role_change',
            CASE 
                WHEN NEW.role = 'admin' THEN 'User role changed to admin'
                ELSE 'Admin role changed to user'
            END,
            NEW.admin_ip_address,
            NEW.admin_user_agent,
            jsonb_build_object(
                'old_role', OLD.role,
                'new_role', NEW.role,
                'change_time', CURRENT_TIMESTAMP,
                'admin_id', NEW.admin_id
            )
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for role changes
CREATE TRIGGER after_role_change
    AFTER UPDATE OF role ON added_user_by_admin
    FOR EACH ROW
    EXECUTE FUNCTION log_role_change();

-- Create function to log profile updates
CREATE OR REPLACE FUNCTION log_profile_update()
RETURNS TRIGGER AS $$
BEGIN
    -- Only log when username or email is actually changed
    IF (OLD.username IS DISTINCT FROM NEW.username) OR (OLD.email IS DISTINCT FROM NEW.email) THEN
        INSERT INTO audit_log (
            actor_id,
            actor_type,
            actor_username,
            target_email,
            target_username,
            action,
            description,
            ip_address,
            user_agent,
            metadata
        ) VALUES (
            NEW.id,
            'user',
            NEW.username,
            NEW.email,
            NEW.username,
            'profile_update',
            'User updated profile information',
            '127.0.0.1', -- Replace with actual IP if available
            NULL,
            jsonb_build_object(
                'old_username', OLD.username,
                'new_username', NEW.username,
                'old_email', OLD.email,
                'new_email', NEW.email,
                'update_time', CURRENT_TIMESTAMP
            )
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for profile updates
CREATE TRIGGER after_profile_update
    AFTER UPDATE OF username, email ON user_register
    FOR EACH ROW
    EXECUTE FUNCTION log_profile_update();




