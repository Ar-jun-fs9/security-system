import { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import "./Auth.css";
import Login from "./Login";
import Register from "./Register";
import ForgotPassword from "./ForgotPassword";
import AdminForgotPassword from "./AdminForgotPassword";

const Auth = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [isRegisterPasswordActive, setIsRegisterPasswordActive] = useState(false);

  // Get the current tab from URL or default to 'login'
  const currentTab = searchParams.get("tab") || "login";

  const handleSwitchToLogin = (username) => {
    setSearchParams({ tab: "login" });
    setShowForgotPassword(false);
    setIsAdmin(false);
    setIsRegisterPasswordActive(false);
    if (username) {
      document.getElementById("loginUsername").value = username;
    }
  };

  const handleSwitchToRegister = () => {
    setSearchParams({ tab: "register" });
    setShowForgotPassword(false);
    setIsAdmin(false);
  };

  const handleForgotPassword = (isAdminUser = false) => {
    setShowForgotPassword(true);
    setIsAdmin(isAdminUser);
    setIsRegisterPasswordActive(false);
  };

  const handleRegisterPasswordActiveChange = (isActive) => {
    setIsRegisterPasswordActive(isActive);
  };

  // Update URL when tab changes
  useEffect(() => {
    if (!searchParams.get("tab")) {
      setSearchParams({ tab: "login" });
    }
  }, [searchParams, setSearchParams]);

  return (
    <div 
      className={`login-container ${currentTab === "register" ? "register-active" : ""} ${isRegisterPasswordActive && currentTab === "register" ? "register-password-active" : ""}`}
      id="authContainer"
    >
      {!showForgotPassword && (
        <div className="auth-header text-center mb-2">
          <i
            className="fas fa-shield-alt fa-3x mb-3"
            style={{ color: "var(--primary-color)" }}
          ></i>
          <h2 className="mb-0">Authentication System</h2>
          <p className="text-muted">Secure access to your account</p>
        </div>
      )}

      {!showForgotPassword && (
        <div id="authTabs" className="mb-4">
          <button
            className={`btn btn-outline-primary ${
              currentTab === "login" ? "active" : ""
            }`}
            onClick={() => setSearchParams({ tab: "login" })}
          >
            <i className="fas fa-sign-in-alt me-2"></i>Login
          </button>
          <button
            className={`btn btn-outline-primary ${
              currentTab === "register" ? "active" : ""
            }`}
            onClick={() => setSearchParams({ tab: "register" })}
          >
            <i className="fas fa-user-plus me-2"></i>Register
          </button>
        </div>
      )}

      {showForgotPassword ? (
        isAdmin ? (
          <AdminForgotPassword onBackToLogin={handleSwitchToLogin} />
        ) : (
          <ForgotPassword onBackToLogin={handleSwitchToLogin} />
        )
      ) : currentTab === "login" ? (
        <Login
          onSwitchToRegister={handleSwitchToRegister}
          onForgotPassword={handleForgotPassword}
          isActive={currentTab === "login"}
        />
      ) : (
        <Register
          onSwitchToLogin={handleSwitchToLogin}
          isActive={currentTab === "register"}
          onPasswordActiveChange={handleRegisterPasswordActiveChange}
        />
      )}
    </div>
  );
};

export default Auth;
