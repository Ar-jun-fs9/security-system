import { useState, useEffect } from "react";
import ReCAPTCHA from "react-google-recaptcha";
import zxcvbn from "zxcvbn";
import { api } from "../../services/api";
import "./Auth.css";
import { useNavigate } from "react-router-dom";
import { FaArrowLeft } from "react-icons/fa";

const Register = ({ onSwitchToLogin, isActive, onPasswordActiveChange }) => {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState({
    strength: 0,
    text: "Weak",
    feedback: "",
  });
  const [requirements, setRequirements] = useState({
    length: false,
    uppercase: false,
    lowercase: false,
    number: false,
    special: false,
    noWhitespace: false,
  });
  const [isCaptchaVerified, setIsCaptchaVerified] = useState(false);
  const [error, setError] = useState("");
  const [usernameError, setUsernameError] = useState("");
  const [emailError, setEmailError] = useState("");
  const [isVerifying, setIsVerifying] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [passwordCharLimitError, setPasswordCharLimitError] = useState("");
  const [passwordFormatError, setPasswordFormatError] = useState("");
  const [passwordUsernameError, setPasswordUsernameError] = useState("");
  const [tempEmailError, setTempEmailError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const interval = setInterval(() => {
      if (window.NBP) {
        window.NBP.init("mostcommon_100000", "/collections/", true);
        clearInterval(interval);
      }
    }, 100);
  }, []);

  useEffect(() => {
    if (isActive) {
      setFormData({
        username: "",
        email: "",
        password: "",
        confirmPassword: "",
      });
      setShowPassword(false);
      setShowConfirmPassword(false);
      setPasswordStrength({ strength: 0, text: "Weak", feedback: "" });
      setRequirements({
        length: false,
        uppercase: false,
        lowercase: false,
        number: false,
        special: false,
        noWhitespace: false,
      });
      setIsCaptchaVerified(false);
      setError("");
    }
  }, [isActive]);

  const hasSequentialChars = (str) => {
    if (!str || str.length < 3) return false;
    for (let i = 0; i < str.length - 2; i++) {
      const a = str.charCodeAt(i);
      const b = str.charCodeAt(i + 1);
      const c = str.charCodeAt(i + 2);
      if ((b === a + 1 && c === b + 1) || (b === a - 1 && c === b - 1))
        return true;
    }
    return false;
  };

  const hasRepeatedChars = (str) => /(.)\1\1/.test(str);

  const getPasswordRequirements = (password) => ({
    length: password.length >= 15,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    noWhitespace: !/\s/.test(password),
  });

  useEffect(() => {
    const pwd = formData.password;
    if (pwd.length === 0) {
      setPasswordStrength({ strength: 0, text: "Weak", feedback: "" });
      setRequirements({
        length: false,
        uppercase: false,
        lowercase: false,
        number: false,
        special: false,
        noWhitespace: false,
      });
      return;
    }

    const currentRequirements = getPasswordRequirements(pwd);
    setRequirements(currentRequirements);

    const zxcvbnResult = zxcvbn(pwd);
    const score = zxcvbnResult.score;
    const feedback = [
      zxcvbnResult.feedback.warning,
      ...zxcvbnResult.feedback.suggestions,
    ]
      .filter(Boolean)
      .join(" ");

    const strengthTexts = [
      "Very Weak",
      "Weak",
      "Fair",
      "Strong",
      "Very Strong",
    ];
    const strengthText = strengthTexts[score] || "Weak";

    setPasswordStrength({ strength: score, text: strengthText, feedback });
  }, [formData.password]);

  const handleInputChange = (e) => {
    const { id, value } = e.target;
    setFormData((prev) => ({ ...prev, [id]: value }));

    if (id === "username") {
      // Clear error if input is empty
      if (!value.trim()) {
        setUsernameError("");
        return;
      }

      // Check length first
      if (value.length < 5 || value.length > 25) {
        setUsernameError("Username must be between 5 and 25 characters");
        return;
      }

      // Check for valid characters
      if (!/^[a-zA-Z0-9@]+$/.test(value)) {
        setUsernameError(
          "Username can only contain letters, numbers, and @ symbol"
        );
        return;
      }

      // If all validations pass
      setUsernameError("");

      // Also re-validate password-username rule if password exists
      if (
        formData.password &&
        value &&
        formData.password.toLowerCase().includes(value.toLowerCase())
      ) {
        setPasswordUsernameError("Password must not contain the username.");
      } else {
        setPasswordUsernameError("");
      }
    }

    if (id === "email") {
      // Clear error if input is empty
      if (!value.trim()) {
        setEmailError("");
        return;
      }

      // Convert email to lowercase
      const lowercaseEmail = value.toLowerCase();
      setFormData((prev) => ({ ...prev, email: lowercaseEmail }));

      // Email validation regex
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(lowercaseEmail)) {
        setEmailError("Please enter a valid email address");
        return;
      }

      // If all validations pass
      setEmailError("");

      if (value && isTemporaryEmail(value)) {
        setTempEmailError(
          "Please don't use a temporary email, use a valid email."
        );
      } else {
        setTempEmailError("");
      }
    }

    if (id === "password") {
      onPasswordActiveChange(value.length > 0);
      // Password char limit check
      if (value.length > 25) {
        setPasswordCharLimitError(
          "Password must be between 15 and 25 characters."
        );
      } else {
        setPasswordCharLimitError("");
      }
      // Password must not be email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (emailRegex.test(value)) {
        setPasswordFormatError("Password must not be in email format.");
      } else {
        setPasswordFormatError("");
      }
      // Password must not contain username
      if (
        formData.username &&
        value.toLowerCase().includes(formData.username.toLowerCase())
      ) {
        setPasswordUsernameError("Password must not contain the username.");
      } else {
        setPasswordUsernameError("");
      }
    }
  };

  const validateUsername = (username) => {
    if (!username.trim()) {
      setUsernameError("Username is required");
      return false;
    }
    if (username.length < 5 || username.length > 25) {
      setUsernameError("Username must be between 5 and 25 characters");
      return false;
    }
    if (!/^[a-zA-Z0-9@]+$/.test(username)) {
      setUsernameError(
        "Username can only contain letters, numbers, and @ symbol"
      );
      return false;
    }
    setUsernameError("");
    return true;
  };

  const validateEmail = (email) => {
    if (!email.trim()) {
      setEmailError("Email is required");
      return false;
    }
    const lowercaseEmail = email.toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(lowercaseEmail)) {
      setEmailError("Please enter a valid email address");
      return false;
    }
    setEmailError("");
    return true;
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    const { username, email, password, confirmPassword } = formData;

    // Temp email check
    if (isTemporaryEmail(email)) {
      setError("Please don't use a temporary email, use a valid email.");
      setIsLoading(false);
      return;
    }

    // Password length check (15-25 chars)
    if (password.length < 15 || password.length > 25) {
      setError("Password must be between 15 and 25 characters.");
      setIsLoading(false);
      return;
    }

    // Password must not be in email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (emailRegex.test(password)) {
      setError("Password must not be in email format.");
      setIsLoading(false);
      return;
    }

    // Password must not contain username
    if (username && password.toLowerCase().includes(username.toLowerCase())) {
      setError("Password must not contain the username.");
      setIsLoading(false);
      return;
    }

    if (!validateUsername(username)) {
      setError(usernameError);
      setIsLoading(false);
      return;
    }

    if (!validateEmail(email)) {
      setError(emailError);
      setIsLoading(false);
      return;
    }

    const isCommon = window.NBP?.isCommonPassword(password);
    const currentRequirements = getPasswordRequirements(password);
    const allRequirementsMet =
      Object.values(currentRequirements).every(Boolean);

    if (!isCaptchaVerified) {
      setError("Please complete the reCAPTCHA verification!");
      setIsLoading(false);
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match!");
      setIsLoading(false);
      return;
    }

    if (isCommon) {
      setError("This password is too common. Please use a stronger one.");
      setIsLoading(false);
      return;
    }

    if (!allRequirementsMet) {
      setError(
        "Please meet all password requirements (15+ chars, uppercase, lowercase, number, special char, no whitespace)."
      );
      setIsLoading(false);
      return;
    }

    if (hasRepeatedChars(password)) {
      setError("Password contains repeated characters.");
      setIsLoading(false);
      return;
    }

    if (hasSequentialChars(password)) {
      setError("Password contains sequential characters eg(abc or 123).");
      setIsLoading(false);
      return;
    }

    if (passwordStrength.strength < 3) {
      setError(
        `Password strength is ${passwordStrength.text}. ${passwordStrength.feedback}`
      );
      setIsLoading(false);
      return;
    }

    try {
      const response = await api.register(username, email, password);

      if (response.error) {
        setError(response.error);
        setIsLoading(false);
        return;
      }

      if (response.requiresVerification) {
        setIsVerifying(true);
        setIsLoading(false);
        // Show success message
        const successMessage = document.createElement("div");
        successMessage.className = "success-message";
        successMessage.innerHTML = `
          <i class="fas fa-envelope"></i>
          <span>Verification email sent! Please check your inbox.</span>
        `;
        document.body.appendChild(successMessage);

        setTimeout(() => {
          successMessage.remove();
        }, 5000);
      }
    } catch (error) {
      setError("Registration failed. Please try again.");
      setIsLoading(false);
    }
  };

  const handleCaptchaChange = (value) => {
    setIsCaptchaVerified(!!value);
  };

  const handleSocialRegister = (provider) => {
    // Implement social registration functionality
    alert(`${provider} registration will be implemented soon!`);
  };

  const handleResendVerification = async () => {
    setIsLoading(true);
    try {
      const response = await api.resendVerification(formData.email);
      if (response.error) {
        setError(response.error);
      } else {
        // Show success message
        const successMessage = document.createElement("div");
        successMessage.className = "success-message";
        successMessage.innerHTML = `
          <i class="fas fa-envelope"></i>
          <span>Verification email resent! Please check your inbox.</span>
        `;
        document.body.appendChild(successMessage);

        setTimeout(() => {
          successMessage.remove();
        }, 5000);
      }
    } catch (error) {
      setError("Failed to resend verification email. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  // Utility function to detect temp/disposable email
  const isTemporaryEmail = (email) => {
    // Common patterns for temp/disposable emails
    const tempPatterns = [
      /mailinator\.com$/i,
      /guerrillamail\.com$/i,
      /10minutemail\.com$/i,
      /tempmail\./i,
      /disposablemail\./i,
      /yopmail\.com$/i,
      /fakeinbox\./i,
      /trashmail\./i,
      /maildrop\.cc$/i,
      /getnada\.com$/i,
      /sharklasers\.com$/i,
      // /@fmail\d*\.com$/i, // suspicious gmail variants
      /@ggmail\./i, // suspicious ggmail variants
      /@gmaill\./i, // suspicious gmaill variants
      /@emailtemp\./i,
      /@temp-mail\./i,
      /@tempail\./i,
      /@tempemail\./i,
      /@tempmailaddress\./i,
      /@tempmailbox\./i,
      /@tempm\./i,
      /@temporarymail\./i,
      /@throwawaymail\./i,
      /@trashmail\./i,
      /@dispostable\./i,
      /@mail-temporaire\./i,
      /@mail-temporaire\.fr$/i,
      /@mail-temporaire\.com$/i,
      /@mail-temporaire\.net$/i,
      /@mail-temporaire\.org$/i,
      /@mail-temporaire\.co$/i,
      /@mail-temporaire\.info$/i,
      /@mail-temporaire\.biz$/i,
      /@mail-temporaire\.eu$/i,
      /@mail-temporaire\.us$/i,
      /@mail-temporaire\.uk$/i,
      /@mail-temporaire\.ca$/i,
      /@mail-temporaire\.de$/i,
      /@mail-temporaire\.es$/i,
      /@mail-temporaire\.it$/i,
      /@mail-temporaire\.nl$/i,
      /@mail-temporaire\.ru$/i,
      /@mail-temporaire\.ch$/i,
      /@mail-temporaire\.be$/i,
      /@mail-temporaire\.pl$/i,
      /@mail-temporaire\.se$/i,
      /@mail-temporaire\.no$/i,
      /@mail-temporaire\.fi$/i,
      /@mail-temporaire\.dk$/i,
      /@mail-temporaire\.cz$/i,
      /@mail-temporaire\.sk$/i,
      /@mail-temporaire\.hu$/i,
      /@mail-temporaire\.tr$/i,
      /@mail-temporaire\.gr$/i,
      /@mail-temporaire\.ro$/i,
      /@mail-temporaire\.bg$/i,
      /@mail-temporaire\.lt$/i,
      /@mail-temporaire\.lv$/i,
      /@mail-temporaire\.ee$/i,
      /@mail-temporaire\.ua$/i,
      /@mail-temporaire\.by$/i,
      /@mail-temporaire\.kz$/i,
      /@mail-temporaire\.il$/i,
      /@mail-temporaire\.in$/i,
      /@mail-temporaire\.pk$/i,
      /@mail-temporaire\.bd$/i,
      /@mail-temporaire\.lk$/i,
      /@mail-temporaire\.np$/i,
      /@mail-temporaire\.af$/i,
      /@mail-temporaire\.ir$/i,
      /@mail-temporaire\.iq$/i,
      /@mail-temporaire\.sy$/i,
      /@mail-temporaire\.jo$/i,
      /@mail-temporaire\.lb$/i,
      /@mail-temporaire\.sa$/i,
      /@mail-temporaire\.ae$/i,
      /@mail-temporaire\.qa$/i,
      /@mail-temporaire\.kw$/i,
      /@mail-temporaire\.om$/i,
      /@mail-temporaire\.bh$/i,
      /@mail-temporaire\.ye$/i,
      /@mail-temporaire\.eg$/i,
      /@mail-temporaire\.ma$/i,
      /@mail-temporaire\.dz$/i,
      /@mail-temporaire\.tn$/i,
      /@mail-temporaire\.ly$/i,
      /@mail-temporaire\.sd$/i,
      /@mail-temporaire\.ss$/i,
      /@mail-temporaire\.et$/i,
      /@mail-temporaire\.ke$/i,
      /@mail-temporaire\.ug$/i,
      /@mail-temporaire\.tz$/i,
      /@mail-temporaire\.rw$/i,
      /@mail-temporaire\.bi$/i,
      /@mail-temporaire\.mw$/i,
      /@mail-temporaire\.zm$/i,
      /@mail-temporaire\.zw$/i,
      /@mail-temporaire\.mz$/i,
      /@mail-temporaire\.ao$/i,
      /@mail-temporaire\.na$/i,
      /@mail-temporaire\.bw$/i,
      /@mail-temporaire\.sz$/i,
      /@mail-temporaire\.ls$/i,
      /@mail-temporaire\.za$/i,
      /@mail-temporaire\.cm$/i,
      /@mail-temporaire\.gh$/i,
      /@mail-temporaire\.ng$/i,
      /@mail-temporaire\.sn$/i,
      /@mail-temporaire\.ml$/i,
      /@mail-temporaire\.bf$/i,
      /@mail-temporaire\.ne$/i,
      /@mail-temporaire\.tg$/i,
      /@mail-temporaire\.bj$/i,
      /@mail-temporaire\.ci$/i,
      /@mail-temporaire\.sl$/i,
      /@mail-temporaire\.lr$/i,
      /@mail-temporaire\.gw$/i,
      /@mail-temporaire\.gm$/i,
      /@mail-temporaire\.cv$/i,
      /@mail-temporaire\.st$/i,
      /@mail-temporaire\.gq$/i,
      /@mail-temporaire\.ga$/i,
      /@mail-temporaire\.cg$/i,
      /@mail-temporaire\.cd$/i,
      /@mail-temporaire\.ao$/i,
      /@mail-temporaire\.mg$/i,
      /@mail-temporaire\.mu$/i,
      /@mail-temporaire\.sc$/i,
      /@mail-temporaire\.km$/i,
      /@mail-temporaire\.yt$/i,
      /@mail-temporaire\.re$/i,
      /@mail-temporaire\.pm$/i,
      /@mail-temporaire\.wf$/i,
      /@mail-temporaire\.pf$/i,
      /@mail-temporaire\.nc$/i,
      /@mail-temporaire\.vu$/i,
      /@mail-temporaire\.sb$/i,
      /@mail-temporaire\.pg$/i,
      /@mail-temporaire\.fj$/i,
      /@mail-temporaire\.to$/i,
      /@mail-temporaire\.ws$/i,
      /@mail-temporaire\.as$/i,
      /@mail-temporaire\.ck$/i,
      /@mail-temporaire\.nu$/i,
      /@mail-temporaire\.tk$/i,
      /@mail-temporaire\.tv$/i,
      /@mail-temporaire\.fm$/i,
      /@mail-temporaire\.mh$/i,
      /@mail-temporaire\.pw$/i,
      /@mail-temporaire\.nr$/i,
      /@mail-temporaire\.ki$/i,
      /@mail-temporaire\.cc$/i,
      /@mail-temporaire\.cx$/i,
      /@mail-temporaire\.nf$/i,
      /@mail-temporaire\.hm$/i,
      /@mail-temporaire\.gs$/i,
      /@mail-temporaire\.aq$/i,
      /@mail-temporaire\.bv$/i,
      /@mail-temporaire\.sj$/i,
      /@mail-temporaire\.tf$/i,
      /@mail-temporaire\.um$/i,
      /@mail-temporaire\.wf$/i,
      /@mail-temporaire\.yt$/i,
      /@mail-temporaire\.pm$/i,
      /@mail-temporaire\.re$/i,
      /@mail-temporaire\.sc$/i,
      /@mail-temporaire\.mu$/i,
      /@mail-temporaire\.mg$/i,
      /@mail-temporaire\.ao$/i,
      /@mail-temporaire\.cd$/i,
      /@mail-temporaire\.cg$/i,
      /@mail-temporaire\.ga$/i,
      /@mail-temporaire\.gq$/i,
      /@mail-temporaire\.st$/i,
      /@mail-temporaire\.cv$/i,
      /@mail-temporaire\.gm$/i,
      /@mail-temporaire\.gw$/i,
      /@mail-temporaire\.lr$/i,
      /@mail-temporaire\.sl$/i,
      /@mail-temporaire\.ci$/i,
      /@mail-temporaire\.bj$/i,
      /@mail-temporaire\.tg$/i,
      /@mail-temporaire\.ne$/i,
      /@mail-temporaire\.bf$/i,
      /@mail-temporaire\.ml$/i,
      /@mail-temporaire\.sn$/i,
      /@mail-temporaire\.ng$/i,
      /@mail-temporaire\.gh$/i,
      /@mail-temporaire\.cm$/i,
      /@mail-temporaire\.za$/i,
      /@mail-temporaire\.ls$/i,
      /@mail-temporaire\.sz$/i,
      /@mail-temporaire\.bw$/i,
      /@mail-temporaire\.na$/i,
      /@mail-temporaire\.ao$/i,
      /@mail-temporaire\.mz$/i,
      /@mail-temporaire\.zw$/i,
      /@mail-temporaire\.zm$/i,
      /@mail-temporaire\.mw$/i,
      /@mail-temporaire\.bi$/i,
      /@mail-temporaire\.rw$/i,
      /@mail-temporaire\.tz$/i,
      /@mail-temporaire\.ug$/i,
      /@mail-temporaire\.ke$/i,
      /@mail-temporaire\.et$/i,
      /@mail-temporaire\.ss$/i,
      /@mail-temporaire\.sd$/i,
      /@mail-temporaire\.ly$/i,
      /@mail-temporaire\.tn$/i,
      /@mail-temporaire\.dz$/i,
      /@mail-temporaire\.ma$/i,
      /@mail-temporaire\.eg$/i,
      /@mail-temporaire\.ye$/i,
      /@mail-temporaire\.bh$/i,
      /@mail-temporaire\.om$/i,
      /@mail-temporaire\.kw$/i,
      /@mail-temporaire\.qa$/i,
      /@mail-temporaire\.ae$/i,
      /@mail-temporaire\.sa$/i,
      /@mail-temporaire\.lb$/i,
      /@mail-temporaire\.jo$/i,
      /@mail-temporaire\.sy$/i,
      /@mail-temporaire\.iq$/i,
      /@mail-temporaire\.ir$/i,
      /@mail-temporaire\.af$/i,
      /@mail-temporaire\.np$/i,
      /@mail-temporaire\.lk$/i,
      /@mail-temporaire\.bd$/i,
      /@mail-temporaire\.pk$/i,
      /@mail-temporaire\.in$/i,
      /@mail-temporaire\.il$/i,
      /@mail-temporaire\.kz$/i,
      /@mail-temporaire\.by$/i,
      /@mail-temporaire\.ua$/i,
      /@mail-temporaire\.ee$/i,
      /@mail-temporaire\.lv$/i,
      /@mail-temporaire\.lt$/i,
      /@mail-temporaire\.bg$/i,
      /@mail-temporaire\.ro$/i,
      /@mail-temporaire\.gr$/i,
      /@mail-temporaire\.tr$/i,
      /@mail-temporaire\.hu$/i,
      /@mail-temporaire\.sk$/i,
      /@mail-temporaire\.cz$/i,
      /@mail-temporaire\.dk$/i,
      /@mail-temporaire\.fi$/i,
      /@mail-temporaire\.no$/i,
      /@mail-temporaire\.se$/i,
      /@mail-temporaire\.pl$/i,
      /@mail-temporaire\.be$/i,
      /@mail-temporaire\.ch$/i,
      /@mail-temporaire\.ru$/i,
      /@mail-temporaire\.nl$/i,
      /@mail-temporaire\.it$/i,
      /@mail-temporaire\.es$/i,
      /@mail-temporaire\.de$/i,
      /@mail-temporaire\.ca$/i,
      /@mail-temporaire\.uk$/i,
      /@mail-temporaire\.us$/i,
      /@mail-temporaire\.biz$/i,
      /@mail-temporaire\.info$/i,
      /@mail-temporaire\.co$/i,
      /@mail-temporaire\.org$/i,
      /@mail-temporaire\.net$/i,
      /@mail-temporaire\.com$/i,
    ];
    return tempPatterns.some((pattern) => pattern.test(email));
  };

  return (
    <div className="auth-container">
      <div className="auth-form-container">
        <button
          className="btn btn-link position-absolute top-0 start-0  text-decoration-none"
          onClick={() => navigate("/")}
          style={{ color: "#0d6efd" }}
        >
          <FaArrowLeft className="me-2" />
        </button>

        <div id="registerForm" className="auth-form">
          <form id="registerFormElement" onSubmit={handleRegister}>
            <div className="row mb-3">
              <div className="col-md-6">
                <label htmlFor="username" className="form-label">
                  <i className="fas fa-user me-2"></i>Username
                </label>
                <input
                  type="text"
                  className={`form-control ${
                    usernameError ? "is-invalid" : ""
                  }`}
                  id="username"
                  autoComplete="off"
                  required
                  value={formData.username}
                  onChange={handleInputChange}
                />
                {usernameError && (
                  <div className="invalid-feedback">{usernameError}</div>
                )}
              </div>

              <div className="col-md-6">
                <label htmlFor="email" className="form-label">
                  <i className="fas fa-envelope me-2"></i>Email
                </label>
                <input
                  type="email"
                  className={`form-control ${emailError ? "is-invalid" : ""}`}
                  id="email"
                  autoComplete="off"
                  required
                  value={formData.email}
                  onChange={handleInputChange}
                />
                {emailError && (
                  <div className="invalid-feedback">{emailError}</div>
                )}
                {tempEmailError && (
                  <div
                    className="invalid-feedback d-block"
                    style={{ color: "red" }}
                  >
                    {tempEmailError}
                  </div>
                )}
              </div>
            </div>

            <div className="row mb-2">
              <div className="col-md-6">
                <label htmlFor="password" className="form-label">
                  <i className="fas fa-lock me-2"></i>Password
                </label>
                <div className="password-input-container">
                  <input
                    type={showPassword ? "text" : "password"}
                    className="form-control"
                    id="password"
                    required
                    value={formData.password}
                    onChange={handleInputChange}
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={
                      showPassword ? "Hide password" : "Show password"
                    }
                  >
                    <i
                      className={`fas fa-${showPassword ? "eye-slash" : "eye"}`}
                    ></i>
                  </button>
                </div>
                {passwordCharLimitError && (
                  <div
                    className="invalid-feedback d-block"
                    style={{ color: "red" }}
                  >
                    {passwordCharLimitError}
                  </div>
                )}
                {passwordFormatError && (
                  <div
                    className="invalid-feedback d-block"
                    style={{ color: "red" }}
                  >
                    {passwordFormatError}
                  </div>
                )}
                {passwordUsernameError && (
                  <div
                    className="invalid-feedback d-block"
                    style={{ color: "red" }}
                  >
                    {passwordUsernameError}
                  </div>
                )}
              </div>

              <div className="col-md-6">
                <label htmlFor="confirmPassword" className="form-label">
                  <i className="fas fa-lock me-2"></i>Confirm Password
                </label>
                <div className="password-input-container">
                  <input
                    id="confirmPassword"
                    type={showConfirmPassword ? "text" : "password"}
                    className="form-control"
                    required
                    value={formData.confirmPassword}
                    onChange={handleInputChange}
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    aria-label={
                      showConfirmPassword
                        ? "Hide confirm password"
                        : "Show confirm password"
                    }
                  >
                    <i
                      className={`fas fa-${
                        showConfirmPassword ? "eye-slash" : "eye"
                      }`}
                    ></i>
                  </button>
                </div>
              </div>
            </div>

            {formData.password && (
              <div className="row mb-2">
                <div className="col-md-12">
                  <div className="password-strength-container">
                    <div className="strength-label">
                      <span>Password Strength</span>
                      <span
                        className={`strength-text strength-${passwordStrength.text
                          .toLowerCase()
                          .replace(/\s/g, "")}`}
                      >
                        {passwordStrength.text}
                      </span>
                    </div>
                    <div
                      className={`password-strength strength-${passwordStrength.text
                        .toLowerCase()
                        .replace(/\s/g, "")}`}
                    ></div>
                    {passwordStrength.feedback && (
                      <div
                        className="password-feedback mt-2"
                        style={{ color: "red" }}
                      >
                        {passwordStrength.feedback}
                      </div>
                    )}
                  </div>
                  <div className="requirements mt-3">
                    {[
                      { key: "length", text: "At least 15 characters" },
                      { key: "uppercase", text: "Uppercase Letter" },
                      { key: "lowercase", text: "Lowercase Letter" },
                      { key: "number", text: "Number" },
                      { key: "special", text: "Special Character" },
                      { key: "noWhitespace", text: "No Whitespace" },
                    ].map((req) => (
                      <div
                        key={req.key}
                        className={`requirement ${
                          requirements[req.key] ? "met" : ""
                        }`}
                      >
                        <i
                          className={`fas fa-${
                            requirements[req.key] ? "check" : "times"
                          }-circle`}
                        ></i>
                        <span>{req.text}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            <div className="mb-4 recaptcha-container">
              <ReCAPTCHA
                sitekey="your site key here"
                onChange={handleCaptchaChange}
              />
            </div>

            {error && <div className="alert alert-danger mb-3">{error}</div>}

            <button
              type={isVerifying ? "button" : "submit"}
              className={`btn btn-primary w-100 ${
                !isCaptchaVerified ? "captcha-unverified" : ""
              }`}
              disabled={isLoading}
              onClick={isVerifying ? handleResendVerification : undefined}
            >
              {isLoading ? (
                <>
                  <span
                    className="spinner-border spinner-border-sm me-2"
                    role="status"
                    aria-hidden="true"
                  ></span>
                  Sending Verification...
                </>
              ) : isVerifying ? (
                <>
                  <i className="fas fa-paper-plane me-2"></i>
                  Resend Verification
                </>
              ) : (
                <>
                  <i className="fas fa-user-plus me-2"></i>
                  Register
                </>
              )}
            </button>

            <div className="social-login-container">
              <div className="divider">
                <span>or continue with</span>
              </div>

              <div className="social-buttons">
                <button
                  type="button"
                  className="btn btn-outline-danger w-100 mb-2"
                  onClick={() => handleSocialRegister("Google")}
                >
                  <i className="fab fa-google me-2"></i>Continue with Google
                </button>
                <button
                  type="button"
                  className="btn btn-outline-primary w-100"
                  onClick={() => handleSocialRegister("Facebook")}
                >
                  <i className="fab fa-facebook me-2"></i>Continue with Facebook
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Register;
