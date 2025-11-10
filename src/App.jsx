import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import Home from "./components/home/Home";
import Auth from "./components/Auth/Auth";
import EmailVerification from "./pages/EmailVerification";
import UserDashboard from "./components/Dashboard/UserDashboard";
import AdminLogin from "./components/Admin/AdminLogin";
import AdminDashboard from "./components/Admin/AdminDashboard";
import ProtectedRoute from "./components/ProtectedRoute";
import AuditLog from './components/Admin/AuditLog';
import "./App.css";

const App = () => {
  return (
    <Router>
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<Home />} />
        <Route path="/features" element={<Home />} />
        <Route path="/pricing" element={<Home />} />
        <Route path="/about" element={<Home />} />
        <Route path="/contact" element={<Home />} />
        <Route path="/auth" element={<Auth />} />
        <Route path="/verify-email" element={<EmailVerification />} />
        <Route path="/admin-login-55x" element={<AdminLogin />} />

        {/* Protected User Routes */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute type="user">
              <UserDashboard />
            </ProtectedRoute>
          }
        />

        {/* Protected Admin Routes */}
        <Route
          path="/admin-dashboard"
          element={
            <ProtectedRoute type="admin">
              <AdminDashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/audit-logs"
          element={
            <ProtectedRoute type="admin">
              <AuditLog />
            </ProtectedRoute>
          }
        />

        {/* Fallback Route */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
};

export default App;
