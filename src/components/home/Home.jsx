import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Header from "./Header";
import Footer from "./Footer";
import "./Home.css";
import "bootstrap/dist/css/bootstrap.min.css";

const Home = () => {
  const navigate = useNavigate();
  const [currentTestimonial, setCurrentTestimonial] = useState(0);

  const testimonials = [
    {
      name: "Sarah Johnson",
      role: "IT Manager",
      company: "TechCorp Inc.",
      content:
        "This security system has revolutionized our data protection strategy. The advanced encryption and user management features are unparalleled.",
      avatar: "👩‍💼",
    },
    {
      name: "Michael Chen",
      role: "Security Analyst",
      company: "SecureNet Solutions",
      content:
        "The analytics dashboard provides incredible insights into our security posture. We've never been more confident in our defenses.",
      avatar: "👨‍💻",
    },
    {
      name: "Emily Rodriguez",
      role: "CEO",
      company: "DataGuard Ltd.",
      content:
        "Outstanding 24/7 support and the most reliable uptime we've experienced. This platform has become our cornerstone security solution.",
      avatar: "👩‍💼",
    },
  ];

  const features = [
    {
      icon: "🔒",
      title: "Advanced Encryption",
      description:
        "Military-grade AES-256 encryption protects your data at rest and in transit with zero-knowledge architecture.",
      details: [
        "End-to-end encryption",
        "Zero-knowledge security",
        "AES-256 encryption",
        "Secure key management",
      ],
    },
    {
      icon: "👥",
      title: "User Management",
      description:
        "Comprehensive role-based access control with multi-factor authentication and granular permissions.",
      details: [
        "Role-based access",
        "Multi-factor auth",
        "Granular permissions",
        "User activity monitoring",
      ],
    },
    {
      icon: "📊",
      title: "Real-time Analytics",
      description:
        "Advanced analytics dashboard with threat detection, compliance reporting, and security insights.",
      details: [
        "Real-time monitoring",
        "Threat detection",
        "Compliance reports",
        "Security insights",
      ],
    },
    {
      icon: "🛡️",
      title: "Threat Protection",
      description:
        "AI-powered threat detection and automated response systems to protect against emerging cyber threats.",
      details: [
        "AI threat detection",
        "Automated responses",
        "Intrusion prevention",
        "Malware protection",
      ],
    },
    {
      icon: "🔄",
      title: "Backup & Recovery",
      description:
        "Automated backup solutions with point-in-time recovery and disaster recovery capabilities.",
      details: [
        "Automated backups",
        "Point-in-time recovery",
        "Disaster recovery",
        "Data redundancy",
      ],
    },
    {
      icon: "📱",
      title: "Mobile Security",
      description:
        "Secure mobile access with device management, remote wipe capabilities, and mobile threat protection.",
      details: [
        "Mobile device management",
        "Remote wipe",
        "Mobile threat protection",
        "Secure access",
      ],
    },
  ];

  const stats = [
    { value: "99.9%", label: "Uptime SLA", icon: "⏱️" },
    { value: "24/7", label: "Expert Support", icon: "🎧" },
    { value: "10K+", label: "Active Users", icon: "👥" },
    { value: "50+", label: "Countries Served", icon: "🌍" },
    { value: "99.99%", label: "Data Security", icon: "🔐" },
    { value: "<1min", label: "Response Time", icon: "⚡" },
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTestimonial((prev) => (prev + 1) % testimonials.length);
    }, 5000);
    return () => clearInterval(interval);
  }, [testimonials.length]);

  return (
    <div className="d-flex flex-column min-vh-100 w-100">
      <Header />

      <main className="flex-grow-1 w-100">
        {/* Hero Section */}
        <section className="hero-section bg-gradient-primary text-white position-relative overflow-hidden">
          <div className="hero-background">
            <div className="hero-shape shape-1"></div>
            <div className="hero-shape shape-2"></div>
            <div className="hero-shape shape-3"></div>
          </div>
          <div className="container-fluid position-relative">
            <div className="row align-items-center min-vh-100">
              <div className="col-lg-6 text-center text-lg-start">
                <div className="hero-content">
                  <h1 className="display-2 fw-bold mb-4 animate-fade-in">
                    Secure Your Digital
                    <span className="text-gradient"> World</span>
                  </h1>
                  <p className="lead fs-4 mb-5 animate-slide-up">
                    Enterprise-grade security solutions with AI-powered threat
                    detection, advanced encryption, and comprehensive user
                    management for modern businesses.
                  </p>
                  <div className="hero-buttons">
                    <button
                      className="btn btn-light btn-lg px-5 py-3 me-3 animate-bounce"
                      onClick={() => navigate("/auth")}
                    >
                      <i className="fas fa-rocket me-2"></i>
                      Get Started Free
                    </button>
                    <button
                      className="btn btn-outline-light btn-lg px-5 py-3 animate-fade-in"
                      onClick={() =>
                        document
                          .getElementById("features")
                          .scrollIntoView({ behavior: "smooth" })
                      }
                    >
                      <i className="fas fa-play me-2"></i>
                      Watch Demo
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-lg-6 d-none d-lg-block">
                <div className="hero-dashboard-preview animate-float">
                  <div className="dashboard-mockup">
                    <div className="mockup-header">
                      <div className="mockup-dots">
                        <span></span>
                        <span></span>
                        <span></span>
                      </div>
                      <div className="mockup-title">Security Dashboard</div>
                    </div>
                    <div className="mockup-content">
                      <div className="mockup-chart">
                        <div
                          className="chart-bar"
                          style={{ height: "60%" }}
                        ></div>
                        <div
                          className="chart-bar"
                          style={{ height: "80%" }}
                        ></div>
                        <div
                          className="chart-bar"
                          style={{ height: "40%" }}
                        ></div>
                        <div
                          className="chart-bar"
                          style={{ height: "90%" }}
                        ></div>
                        <div
                          className="chart-bar"
                          style={{ height: "70%" }}
                        ></div>
                      </div>
                      <div className="mockup-stats">
                        <div className="stat-item">
                          <span className="stat-number">99.9%</span>
                          <span className="stat-label">Uptime</span>
                        </div>
                        <div className="stat-item">
                          <span className="stat-number">0</span>
                          <span className="stat-label">Threats</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="features-section py-5" id="features">
          <div className="container-fluid">
            <div className="row justify-content-center mb-5">
              <div className="col-lg-8 text-center">
                <h2 className="display-4 fw-bold text-primary mb-4">
                  Comprehensive Security Features
                </h2>
                <p className="lead text-muted fs-5">
                  Everything you need to protect your organization with
                  enterprise-grade security solutions designed for the modern
                  digital landscape.
                </p>
              </div>
            </div>
            <div className="row g-4">
              {features.map((feature, index) => (
                <div key={index} className="col-lg-4 col-md-6">
                  <div className="feature-card card h-100 border-0 shadow-lg hover-lift">
                    <div className="card-body text-center p-4">
                      <div className="feature-icon mb-4">
                        <span className="display-2">{feature.icon}</span>
                      </div>
                      <h3 className="card-title h4 mb-3 fw-bold">
                        {feature.title}
                      </h3>
                      <p className="card-text text-muted mb-4">
                        {feature.description}
                      </p>
                      <ul className="feature-details list-unstyled">
                        {feature.details.map((detail, idx) => (
                          <li key={idx} className="mb-2">
                            <i className="fas fa-check text-success me-2"></i>
                            {detail}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Stats Section */}
        <section className="stats-section py-5 bg-light">
          <div className="container-fluid">
            <div className="row justify-content-center mb-5">
              <div className="col-lg-6 text-center">
                <h2 className="display-4 fw-bold text-primary mb-4">
                  Trusted by Organizations Worldwide
                </h2>
                <p className="lead text-muted">
                  Join thousands of companies that rely on our security platform
                </p>
              </div>
            </div>
            <div className="row g-4">
              {stats.map((stat, index) => (
                <div key={index} className="col-lg-2 col-md-4 col-sm-6">
                  <div className="stat-card card border-0 shadow-sm text-center h-100">
                    <div className="card-body p-4">
                      <div className="stat-icon mb-3">
                        <span className="display-4">{stat.icon}</span>
                      </div>
                      <h3 className="stat-value display-5 fw-bold text-primary mb-2">
                        {stat.value}
                      </h3>
                      <p className="stat-label text-muted mb-0 small">
                        {stat.label}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Testimonials Section */}
        <section className="testimonials-section py-5">
          <div className="container-fluid">
            <div className="row justify-content-center mb-5">
              <div className="col-lg-6 text-center">
                <h2 className="display-4 fw-bold text-primary mb-4">
                  What Our Customers Say
                </h2>
                <p className="lead text-muted">
                  Real feedback from organizations using our security platform
                </p>
              </div>
            </div>
            <div className="row justify-content-center">
              <div className="col-lg-8">
                <div className="testimonial-card card border-0 shadow-lg">
                  <div className="card-body p-5 text-center">
                    <div className="testimonial-avatar mb-4">
                      <span className="display-1">
                        {testimonials[currentTestimonial].avatar}
                      </span>
                    </div>
                    <blockquote className="blockquote mb-4">
                      <p className="lead mb-4">
                        "{testimonials[currentTestimonial].content}"
                      </p>
                    </blockquote>
                    <div className="testimonial-author">
                      <h5 className="fw-bold mb-1">
                        {testimonials[currentTestimonial].name}
                      </h5>
                      <p className="text-muted mb-0">
                        {testimonials[currentTestimonial].role},{" "}
                        {testimonials[currentTestimonial].company}
                      </p>
                    </div>
                  </div>
                  <div className="testimonial-indicators d-flex justify-content-center p-3">
                    {testimonials.map((_, index) => (
                      <button
                        key={index}
                        className={`indicator mx-1 ${
                          index === currentTestimonial ? "active" : ""
                        }`}
                        onClick={() => setCurrentTestimonial(index)}
                      ></button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="cta-section bg-gradient-primary text-white py-5">
          <div className="container-fluid">
            <div className="row justify-content-center">
              <div className="col-lg-8 text-center">
                <h2 className="display-4 fw-bold mb-4">
                  Ready to Secure Your Organization?
                </h2>
                <p className="lead mb-5 fs-4">
                  Start your free trial today and experience enterprise-grade
                  security with our comprehensive platform. No credit card
                  required.
                </p>
                <div className="cta-buttons">
                  <button
                    className="btn btn-light btn-lg px-5 py-3 me-3"
                    onClick={() => navigate("/auth")}
                  >
                    <i className="fas fa-user-plus me-2"></i>
                    Start Free Trial
                  </button>
                  <button
                    className="btn btn-outline-light btn-lg px-5 py-3"
                    onClick={() => navigate("/contact")}
                  >
                    <i className="fas fa-envelope me-2"></i>
                    Contact Sales
                  </button>
                </div>
                <p className="mt-4 text-light opacity-75">
                  <small>Join 10,000+ organizations already protected</small>
                </p>
              </div>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
};

export default Home;
