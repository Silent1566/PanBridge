package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestEvaluateWhitelist(t *testing.T) {
	tests := []struct {
		name        string
		requestPath string
		scene       string
		allowed     bool
		matchType   string
		rule        string
	}{
		{name: "root exact", requestPath: "/", scene: "generic", allowed: true, matchType: "exact", rule: "/"},
		{name: "zx exact", requestPath: "/api/search", scene: "zx", allowed: true, matchType: "exact", rule: "/api/search"},
		{name: "pg normalized exact", requestPath: "/s/", scene: "pg", allowed: true, matchType: "exact", rule: "/s"},
		{name: "proxy prefix", requestPath: "/api/proxy/image.png", scene: "generic", allowed: true, matchType: "prefix", rule: "/api/proxy/"},
		{name: "pg nested path denied", requestPath: "/s/evil", scene: "pg", allowed: false},
		{name: "zx nested path denied", requestPath: "/api/search/evil", scene: "zx", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := evaluateWhitelist(tt.requestPath)
			if decision.Scene != tt.scene {
				t.Fatalf("scene mismatch: got %q want %q", decision.Scene, tt.scene)
			}
			if decision.IsWhitelisted != tt.allowed {
				t.Fatalf("whitelist mismatch: got %v want %v", decision.IsWhitelisted, tt.allowed)
			}
			if decision.MatchType != tt.matchType {
				t.Fatalf("matchType mismatch: got %q want %q", decision.MatchType, tt.matchType)
			}
			if decision.Rule != tt.rule {
				t.Fatalf("rule mismatch: got %q want %q", decision.Rule, tt.rule)
			}
		})
	}
}

func TestMonitoringMiddlewareAutoBlockForPGNestedPath(t *testing.T) {
	app := newTestApplication(t, true)
	req := httptest.NewRequest(http.MethodPost, "/s/evil", nil)
	req.RemoteAddr = "127.0.0.1:4567"
	rec := httptest.NewRecorder()
	called := false

	handler := app.MonitoringMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatalf("next handler should not be called for non-whitelisted PG path")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status mismatch: got %d want %d", rec.Code, http.StatusNotFound)
	}
	if !app.blacklistManager.IsBlocked("ip", "127.0.0.1") {
		t.Fatalf("expected IP to be auto-blocked for non-whitelisted PG path")
	}
}

func TestMonitoringMiddlewareNoAutoBlockWhenDisabled(t *testing.T) {
	app := newTestApplication(t, false)
	req := httptest.NewRequest(http.MethodPost, "/s/evil", nil)
	req.RemoteAddr = "127.0.0.1:4567"
	rec := httptest.NewRecorder()

	handler := app.MonitoringMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status mismatch: got %d want %d", rec.Code, http.StatusNotFound)
	}
	if app.blacklistManager.IsBlocked("ip", "127.0.0.1") {
		t.Fatalf("expected IP not to be blocked when auto block is disabled")
	}
}

func TestMonitoringMiddlewareAllowsLegitPGPath(t *testing.T) {
	app := newTestApplication(t, true)
	req := httptest.NewRequest(http.MethodPost, "/s/", nil)
	req.RemoteAddr = "127.0.0.1:4567"
	rec := httptest.NewRecorder()
	called := false

	handler := app.MonitoringMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("expected legit PG path to reach next handler")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status mismatch: got %d want %d", rec.Code, http.StatusOK)
	}
	if app.blacklistManager.IsBlocked("ip", "127.0.0.1") {
		t.Fatalf("expected legit PG path not to be blocked")
	}
}

func newTestApplication(t *testing.T, autoBlock bool) *Application {
	t.Helper()
	t.Setenv("P2T_DB_PATH", filepath.Join(t.TempDir(), "test.db"))

	logger := NewLogger(ErrorLevel)
	db, err := initSQLiteDB()
	if err != nil {
		t.Fatalf("initSQLiteDB failed: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	configManager, err := NewConfigManager(db, logger)
	if err != nil {
		t.Fatalf("NewConfigManager failed: %v", err)
	}
	configManager.configLock.Lock()
	cfg := configManager.config
	cfg.AutoBlockIP = autoBlock
	configManager.config = cfg
	configManager.configLock.Unlock()

	app := &Application{
		configManager:             configManager,
		logger:                    logger,
		metricsManager:            NewMetricsManager(),
		blacklistManager:          NewBlacklistManager(db, logger),
		geoipService:              &GeoIPService{logger: logger},
		passwordProtectionManager: NewPasswordProtectionManager(logger),
		db:                        db,
	}
	configManager.SetApplication(app)
	return app
}
