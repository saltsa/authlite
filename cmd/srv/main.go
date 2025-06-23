package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/saltsa/authlite"
	"github.com/saltsa/authlite/applog"
	"github.com/saltsa/authlite/internal/auth"
	"github.com/saltsa/authlite/internal/constants"
	"github.com/saltsa/authlite/internal/util"

	_ "github.com/joho/godotenv/autoload"
)

const cookieName = "al_session_id"

var logger = applog.GetLogger()

var w6nConfig *webauthn.WebAuthn

func main() {

	auth.ReadUsers()
	w6nConfig = auth.WebauthConfig()

	// server init
	tlsConfig := &tls.Config{
		GetCertificate: util.ProvideTLSCertificate,
	}
	mux := http.NewServeMux()
	srv := &http.Server{
		Addr:      "localhost:" + util.MustGetEnv("PORT", "5021"),
		TLSConfig: tlsConfig,
		Handler:   setMiddleware(mux),
	}

	// routes
	mux.HandleFunc("POST /login/begin", loginBeginHandler)
	mux.HandleFunc("POST /login/finish", loginFinishHandler)
	validPaths := map[string]string{
		"/":            "templates/index.html",
		"/style.css":   "templates/style.css",
		"/webauthn.js": "",
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if fp, ok := validPaths[r.URL.Path]; ok {
			if fp == "" {
				fp = "templates" + r.URL.Path
			}
			http.ServeFileFS(w, r, authlite.WebRoot, fp)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	if util.GetEnvBool("SKIP_TLS") {
		logger.Printf("listen HTTP at %s", srv.Addr)
		logger.Print(srv.ListenAndServe())
		return
	}
	logger.Printf("listen HTTPS at %s", srv.Addr)
	logger.Print(srv.ListenAndServeTLS("", ""))
}

func respondError(w http.ResponseWriter, status int, msg string, err error) {
	w.Header().Set("content-type", "application/json")
	response := map[string]any{
		"error": msg,
	}
	if errors.Is(err, auth.ErrUserNotFound) {
		status = 404
		response["credentialRemoved"] = true
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

func setMiddleware(next http.Handler) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// skip get and options methods as we're not interested about them
		if r.Method == http.MethodGet || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()

		if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			xff := r.Header.Get("X-Forwarded-For")
			ips := strings.Split(xff, ",")
			ipA := strings.TrimSpace(ips[0])
			ipA = strings.TrimPrefix(ipA, "[")
			ipA = strings.TrimSuffix(ipA, "]")
			ipParsed := net.ParseIP(ipA)
			if ipParsed != nil {
				ip = ipParsed.String()
			}
			ctx = context.WithValue(ctx, constants.CtxClientIP, ip)
		} else {
			logger.Printf("failure, no ip got: %s", err)
			respondError(w, http.StatusInternalServerError, "logging failure in server", err)
			return
		}

		if cookie, err := r.Cookie(cookieName); err == nil {
			ctx = context.WithValue(ctx, constants.CtxAuthID, cookie.Value)
		}

		newReq := r.WithContext(ctx)
		next.ServeHTTP(w, newReq)
	})

	return handler
}

func loginBeginHandler(w http.ResponseWriter, r *http.Request) {
	cu := auth.NewChallenge(r.Context())
	if cu == nil {
		respondError(w, http.StatusTooManyRequests, "Too many requests. Try again later.", nil)
		return
	}
	ret, sessionData, err := w6nConfig.BeginDiscoverableLogin(
		auth.WebauthChallenge(cu.ID),
	)
	if err != nil {
		logger.Printf("failure to start discovery: %s", err)
		respondError(w, http.StatusInternalServerError, "Internal failure to start authentication process.", err)
		return
	}

	ctx := context.WithValue(r.Context(), constants.CtxAuthID, cu.ID.String())
	applog.LogAuditEvent(ctx, applog.AuditNewChallenge, "new challenge created")

	cu.AddSessionData(sessionData)

	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    cu.ID.String(),
		MaxAge:   cu.GetLifeTime(),
		Secure:   true,
		HttpOnly: true,
		Path:     "/login",
	}

	http.SetCookie(w, cookie)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.Encode(ret)
}

func loginFinishHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		respondError(w, http.StatusForbidden, "cookie missing", err)
		return
	}

	challengeEntry := auth.GetSessionData(cookie.Value)
	if challengeEntry == nil {
		respondError(w, http.StatusForbidden, "session not found", nil)
		return
	}

	credential, err := w6nConfig.FinishDiscoverableLogin(auth.UserHandler, *challengeEntry.GetSessionData(), r)
	if err != nil {
		applog.LogAuditEvent(r.Context(), applog.AuditLoginfailed, "login failure", "error", err)
		respondError(w, http.StatusForbidden, "failed to log user in", err)
		return
	}

	applog.LogAuditEvent(r.Context(), applog.AuditLoginSuccess, "login successful")
	_ = credential

	w.Header().Set("content-type", "application json")
	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"token": fmt.Sprintf("authtoken:%s", challengeEntry.ID.String()),
	}

	json.NewEncoder(w).Encode(response)
}
