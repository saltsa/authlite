package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol"
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
		Addr:      ":" + util.MustGetEnv("PORT", "5021"),
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

	// graceful shutdown setup for SIGTERM
	wg := sync.WaitGroup{}
	wg.Add(1)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		<-sigs
		err := srv.Shutdown(context.Background())
		if err != nil {
			slog.Error("shutdown was not clean", "error", err)
			return
		}
		slog.Info("server successfully shutdown")
		wg.Done()
	}()

	// listen
	var err error
	if util.GetEnvBool("SKIP_TLS") {
		slog.Info("start listening", "proto", "HTTP", "addr", srv.Addr)
		err = srv.ListenAndServe()
	} else {
		slog.Info("start listening", "proto", "HTTPS", "addr", srv.Addr)
		err = srv.ListenAndServeTLS("", "")
	}
	slog.Info("server listen stopped", "error", err)
	close(sigs)

	// wait for graceful shutdown
	wg.Wait()
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
		logger.Printf("--- request method=%s uri=%s host=%s remote=%s", r.Method, r.RequestURI, r.Host, r.RemoteAddr)
		for hdr := range r.Header {
			logger.Printf("%s -> %s", hdr, r.Header.Get(hdr))
		}
		logger.Printf("--- header list end")

		// skip get and options methods as we're not interested about them
		if r.Method == http.MethodGet || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
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

		ctx = context.WithValue(ctx, constants.CtxUserAgent, r.UserAgent())
		newReq := r.WithContext(ctx)
		next.ServeHTTP(w, newReq)
		end := time.Now()

		slog.InfoContext(ctx, fmt.Sprintf("%s %s %s", r.Method, r.RequestURI, r.UserAgent()), "ms", end.Sub(start).Milliseconds())
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

	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		applog.LogAuditEvent(r.Context(), applog.AuditLoginfailed, "login finish failed to parse response", "error", err)
		respondError(w, http.StatusBadRequest, "failed to parse response", err)
		return
	}

	user, credential, err := w6nConfig.ValidatePasskeyLogin(auth.UserHandler, *challengeEntry.GetSessionData(), parsedResponse)
	if err != nil {
		applog.LogAuditEvent(r.Context(), applog.AuditLoginfailed, "validating login failed", "error", err)
		respondError(w, http.StatusForbidden, "login failed", err)
		return
	}

	applog.LogAuditEvent(r.Context(), applog.AuditLoginSuccess, "login successful")

	_ = credential

	logger.Printf("user: %x", user.WebAuthnID())

	w.Header().Set("content-type", "application json")
	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"token": fmt.Sprintf("authtoken:%s", challengeEntry.ID.String()),
	}

	json.NewEncoder(w).Encode(response)
}
