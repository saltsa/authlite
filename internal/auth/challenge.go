package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

const challengeExpireTime = 15 * time.Minute
const challengeLength = 32

// One session takes about 200-300 bytes of memory so 10_000 is less
// than 3 MB.
const maxOpenSessions = 10_000

type ChallengeEntry struct {
	ID          uuid.UUID
	Challenge   []byte
	sessionData *webauthn.SessionData
	Created     time.Time // TODO: To be removed because we're using ID. Left for now.
}

func (cu *ChallengeEntry) AddSessionData(sd *webauthn.SessionData) {
	slog.Debug("adding sesssion data",
		"challenge", sd.Challenge,
		"rp", sd.RelyingPartyID,
		"userId", b64(sd.UserID),
		"numOfCredentials", len(sd.AllowedCredentialIDs),
		"expires", sd.Expires.String(),
		"userVerification", sd.UserVerification,
		"extensionLength", len(sd.Extensions),
		"credentialParameters", jsonOutput(sd.CredParams),
	)
	cu.sessionData = sd
}

func (cu *ChallengeEntry) GetSessionData() (sd *webauthn.SessionData) {
	return cu.sessionData
}

func (cu *ChallengeEntry) Expired() (expired bool) {
	if cu != nil {
		created := time.Unix(cu.ID.Time().UnixTime())
		if age := time.Since(created); age > challengeExpireTime {
			return true
		}
	}
	return false
}

func (cu *ChallengeEntry) GetLifeTime() int {
	return int(challengeExpireTime.Seconds())
}

var lock sync.Mutex
var challenges = make(map[uuid.UUID]*ChallengeEntry)

func NewChallenge(ctx context.Context) *ChallengeEntry {
	lock.Lock()
	defer lock.Unlock()

	if len(challenges) >= maxOpenSessions {
		return nil
	}

	u := uuid.Must(uuid.NewV7())
	e := &ChallengeEntry{
		ID:        u,
		Challenge: random(),
		Created:   time.Now(),
	}

	challenges[u] = e

	return e
}

func GetChallengeUUID(u uuid.UUID) *ChallengeEntry {
	lock.Lock()
	defer lock.Unlock()
	r := challenges[u]

	if r.Expired() {
		delete(challenges, u)
	}
	return r
}

func random() []byte {
	buf := make([]byte, challengeLength)
	rand.Read(buf)
	return buf
}

func init() {
	go func() {
		for range time.Tick(30 * time.Second) {
			lock.Lock()
			start := time.Now()
			count := 0
			total := len(challenges)
			for key := range challenges {
				if challenges[key].Expired() {
					count++
					delete(challenges, key)
				}
			}
			lock.Unlock()

			if count > 0 {
				slog.Info("removed expired challenges", "removed", count, "totalBeforeRemove", total, "duration", time.Since(start))
			}
		}
	}()
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func jsonOutput(data any) string {
	b, _ := json.Marshal(data)
	return string(b)
}
