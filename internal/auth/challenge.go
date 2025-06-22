package auth

import (
	"context"
	"crypto/rand"
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
	Created     time.Time
}

func (cu *ChallengeEntry) AddSessionData(sd *webauthn.SessionData) {
	cu.sessionData = sd
}

func (cu *ChallengeEntry) GetSessionData() (sd *webauthn.SessionData) {
	return cu.sessionData
}

func (cu *ChallengeEntry) Expired() (expired bool) {
	if cu != nil {
		if age := time.Since(cu.Created); age > challengeExpireTime {
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
				logger.Printf("removed expired challenges %d of %d total. Operation was done in %s", count, total, time.Since(start))
			}
		}
	}()
}
