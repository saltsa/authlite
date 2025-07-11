package auth

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/saltsa/authlite"
	"github.com/saltsa/authlite/applog"
	"github.com/saltsa/authlite/configreader"
	"github.com/saltsa/authlite/internal/util"
)

var logger = applog.GetLogger()

const authenticationTimeout = 5 * time.Minute

func WebauthConfig() *webauthn.WebAuthn {
	rpID := util.MustGetEnv("RPID")
	rpName := util.MustGetEnv("RPID_NAME", "dummy display name")
	rpOrigin := util.MustGetEnv("RPID_ORIGIN", "https://"+rpID)

	wn, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpName,
		RPOrigins:     []string{rpOrigin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// RequireResidentKey: &requireResident,
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		},
		// RPTopOriginVerificationMode: protocol.TopOriginImplicitVerificationMode,
		// TODO: These are broken(?) on Chrome/macOs and do not work. It doesn't respect timeout
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    authenticationTimeout,
				TimeoutUVD: authenticationTimeout,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    authenticationTimeout,
				TimeoutUVD: authenticationTimeout,
			},
		},
	})
	if err != nil {
		logger.Fatalf("failed to initialize webauthn: %s", err)
	}
	return wn
}

func WebauthChallenge(cu uuid.UUID) webauthn.LoginOption {
	return webauthn.WithChallenge(GetChallengeUUID(cu).Challenge)
}

func UserHandler(rawID, userHandle []byte) (webauthn.User, error) {
	logger.Printf("user %s (%d), handle %s (%d) logging in", hd(rawID), len(rawID), hd(userHandle), len(userHandle))

	if len(userHandle) == 16 {
		uUser := uuid.UUID(userHandle)
		logger.Printf("user handle: %s", uUser)
		return getW6NUser(uUser)
	}
	// if len(rawID) == 16 {
	// 	uUser := uuid.UUID(rawID)
	// 	logger.Printf("user rawid: %s", uUser)
	// 	return nil, errors.New("not implemented")
	// }
	return nil, ErrUserNotFound
}

func GetSessionData(session string) *ChallengeEntry {
	uSess, err := uuid.Parse(session)
	if err != nil {
		logger.Printf("failure to parse uuid: %s", err)
		return nil
	}

	cu := GetChallengeUUID(uSess)
	if cu.sessionData == nil {
		return nil
	}
	return cu
}

func hd(d []byte) string {
	return hex.EncodeToString(d)
}

var users map[uuid.UUID][]configreader.Credential

func ReadUsers() {
	var err error
	users, err = configreader.ReadUsers(authlite.FSRoot)
	if err != nil {
		panic(err)
	}
}

var ErrUserNotFound = errors.New("user not found")

func getW6NUser(u uuid.UUID) (webauthn.User, error) {
	ui, ok := users[u]
	if !ok {
		return nil, ErrUserNotFound
	}
	return NewW6NUser(u, ui), nil
}

func NewW6NUser(uUser uuid.UUID, credentials []configreader.Credential) w6nUser {
	handle := uUser[:]
	ret := w6nUser{
		Handle: handle,
	}
	for _, cred := range credentials {
		keyID, pk := cred.GetIDAndPublicKey()
		wc := webauthn.Credential{
			ID:        keyID,
			PublicKey: pk,
			Flags: webauthn.CredentialFlags{
				BackupEligible: true,
			},
		}
		ret.Keys = append(ret.Keys, wc)
	}
	return ret
}

type w6nUser struct {
	Handle []byte
	Keys   []webauthn.Credential
}

func (w w6nUser) WebAuthnID() []byte {
	return w.Handle
}
func (w6nUser) WebAuthnName() string {
	return "name is not used"
}
func (w6nUser) WebAuthnDisplayName() string {
	return "display name is not used"
}
func (w w6nUser) WebAuthnCredentials() []webauthn.Credential {
	return w.Keys
}
