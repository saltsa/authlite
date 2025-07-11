package configreader

import (
	"encoding/base64"
	"encoding/csv"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"os"

	"github.com/google/uuid"
)

type Credential struct {
	KeyID     string
	PublicKey string
}

func (c Credential) GetIDAndPublicKey() ([]byte, []byte) {
	id, err := base64.RawURLEncoding.DecodeString(c.KeyID)
	if err != nil {
		log.Fatalf("failure to decode keyid: %s", err)
	}
	pk, err := base64.RawURLEncoding.DecodeString(c.PublicKey)
	if err != nil {
		log.Fatalf("failure to decode public key: %s", err)
	}
	return id, pk
}

// Reads users from CSV, expected format:
// user_id string uuid, key id base64, public key base64
func ReadUsers(fsRoot fs.FS) (map[uuid.UUID][]Credential, error) {
	r, err := fsRoot.Open("users.csv")
	if err != nil {
		return nil, err
	}
	defer r.Close()

	rdr := csv.NewReader(r)
	rdr.FieldsPerRecord = 3

	usMap := make(map[uuid.UUID][]Credential)
	for {
		records, err := rdr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		uu := uuid.MustParse(records[0])
		m := usMap[uu]
		m = append(m, Credential{
			KeyID:     records[1],
			PublicKey: records[2],
		})
		usMap[uu] = m
		slog.Debug("read user", "uuid", uu.String())
	}
	return usMap, nil
}

func WriteUsers(records [][]string) error {
	f, err := os.OpenFile("users.csv", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	wr := csv.NewWriter(f)

	return wr.WriteAll(records)
}
