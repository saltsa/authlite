package util

import (
	"log"
	"os"
)

func MustGetEnv(env string, def ...string) string {
	r := os.Getenv(env)
	if len(r) == 0 {
		if len(def) > 0 {
			return def[0]
		}
		log.Fatalf("env %q is empty", env)
	}
	return r
}
