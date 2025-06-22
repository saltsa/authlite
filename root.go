package authlite

import (
	"embed"
)

//go:embed users.csv
var FSRoot embed.FS

//go:embed templates
var WebRoot embed.FS
