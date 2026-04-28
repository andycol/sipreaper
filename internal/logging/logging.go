// Package logging configures zerolog for the daemon and routes the stdlib
// `log` package through it so existing log.Printf call sites get structured
// output for free. Call Init once from main / daemon startup.
package logging

import (
	"fmt"
	stdlog "log"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init configures global zerolog state from config. Outputs:
//
//   - "stdout" (default): JSON to stdout
//   - "stderr": JSON to stderr
//   - "console": pretty colourised output (dev mode)
//   - "file": JSON to the path given by `file`
//
// level is one of: trace, debug, info, warn, error.
func Init(level, output, file string) error {
	zerolog.TimestampFieldName = "ts"
	zerolog.MessageFieldName = "msg"
	zerolog.LevelFieldName = "lvl"

	lvl, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil || level == "" {
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)

	var writer zerolog.LevelWriter
	switch output {
	case "console":
		writer = zerolog.MultiLevelWriter(zerolog.ConsoleWriter{Out: os.Stderr})
	case "stderr":
		writer = zerolog.MultiLevelWriter(os.Stderr)
	case "file":
		if file == "" {
			return fmt.Errorf("logging.output=file requires logging.file to be set")
		}
		f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening log file %q: %w", file, err)
		}
		writer = zerolog.MultiLevelWriter(f)
	default:
		writer = zerolog.MultiLevelWriter(os.Stdout)
	}

	logger := zerolog.New(writer).With().Timestamp().Logger()
	log.Logger = logger

	// Route the stdlib log package through zerolog's info-level writer so
	// every existing log.Printf in the codebase gets timestamped + structured
	// without us having to rewrite call sites.
	stdlog.SetFlags(0)
	stdlog.SetPrefix("")
	stdlog.SetOutput(logger.Level(zerolog.InfoLevel))
	return nil
}
