package main

import (
	"log/slog"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	for _, test := range []struct {
		input string
		want  slog.Level
	}{
		{input: "debug", want: slog.LevelDebug},
		{input: "info", want: slog.LevelInfo},
		{input: "warn", want: slog.LevelWarn},
		{input: "error", want: slog.LevelError},
		{input: "DEBUG", want: slog.LevelDebug},
	} {
		t.Run(test.input, func(t *testing.T) {
			got, err := parseLogLevel(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("parseLogLevel(%q) = %v, want %v", test.input, got, test.want)
			}
		})
	}
}

func TestParseLogLevelRejectsInvalidLevel(t *testing.T) {
	if _, err := parseLogLevel("trace"); err == nil {
		t.Fatal("expected invalid log level to be rejected")
	}
}
