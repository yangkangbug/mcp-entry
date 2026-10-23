package main

import (
	"io"
	"testing"
)

func TestAdminAndClientBindingOptions(t *testing.T) {
	for _, args := range [][]string{
		{"-admin-token-file", "synthetic-admin-file"},
		{"-client-binding"},
		{"-admin-token-file", "synthetic-admin-file", "-client-binding"},
	} {
		if _, err := parseOptions(args, io.Discard); err != nil {
			t.Fatalf("valid local flags rejected: %v", err)
		}
	}
	for _, args := range [][]string{
		{"-admin-token-file", ""},
		{"-admin-token-file", "synthetic-admin-file", "-allow-remote-test", "-allow-insecure-http-test"},
		{"-client-binding", "-allow-remote-test", "-allow-insecure-http-test"},
		{"-admin-token-file", "synthetic-admin-file", "-tls-cert", "c", "-tls-key", "k"},
		{"-client-binding", "-tls-cert", "c", "-tls-key", "k"},
		{"-admin-token-file", "synthetic-admin-file", "-operation", "check-config"},
		{"-client-binding", "-operation", "check-config"},
	} {
		if _, err := parseOptions(args, io.Discard); err == nil {
			t.Fatalf("unsafe flags accepted: %v", args)
		}
	}
}
