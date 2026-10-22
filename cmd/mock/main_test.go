package main

import "testing"

func TestMockOptions(t *testing.T) {
	for _, args := range [][]string{{}, {"-system", "docs", "-listen", "127.0.0.1:9002"}, {"-listen", "[::1]:0"}} {
		if _, _, err := parse(args); err != nil {
			t.Fatalf("valid options: %v", err)
		}
	}
	for _, args := range [][]string{{"-system", "real"}, {"-listen", "0.0.0.0:9001"}, {"-listen", "localhost:9001"}, {"-listen", "127.0.0.1:65536"}, {"-token", "secret"}, {"unexpected"}} {
		if _, _, err := parse(args); err == nil {
			t.Fatalf("invalid options accepted: %v", args)
		}
	}
}
