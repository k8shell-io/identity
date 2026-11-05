// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package mail

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// fakeSMTP accepts one connection, speaks just enough SMTP for net/smtp, and
// returns the DATA payload on the channel.
func fakeSMTP(t *testing.T) (port int, data <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		reply := func(s string) { c.Write([]byte(s + "\r\n")) }
		reply("220 fake")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				reply("250 fake")
			case strings.HasPrefix(cmd, "DATA"):
				reply("354 go")
				var sb strings.Builder
				for {
					l, _ := r.ReadString('\n')
					if l == ".\r\n" {
						break
					}
					sb.WriteString(l)
				}
				ch <- sb.String()
				reply("250 2.0.0 OK queued as abc123")
			case strings.HasPrefix(cmd, "QUIT"):
				reply("221 bye")
				return
			default:
				reply("250 ok")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ch
}

func TestSendNotificationEmail_SanitisesSubject(t *testing.T) {
	port, data := fakeSMTP(t)
	cfg := Config{Host: "127.0.0.1", Port: port, From: "noreply@example.com"}
	reply, err := SendNotificationEmail(cfg, "a@example.com", "Hi\r\nBcc: evil@example.com", "line1\nline2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply, "queued as abc123") {
		t.Fatalf("relay reply not returned: %q", reply)
	}
	msg := <-data
	head, body, _ := strings.Cut(msg, "\r\n\r\n")
	for _, h := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(h, "Bcc:") {
			t.Fatalf("subject injected a header: %q", head)
		}
	}
	if !strings.Contains(head, "Subject: Hi  Bcc: evil@example.com") {
		t.Fatalf("subject not flattened: %q", head)
	}
	if body != "line1\r\nline2\r\n" {
		t.Fatalf("body = %q", body)
	}
}
