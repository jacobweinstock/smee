package main

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sync/errgroup"
)

func TestFormatHostPort(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"port only":               {input: ":67", want: "0.0.0.0:67"},
		"host only":               {input: "4.4.4.4", want: "4.4.4.4"},
		"host and port":           {input: "1.1.1.1:53", want: "1.1.1.1:53"},
		"no host or port":         {input: "", want: ""},
		"not in host:port format": {input: "abcde", want: "abcde"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := formatHostPort(tc.input)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf(diff)
			}
		})
	}
}

func TestCustomBootserver(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"127.0.0.1": {input: "127.0.0.1", want: "127.0.0.1"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fn := customBootserver(tc.input)
			got := fn()
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf(diff)
			}
		})
	}
}

func TestCustomBootfile(t *testing.T) {
	type inputs struct {
		arch, uClass string
	}
	tests := map[string]struct {
		input inputs
		want  string
	}{
		"arch: hua":     {input: inputs{arch: "hua"}, want: "snp-hua.efi"},
		"arch: 2a2":     {input: inputs{arch: "2a2"}, want: "snp-hua.efi"},
		"arch: aarch64": {input: inputs{arch: "aarch64"}, want: "snp-nolacp.efi"},
		"arch: uefi":    {input: inputs{arch: "uefi"}, want: "ipxe.efi"},
		"arch: ia32":    {input: inputs{arch: "IA32"}, want: "undionly.kpxe"},
		"arch: iPXE":    {input: inputs{arch: "IA32", uClass: "iPXE"}, want: "http://static/auto.ipxe"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fn := customBootfile("static")
			got := fn(tc.input.arch, tc.input.uClass)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf(diff)
			}
		})
	}
}

func TestRunProxyDHCP(t *testing.T) {
	tests := map[string]struct {
		input string
		want  error
	}{
		"context canceled":      {input: "127.0.0.1:35689", want: context.Canceled},
		"network address error": {input: "127.0.0.1", want: &net.AddrError{}},
	}
	fqdn := "127.0.0.1"
	bfile := customBootfile(fqdn)
	sfile := customBootserver(fqdn)
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				return runProxyDHCP(ctx, mainlog, tc.input, bfile, sfile)
			})

			if errors.Is(tc.want, context.Canceled) {
				cancel()
			}
			got := g.Wait()
			if reflect.TypeOf(got) != reflect.TypeOf(tc.want) {
				cancel()
				t.Fatalf("expected error of type %T, got: %T", tc.want, got)
			}
			cancel()
		})
	}
}
