package main

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tinkerbell/boots/proxy"
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
			got := formatAddr(tc.input)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf(diff)
			}
		})
	}
}

func TestWithServer(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"127.0.0.1": {input: "127.0.0.1", want: "127.0.0.1"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fn := withServer(tc.input)
			got := fn()
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf(diff)
			}
		})
	}
}

func TestWithBootfile(t *testing.T) {
	tests := map[string]struct {
		input proxy.Machine
		want  string
	}{
		"arch: hua":     {input: proxy.Machine{Arch: proxy.ArchHua}, want: "snp-hua.efi"},
		"arch: 2a2":     {input: proxy.Machine{Arch: proxy.Arch2a2}, want: "snp-hua.efi"},
		"arch: aarch64": {input: proxy.Machine{Arch: proxy.ArchAarch64}, want: "snp-nolacp.efi"},
		"arch: uefi":    {input: proxy.Machine{Arch: proxy.ArchUefi}, want: "ipxe.efi"},
		"arch: ia32":    {input: proxy.Machine{Arch: proxy.ArchIA32}, want: "undionly.kpxe"},
		"arch: iPXE":    {input: proxy.Machine{Arch: proxy.ArchIA32, Firm: proxy.FirmwareX86Ipxe}, want: "http://static/auto.ipxe"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fn := withBootfile("static")
			got := fn(tc.input)
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
	bfile := withBootfile(fqdn)
	sfile := withServer(fqdn)
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				return serveProxy(ctx, mainlog, tc.input, bfile, sfile)
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
