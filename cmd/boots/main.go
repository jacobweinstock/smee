package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/avast/retry-go"
	"github.com/packethost/pkg/env"
	"github.com/packethost/pkg/log"
	"github.com/peterbourgon/ff/v3"
	"github.com/pkg/errors"
	"github.com/tinkerbell/boots/conf"
	"github.com/tinkerbell/boots/dhcp"
	"github.com/tinkerbell/boots/httplog"
	"github.com/tinkerbell/boots/installers"
	"github.com/tinkerbell/boots/job"
	"github.com/tinkerbell/boots/metrics"
	"github.com/tinkerbell/boots/packet"
	"github.com/tinkerbell/boots/proxy"
	"github.com/tinkerbell/boots/syslog"
	"github.com/tinkerbell/boots/tftp"
	"golang.org/x/sync/errgroup"

	_ "github.com/tinkerbell/boots/installers/coreos"
	_ "github.com/tinkerbell/boots/installers/custom_ipxe"
	_ "github.com/tinkerbell/boots/installers/nixos"
	_ "github.com/tinkerbell/boots/installers/osie"
	_ "github.com/tinkerbell/boots/installers/rancher"
	_ "github.com/tinkerbell/boots/installers/vmware"
)

var (
	client                *packet.Client
	apiBaseURL            = env.URL("API_BASE_URL", "https://api.packet.net")
	provisionerEngineName = env.Get("PROVISIONER_ENGINE_NAME", "packet")

	mainlog log.Logger

	GitRev    = "unknown (use make)"
	StartTime = time.Now()
)

func main() {
	fs := flag.NewFlagSet("boots", flag.ExitOnError)
	var (
		dhcpAddr      = fs.String("dhcp-addr", conf.BOOTPBind, "IP and port to listen on for DHCP.")
		httpAddr      = fs.String("http-addr", conf.HTTPBind, "IP and port to listen on for HTTP.")
		tftpAddr      = fs.String("tftp-addr", conf.TFTPBind, "IP and port to listen on for TFTP.")
		proxyDHCPAddr = fs.String("proxyDHCP-addr", "0.0.0.0:67", "IP and port to listen on for proxyDHCP requests.")
		proxyDHCP     = fs.Bool("proxyDHCP", false, "Enables proxyDHCP only")
		publicFDQN    = fs.String("public-fqdn", "boots", "public FQDN of boots.")
	)
	ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix("BOOTS"))

	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer done()

	l, err := log.Init("github.com/tinkerbell/boots")
	if err != nil {
		panic(nil)
	}
	defer l.Close()
	mainlog = l.Package("main")
	metrics.Init(l)
	dhcp.Init(l)
	conf.Init(l)
	httplog.Init(l)
	installers.Init(l)
	job.Init(l)
	syslog.Init(l)
	tftp.Init(l)
	mainlog.With("version", GitRev).Info("starting")

	consumer := env.Get("API_CONSUMER_TOKEN")
	if consumer == "" {
		err := errors.New("required envvar missing")
		mainlog.With("envvar", "API_CONSUMER_TOKEN").Fatal(err)
		panic(err)
	}
	auth := env.Get("API_AUTH_TOKEN")
	if auth == "" {
		err := errors.New("required envvar missing")
		mainlog.With("envvar", "API_AUTH_TOKEN").Fatal(err)
		panic(err)
	}

	go func() {
		mainlog.Info("serving syslog")
		err = retry.Do(
			func() error {
				_, err := syslog.StartReceiver(1)
				return err
			},
		)
		if err != nil {
			mainlog.Fatal(errors.Wrap(err, "retry syslog serve"))
		}
	}()
	client, err = packet.NewClient(consumer, auth, apiBaseURL)
	if err != nil {
		mainlog.Fatal(err)
	}
	job.SetClient(client)
	g, ctx := errgroup.WithContext(ctx)
	if *proxyDHCP {
		mainlog.With("address", *proxyDHCPAddr).Info("serving proxyDHCP")
		g.Go(func() error { return runProxyDHCP(ctx, mainlog, *proxyDHCPAddr, *tftpAddr, *httpAddr, *publicFDQN) })
	} else {
		job.SetProvisionerEngineName(provisionerEngineName)
		mainlog.With("address", dhcpAddr).Info("serving dhcp")
		g.Go(func() error { return ServeDHCP(ctx, *dhcpAddr) })
	}
	mainlog.With("address", tftpAddr).Info("serving tftp")
	g.Go(func() error { return ServeTFTP(ctx, *tftpAddr) })
	mainlog.With("address", httpAddr).Info("serving http")
	g.Go(func() error { return ServeHTTP(ctx, *httpAddr) })

	err = g.Wait()
	if errors.Is(err, context.Canceled) {
		mainlog.Info("signal caught")
	} else if err != nil {
		mainlog.Error(err, "services failed")
	}
	mainlog.Info("boots shutdown")
}

// runProxyDHCP is a place holder for proxyDHCP being a proper subcommand
// its goal is to serves proxyDHCP requests
func runProxyDHCP(ctx context.Context, logger log.Logger, proxyAddr, tftpAddr, httpAddr, publicFDQN string) error {
	bootfile := func(arch, uClass, hwID string) string {
		// business logic of what to give a pxe client
		// lookup hardware id in tink for
		filename := "/nonexistent"
		switch strings.ToLower(uClass) {
		case "ipxe", "tinkerbell":
			filename = fmt.Sprintf("http://%v/auto.ipxe", publicFDQN)
		default:
			switch strings.ToLower(arch) {
			case "hua", "2a2":
				filename = "snp-hua.efi"
			case "aarch64":
				filename = "snp-nolacp.efi"
			case "uefi":
				filename = "ipxe.efi"
			default:
				filename = "undionly.kpxe"
			}
		}
		return filename
	}
	bootserver := func() string {
		return publicFDQN
	}
	return proxy.Serve(ctx, mainlog, proxyAddr, bootfile, bootserver)
}
