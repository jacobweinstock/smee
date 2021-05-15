package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/packethost/pkg/env"
	"github.com/packethost/pkg/log"
	"github.com/peterbourgon/ff/v3"
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
		proxyDHCPAddr = fs.String("proxyDHCP-addr", conf.ProxyDHCP, "IP and port to listen on for proxyDHCP requests.")
		disableDHCP   = fs.Bool("disableDHCP", false, "Disable serving DHCP")
		disablePXE    = fs.Bool("disablePXE", false, "Disable serving PXE")
	)
	ff.Parse(fs, os.Args[1:])

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		signal.Stop(signals)
		cancel()
	}()

	go func() {
		select {
		case <-signals:
			cancel()
		case <-ctx.Done():
		}
	}()

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
	/*
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
		client, err = packet.NewClient(consumer, auth, apiBaseURL)
		if err != nil {
			mainlog.Fatal(err)
		}
		job.SetClient(client)
		job.SetProvisionerEngineName(provisionerEngineName)

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
	*/

	if !*disableDHCP {
		mainlog.With("address", dhcpAddr).Info("serving dhcp")
		go ServeDHCP(*dhcpAddr)
	}
	if !*disablePXE {
		mainlog.With("address", tftpAddr).Info("serving tftp")
		go ServeTFTP(*tftpAddr)
		mainlog.With("address", httpAddr).Info("serving http")
		go ServeHTTP(*httpAddr)
		mainlog.With("address", *proxyDHCPAddr).Info("serving proxyDHCP")
		go proxy.Serve(ctx, mainlog, *proxyDHCPAddr)
	}
	<-ctx.Done()
	mainlog.Info("shutting down")
}
