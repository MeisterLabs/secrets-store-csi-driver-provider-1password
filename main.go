// Copyright 2020 Google LLC
// Copyright 2023 MeisterLabs Gmbh
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Binary secrets-store-csi-driver-provider-1password is a plugin for the
// secrets-store-csi-driver for fetching secrets from the 1Password API
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/martyn-meister/secrets-store-csi-driver-provider-1password/server"
	"github.com/martyn-meister/secrets-store-csi-driver-provider-1password/infra"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"google.golang.org/grpc"
	/*
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"*/
	logsapi "k8s.io/component-base/logs/api/v1"
	jlogs "k8s.io/component-base/logs/json"
	"k8s.io/klog/v2"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

var (
	kubeconfig            = flag.String("kubeconfig", "", "absolute path to kubeconfig file")
	logFormatJSON         = flag.Bool("log-format-json", true, "set log formatter to json")
	metricsAddr           = flag.String("metrics_addr", ":8095", "configure http listener for reporting metrics")
	enableProfile         = flag.Bool("enable-pprof", false, "enable pprof profiling")
	debugAddr             = flag.String("debug_addr", "localhost:6060", "port for pprof profiling")
	_                     = flag.Bool("write_secrets", false, "[unused]")
	smConnectionPoolSize  = flag.Int("sm_connection_pool_size", 5, "size of the connection pool for the secret manager API client")
	iamConnectionPoolSize = flag.Int("iam_connection_pool_size", 5, "size of the connection pool for the IAM API client")

	version = "dev"
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	flag.Parse()

	if *logFormatJSON {
		jsonFactory := jlogs.Factory{}
		logger, _ := jsonFactory.Create(logsapi.LoggingConfiguration{Format: "json"})
		klog.SetLogger(logger)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ua := fmt.Sprintf("secrets-store-csi-driver-provider-1password/%s", version)
	klog.InfoS(fmt.Sprintf("starting %s", ua))

	/*
	// Kubernetes Client
	var rc *rest.Config
	var err error
	if *kubeconfig != "" {
		klog.V(5).InfoS("using kubeconfig", "path", *kubeconfig)
		rc, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	} else {
		klog.V(5).InfoS("using in-cluster kubeconfig")
		rc, err = rest.InClusterConfig()
	}
	if err != nil {
		klog.ErrorS(err, "failed to read kubeconfig")
		klog.Fatal("failed to read kubeconfig")
	}

	clientset, err := kubernetes.NewForConfig(rc)
	if err != nil {
		klog.ErrorS(err, "failed to configure k8s client")
		klog.Fatal("failed to configure k8s client")
	}

	// HTTP client
	hc := &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   2 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
		},
		Timeout: 60 * time.Second,
	}
*/
	// setup provider grpc server
	s := &server.Server{
	}

	socketPath := filepath.Join(os.Getenv("TARGET_DIR"), "1password.sock")
	// Attempt to remove the UDS to handle cases where a previous execution was
	// killed before fully closing the socket listener and unlinking.
	_ = os.Remove(socketPath)

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		klog.ErrorS(err, "unable to listen to unix socket", "path", socketPath)
		klog.Fatalln("unable to start")
	}
	defer l.Close()

	g := grpc.NewServer(
		grpc.UnaryInterceptor(infra.LogInterceptor()),
	)
	v1alpha1.RegisterCSIDriverProviderServer(g, s)
	go g.Serve(l)

	// initialize metrics and health http server
	mux := http.NewServeMux()
	ms := http.Server{
		Addr:        *metricsAddr,
		Handler:     mux,
		ReadTimeout: 10 * time.Second,
	}
	defer ms.Shutdown(ctx)

	_, err = otelprom.New()
	if err != nil {
		klog.ErrorS(err, "unable to initialize prometheus registry")
		klog.Fatalln("unable to initialize prometheus registry")
	}

	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	go func() {
		if err := ms.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			klog.ErrorS(err, "metrics http server error")
		}
	}()
	klog.InfoS("health server listening", "addr", *metricsAddr)

	if *enableProfile {
		dmux := http.NewServeMux()
		dmux.HandleFunc("/debug/pprof/", pprof.Index)
		dmux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		dmux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		dmux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		dmux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		ds := http.Server{
			Addr:        *debugAddr,
			Handler:     dmux,
			ReadTimeout: 10 * time.Second,
		}
		defer ds.Shutdown(ctx)
		go func() {
			if err := ds.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				klog.ErrorS(err, "debug http server error")
			}
		}()
		klog.InfoS("debug server listening", "addr", *debugAddr)
	}

	<-ctx.Done()
	klog.InfoS("terminating")
	g.GracefulStop()
}
