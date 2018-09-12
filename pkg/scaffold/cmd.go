package scaffold

import (
	"io"

	yaml "gopkg.in/yaml.v2"
)

type cmd struct {
	// ProjectPath is the project path rooted at GOPATH.
	ProjectPath string
}

func renderCmd(w io.Writer, projectPath string) error {
	o, err := yaml.Marshal(&cmd{
		ProjectPath: projectPath,
	})
	if err != nil {
		return err
	}

	_, err = w.Write(o)
	return err
}

const main_tml = `package main

import (
	"flag"
	"log"
	"runtime"

	"{{projectPath}}/pkg/apis"
	"{{projectPath}}/pkg/controller"

	k8sutil "github.com/operator-framework/operator-sdk/pkg/util/k8sutil"
	sdkVersion "github.com/operator-framework/operator-sdk/version"
	"github.com/sirupsen/logrus"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/runtime/signals"
)

func printVersion() {
	logrus.Infof("Go Version: %s", runtime.Version())
	logrus.Infof("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH)
	logrus.Infof("operator-sdk Version: %v", sdkVersion.Version)
}

func main() {
	printVersion()
	flag.Parse()

	namespace, err := k8sutil.GetWatchNamespace()
	if err != nil {
		log.Fatal("Failed to get watch namespace: %v", err)
	}

	// Expose metrics port after SDK uses controller-runtime's dynamic client
	// sdk.ExposeMetricsPort()

	// Get a config to talk to the apiserver
	cfg, err := config.GetConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Cmd to provide shared dependencies and start components
	// TODO: Need to support namespacing the manager upstream to avoid cluster wide permissions
	// https://github.com/kubernetes-sigs/controller-runtime/issues/124
	mgr, err := manager.New(cfg, manager.Options{Namespace: namespace})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Registering Components.")

	// Setup Scheme for all resources
	if err := apis.AddToScheme(mgr.GetScheme()); err != nil {
		log.Fatal(err)
	}

	// Setup all Controllers
	if err := controller.AddToManager(mgr); err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting the Cmd.")

	// Start the Cmd
	log.Fatal(mgr.Start(signals.SetupSignalHandler()))
}`
