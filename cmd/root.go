package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"github.com/istio-doctor/pkg/client"
)

var (
	cfgFile    string
	kubeconfig string
	context    string
	namespace  string
	outputFmt  string
	verbose    bool
	noColor    bool
	workers    int
	timeout    int

	Logger *zap.SugaredLogger
	Client *client.IstioClient
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "istio-doctor",
	Short: "Production-grade Istio debugging utility for large-scale clusters",
	Long: color.CyanString(`
 ██╗███████╗████████╗██╗ ██████╗       ██████╗  ██████╗  ██████╗████████╗ ██████╗ ██████╗ 
 ██║██╔════╝╚══██╔══╝██║██╔═══██╗      ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
 ██║███████╗   ██║   ██║██║   ██║█████╗██║  ██║██║   ██║██║        ██║   ██║   ██║██████╔╝
 ██║╚════██║   ██║   ██║██║   ██║╚════╝██║  ██║██║   ██║██║        ██║   ██║   ██║██╔══██╗
 ██║███████║   ██║   ██║╚██████╔╝      ██████╔╝╚██████╔╝╚██████╗   ██║   ╚██████╔╝██║  ██║
 ╚═╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝       ╚═════╝  ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
`) + `
  Production-grade Istio debugging for large-scale Kubernetes clusters.
  Supports 2000+ nodes, 50k+ pods with parallel collection and smart triage.
`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip client init for help/completion
		if cmd.Name() == "help" || cmd.Name() == "__complete" {
			return nil
		}
		if noColor {
			color.NoColor = true
		}
		initLogger()
		return initClient()
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.istio-doctor.yaml)")
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	rootCmd.PersistentFlags().StringVar(&context, "context", "", "kubeconfig context to use")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "namespace to scope operation (default: all namespaces)")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "output format: table|json|yaml|prometheus")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")
	rootCmd.PersistentFlags().IntVar(&workers, "workers", 50, "number of parallel workers for data collection")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 30, "timeout in seconds for operations")

	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("workers", rootCmd.PersistentFlags().Lookup("workers"))

	rootCmd.AddCommand(
		summaryCmd,
		checkCmd,
		traceCmd,
		auditCmd,
		simulateCmd,
		reportCmd,
	)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home)
		}
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".istio-doctor")
	}
	viper.SetEnvPrefix("ISTIO_DOCTOR")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	viper.ReadInConfig()
}

func initLogger() {
	level := zapcore.InfoLevel
	if verbose {
		level = zapcore.DebugLevel
	}
	cfg := zap.Config{
		Level:       zap.NewAtomicLevelAt(level),
		Development: false,
		Encoding:    "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
	logger, _ := cfg.Build()
	Logger = logger.Sugar()
}

func initClient() error {
	var err error
	Client, err = client.New(client.Config{
		Kubeconfig: kubeconfig,
		Context:    context,
		Workers:    workers,
		Timeout:    timeout,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize client: %w", err)
	}
	return nil
}
