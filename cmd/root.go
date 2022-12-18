// cmd/root.go
// Server main command.

package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/cubeflix/lily/version"
	"github.com/spf13/cobra"
)

var host string
var port int
var username string
var password string
var certFile string
var keyFile string
var insecureSkipVerify bool
var useCerts bool
var timeout string

// Base Lily command.
var RootCmd = &cobra.Command{
	Use:   "lily-cli",
	Short: "The command-line interface for Lily, a secure file server.",
	Long:  `lily-cli is the Lily file server client program.`,
	Run:   CLICommand,
}

// Version command.
var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version and exit.",
	Long:  `Print the Lily version number.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("lily", version.VERSION, runtime.GOOS)
	},
}

// Execute the root command.
func Execute() {
	// Execute the main command.
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Init cobra.
func init() {
	// Set the arguments.
	RootCmd.PersistentFlags().StringVarP(&host, "host", "s", "", "The host to connect to")
	RootCmd.PersistentFlags().IntVar(&port, "port", 42069, "The port to connect to")
	RootCmd.PersistentFlags().StringVarP(&username, "username", "u", "", "The port to connect to")
	RootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "The port to connect to")
	RootCmd.PersistentFlags().StringVar(&certFile, "cert", "", "The optional certificate file")
	RootCmd.PersistentFlags().StringVar(&keyFile, "key", "", "The optional key file")
	RootCmd.PersistentFlags().BoolVar(&insecureSkipVerify, "insecure", false, "If we should ignore the certificate from the server")
	RootCmd.PersistentFlags().BoolVar(&useCerts, "use-certs", false, "If we should use client certificates")
	RootCmd.PersistentFlags().StringVarP(&timeout, "timeout", "t", "5s", "The timeout for the client")

	// Add the commands.
	RootCmd.AddCommand(VersionCmd)
}
