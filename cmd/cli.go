// cmd/cli.go
// Lily client command-line interface.

package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cubeflix/lily/client"
	"github.com/google/shlex"
	"github.com/spf13/cobra"
)

// Command-line interface.
func CLICommand(cmd *cobra.Command, args []string) {
	// Get the host name, username, and password.
	timeoutDuration, err := time.ParseDuration(timeout)
	if err != nil {
		fmt.Println("lily-cli:", err.Error())
	}

	for host == "" {
		fmt.Printf("server hostname: ")
		fmt.Scanln(&host)
	}
	for username == "" {
		fmt.Printf("username: ")
		fmt.Scanln(&username)
	}
	for password == "" {
		fmt.Printf("password: ")
		fmt.Scanln(&password)
	}

	StartCLI(host, port, username, password, certFile, keyFile, insecureSkipVerify, useCerts, timeoutDuration)
}

// Login.
func Login(host string, port int, username, password, certFile, keyFile string, insecureSkipVerify, useCerts bool, timeout time.Duration) (*client.Client, *client.SessionAuth, error) {
	c := client.NewClient(host, port, certFile, keyFile, insecureSkipVerify, useCerts)
	resp, err := c.MakeNonChunkRequest(*client.NewRequest(client.NewUserAuth(username, password), "login", map[string]interface{}{}, timeout))
	if err != nil {
		return nil, nil, err
	}
	if resp.Code != 0 {
		return nil, nil, errors.New("failed to log in: error code " + strconv.Itoa(resp.Code) + " " + resp.String)
	}
	return c, client.NewSessionAuth(username, resp.Data["id"].([]byte)), nil
}

// Logout.
func Logout(c *client.Client, auth *client.SessionAuth, timeout time.Duration) error {
	resp, err := c.MakeNonChunkRequest(*client.NewRequest(auth, "logout", map[string]interface{}{}, timeout))
	if err != nil {
		return err
	}
	if resp.Code != 0 {
		return errors.New("failed to log out: error code " + strconv.Itoa(resp.Code) + " " + resp.String)
	}
	return nil
}

// Run a command.
func Command(name string, params map[string]interface{}, c *client.Client, auth client.Auth, timeout time.Duration) (client.Response, error) {
	resp, err := c.MakeNonChunkRequest(*client.NewRequest(auth, name, params, timeout))
	if err != nil {
		return resp, err
	}
	if resp.Code != 0 {
		return resp, errors.New("failed: error code " + strconv.Itoa(resp.Code) + " " + resp.String)
	}
	return resp, nil
}

// Start the CLI.
func StartCLI(host string, port int, username, password, certFile, keyFile string, insecureSkipVerify, useCerts bool, timeout time.Duration) {
	// Login.
	c, auth, err := Login(host, port, username, password, certFile, keyFile, insecureSkipVerify, useCerts, timeout)
	if err != nil {
		fmt.Println("lily-cli:", err.Error())
		return
	}

	fmt.Println("logged in successfully")
	defer func() {
		err := Logout(c, auth, timeout)
		if err != nil {
			fmt.Println("lily-cli:", err.Error())
		}
		fmt.Println("logged out successfully")
	}()

	go func() {
		for {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			<-sig
			err := Logout(c, auth, timeout)
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
			}
			fmt.Println("logged out successfully")
			os.Exit(0)
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s@%s> ", username, host)
		command, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("lily-cli:", err.Error())
			return
		}
		split, err := shlex.Split(command)
		if err != nil {
			fmt.Println("lily-cli:", err.Error())
			return
		}
		if len(split) == 0 {
			continue
		}
		name := strings.ToLower(split[0])
		if name == "quit" || name == "exit" {
			break
		}

		// Parse the command.
		if name == "info" {
			// Get info.
			resp, err := Command("info", map[string]interface{}{}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			fmt.Println("name:", resp.Data["name"])
			fmt.Println("version:", resp.Data["version"])
			fmt.Println("drives:", resp.Data["drives"])
			fmt.Println("defaultSessionExpiration:", time.Duration(resp.Data["defaultSessionExpiration"].(int64)))
			fmt.Println("allowChangeSessionExpiration:", resp.Data["allowChangeSessionExpiration"])
			fmt.Println("allowNonExpiringSessions:", resp.Data["allowNonExpiringSessions"])
			fmt.Println("timeout:", time.Duration(resp.Data["timeout"].(int64)))
			fmt.Println("limit:", time.Duration(resp.Data["limit"].(int64)))
			fmt.Println("maxLimitEvents:", resp.Data["maxLimitEvents"])
		} else {
			fmt.Println("command not recognized")
		}
	}
}
