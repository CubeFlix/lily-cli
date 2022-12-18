// cmd/cli.go
// Lily client command-line interface.

package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cubeflix/lily/client"
	"github.com/google/shlex"
	"github.com/google/uuid"
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
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s@%s> ", username, host)
		command, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Println("lily-cli:", err.Error())
			}
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
		args := split[1:]

		// Parse the command.
		switch name {
		case "quit", "exit", "logout":
			return
		case "info":
			// Get info.
			resp, err := Command("info", map[string]interface{}{}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			name, err := getParam(resp.Data, "name")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			version, err := getParam(resp.Data, "version")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			drives, err := getParam(resp.Data, "drives")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			defaultSessionExpiration, err := getDuration(resp.Data, "defaultSessionExpiration")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			allowChangeSessionExpiration, err := getParam(resp.Data, "allowChangeSessionExpiration")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			allowNonExpiringSessions, err := getParam(resp.Data, "allowNonExpiringSessions")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			timeout, err := getDuration(resp.Data, "timeout")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			limit, err := getDuration(resp.Data, "limit")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			maxLimitEvents, err := getParam(resp.Data, "maxLimitEvents")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			fmt.Println("name:", name)
			fmt.Println("version:", version)
			fmt.Println("drives:", drives)
			fmt.Println("defaultSessionExpiration:", defaultSessionExpiration)
			fmt.Println("allowChangeSessionExpiration:", allowChangeSessionExpiration)
			fmt.Println("allowNonExpiringSessions:", allowNonExpiringSessions)
			fmt.Println("timeout:", timeout)
			fmt.Println("limit:", limit)
			fmt.Println("maxLimitEvents:", maxLimitEvents)
		case "getallusers":
			resp, err := Command("getallusers", map[string]interface{}{}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			users, err := getSliceOfStrings(resp.Data, "users")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			fmt.Println(strings.Join(users, "\n"))
		case "getuserinformation":
			if len(args) < 1 {
				fmt.Println("invalid number of arguments")
				continue
			}
			resp, err := Command("getuserinformation", map[string]interface{}{"users": args}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			info, err := getSlice(resp.Data, "info")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			for i := range info {
				fmt.Println(info[i].(map[string]interface{})["username"])
				fmt.Println("	clearance:", info[i].(map[string]interface{})["clearance"])
				fmt.Printf("	password hash: %x\n", info[i].(map[string]interface{})["passwordhash"])
			}
		case "setuserclearance":
			if len(args) != 2 {
				fmt.Println("invalid number of arguments")
				continue
			}
			username := args[0]
			clearance, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			_, err = Command("setuserclearance", map[string]interface{}{"users": []string{username}, "clearances": []int{clearance}}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "setuserpassword":
			if len(args) != 2 {
				fmt.Println("invalid number of arguments")
				continue
			}
			username := args[0]
			password := args[1]
			_, err = Command("setuserpassword", map[string]interface{}{"users": []string{username}, "passwords": []string{password}}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "createuser":
			if len(args) != 3 {
				fmt.Println("invalid number of arguments")
				continue
			}
			username := args[0]
			password := args[1]
			clearance, err := strconv.Atoi(args[2])
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			_, err = Command("createusers", map[string]interface{}{"users": []string{username}, "passwords": []string{password}, "clearances": []int{clearance}}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "deleteuser":
			if len(args) != 1 {
				fmt.Println("invalid number of arguments")
				continue
			}
			username := args[0]
			_, err = Command("deleteusers", map[string]interface{}{"users": []string{username}}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "getallsessions":
			resp, err := Command("getallsessions", map[string]interface{}{}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			ids, err := getSlice(resp.Data, "ids")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			for i := range ids {
				id, err := uuid.FromBytes(ids[i].([]byte))
				if err != nil {
					fmt.Println(err.Error())
					continue
				}
				fmt.Println(id)
			}
		case "getallusersessions":
			if len(args) != 1 {
				fmt.Println("invalid number of arguments")
				continue
			}
			username := args[0]
			resp, err := Command("getallusersessions", map[string]interface{}{"user": username}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			ids, err := getSlice(resp.Data, "ids")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			for i := range ids {
				id, err := uuid.FromBytes(ids[i].([]byte))
				if err != nil {
					fmt.Println(err.Error())
					continue
				}
				fmt.Println(id)
			}
		case "getsessioninfo":
			if len(args) != 1 {
				fmt.Println("invalid number of arguments")
				continue
			}
			idString := args[0]
			id, err := uuid.Parse(idString)
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			bytes, err := id.MarshalBinary()
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			resp, err := Command("getsessioninfo", map[string]interface{}{"ids": [][]byte{bytes}}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			info, err := getSlice(resp.Data, "sessions")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			for i := range info {
				fmt.Println(id)
				fmt.Println("	username:", info[i].(map[string]interface{})["username"])
				fmt.Println("	expire after:", time.Duration(info[i].(map[string]interface{})["expireafter"].(int64)))
				fmt.Println("	expire at:", time.Unix(info[i].(map[string]interface{})["expireat"].(int64), 0))
			}
		case "expireallsessions":
			_, err = Command("expireallsessions", map[string]interface{}{}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "expiresession":
			if len(args) != 1 {
				fmt.Println("invalid number of arguments")
				continue
			}
			idString := args[0]
			id, err := uuid.Parse(idString)
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			bytes, err := id.MarshalBinary()
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			_, err = Command("expiresessions", map[string]interface{}{"ids": [][]byte{bytes}}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "getallsettings":
			resp, err := Command("getallsettings", map[string]interface{}{}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			host, err := getParam(resp.Data, "host")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			port, err := getParam(resp.Data, "port")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			drives, err := getParam(resp.Data, "drives")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			driveFiles, err := getParam(resp.Data, "driveFiles")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			numWorkers, err := getParam(resp.Data, "numWorkers")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			mainCronInterval, err := getDuration(resp.Data, "mainCronInterval")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			sessionCronInterval, err := getDuration(resp.Data, "sessionCronInterval")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			networkTimeout, err := getDuration(resp.Data, "networkTimeout")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			verbose, err := getParam(resp.Data, "verbose")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			logToFile, err := getParam(resp.Data, "logToFile")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			logJSON, err := getParam(resp.Data, "logJSON")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			logLevel, err := getParam(resp.Data, "logLevel")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			logFile, err := getParam(resp.Data, "logFile")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			limit, err := getDuration(resp.Data, "limit")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			maxLimitEvents, err := getParam(resp.Data, "maxLimitEvents")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			fmt.Println("name:", name)
			fmt.Println("host:", host)
			fmt.Println("port:", port)
			fmt.Println("drives:", drives)
			fmt.Println("driveFiles:", driveFiles)
			fmt.Println("numWorkers:", numWorkers)
			fmt.Println("mainCronInterval:", mainCronInterval)
			fmt.Println("sessionCronInterval:", sessionCronInterval)
			fmt.Println("networkTimeout:", networkTimeout)
			fmt.Println("verbose:", verbose)
			fmt.Println("logToFile:", logToFile)
			fmt.Println("logJSON:", logJSON)
			fmt.Println("logLevel:", logLevel)
			fmt.Println("logFile:", logFile)
			fmt.Println("limit:", limit)
			fmt.Println("maxLimitEvents:", maxLimitEvents)
		case "sethostandport":
			if len(args) != 2 {
				fmt.Println("invalid number of arguments")
				continue
			}
			host := args[0]
			port, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			_, err = Command("sethostandport", map[string]interface{}{"host": host, "port": port}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "adddrive":
			if len(args) != 2 {
				fmt.Println("invalid number of arguments")
				continue
			}
			name := args[0]
			path := args[1]
			_, err = Command("adddrive", map[string]interface{}{"name": name, "path": path}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "renamedrive":
			if len(args) != 2 {
				fmt.Println("invalid number of arguments")
				continue
			}
			drive := args[0]
			newName := args[1]
			_, err = Command("renamedrive", map[string]interface{}{"drive": drive, "newName": newName}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "removedrive":
			if len(args) != 1 {
				fmt.Println("invalid number of arguments")
				continue
			}
			drive := args[0]
			_, err = Command("removedrive", map[string]interface{}{"drive": drive}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "setnumworkers":
			if len(args) != 1 {
				fmt.Println("invalid number of arguments")
				continue
			}
			numWorkers, err := strconv.Atoi(args[0])
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			_, err = Command("setnumworkers", map[string]interface{}{"numWorkers": numWorkers}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "setcronintervals":
			if len(args) != 2 {
				fmt.Println("invalid number of arguments")
				continue
			}
			mainInterval, err := time.ParseDuration(args[0])
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			sessionInterval, err := time.ParseDuration(args[1])
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			_, err = Command("setcronintervals", map[string]interface{}{"mainInterval": mainInterval, "sessionInterval": sessionInterval}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "settimeoutinterval":
			if len(args) != 1 {
				fmt.Println("invalid number of arguments")
				continue
			}
			timeout, err := time.ParseDuration(args[0])
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			_, err = Command("settimeoutinterval", map[string]interface{}{"timeout": timeout}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "setloggingsettings":
			if len(args) != 5 {
				fmt.Println("invalid number of arguments")
				continue
			}
			verbose, err := strconv.ParseBool(args[0])
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			logToFile, err := strconv.ParseBool(args[1])
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			logJSON, err := strconv.ParseBool(args[2])
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			logLevel := args[3]
			logPath := args[4]
			_, err = Command("settimeoutinterval", map[string]interface{}{"verbose": verbose, "logToFile": logToFile, "logJSON": logJSON, "logLevel": logLevel, "logPath": logPath}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "setratelimit":
			if len(args) != 2 {
				fmt.Println("invalid number of arguments")
				continue
			}
			limit, err := time.ParseDuration(args[0])
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			maxLimitEvents, err := strconv.Atoi(args[0])
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			_, err = Command("setratelimit", map[string]interface{}{"limit": limit, "maxLimitEvents": maxLimitEvents}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
		case "shutdown":
			_, err = Command("shutdown", map[string]interface{}{}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			os.Exit(0)
		case "getmemoryusage":
			resp, err := Command("getmemoryusage", map[string]interface{}{}, c, auth, timeout)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			alloc, err := getParam(resp.Data, "alloc")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			total, err := getParam(resp.Data, "total")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			sys, err := getParam(resp.Data, "sys")
			if err != nil {
				fmt.Println("lily-cli:", err.Error())
				continue
			}
			fmt.Println("alloc:", alloc)
			fmt.Println("total:", total)
			fmt.Println("sys:", sys)
		default:
			fmt.Println("command not recognized")
		}
	}
}
