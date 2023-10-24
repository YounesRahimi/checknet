package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gen2brain/beeep"
	_ "golang.org/x/net/context"
	"golang.org/x/sys/windows"

	_ "modernc.org/sqlite"
)

const (
	dbPath      = "ip_cache.db"
	ipInfoTable = "ip_info"
)

var (
	apiKey           string
	showNotification bool
	showAlert        bool
	lock             sync.Mutex
	lastEventTime    time.Time
	notifyInterval   time.Duration
	checkingInterval time.Duration
	killSwitch       bool
	switchStarted    bool
)

func init() {
	// Define command-line flags
	flag.StringVar(&apiKey, "api-key", "", "API key from ipinfo.io (required)")
	flag.BoolVar(&showNotification, "show-notification", true, "Enable notifications")
	flag.BoolVar(&showAlert, "show-alert", false, "Show alert (warning sound)")
	flag.DurationVar(&notifyInterval, "notify-interval", 20*time.Second, "Notification interval")
	flag.DurationVar(&checkingInterval, "checking-interval", 3*time.Second, "Warning interval")
	flag.BoolVar(&killSwitch, "kill-switch", false, "Kill Switch in case of leakage")

	// Parse command-line arguments
	flag.Parse()

	// Check if the API key is provided
	if apiKey == "" {
		fmt.Println("API key is required. Please use the --api-key flag.")
		os.Exit(1)
	}

	// if not elevated, relaunch by shellexecute with runas verb set
	if killSwitch && !amAdmin() {
		runMeElevated()
		os.Exit(-1)
	}
}

func runMeElevated() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}
}

func amAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		fmt.Println("admin no")
		return false
	}
	fmt.Println("admin yes")
	return true
}

func main() {
	// Create channels for notifications and warnings
	notifyChan := make(chan string)
	alertChan := make(chan string)
	killSwitchChan := make(chan bool)

	checkIp(notifyChan, alertChan, killSwitchChan)

	// Check IP location in the background with the specified interval
	go func() {
		ticker := time.NewTicker(notifyInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				checkIp(notifyChan, alertChan, killSwitchChan)
			}
		}
	}()

	shouldKill := false
	// Handle notifications and warnings with a lock
	for {
		select {
		case msg := <-notifyChan:
			// Acquire the lock and check if it's been more than the notification interval since the last event
			lock.Lock()
			if time.Since(lastEventTime) > notifyInterval {
				lastEventTime = time.Now()
				lock.Unlock()

				// Display a notification if not in U.S. location and notifications are enabled
				if showNotification {
					err := showNotificationOS("Error", msg)
					if err != nil {
						fmt.Println("Error displaying notification:", err)
					}
				}
			} else {
				lock.Unlock()
			}
		case msg := <-alertChan:
			// Acquire the lock and check if it's been more than the notify interval since the last event
			lock.Lock()
			if time.Since(lastEventTime) > notifyInterval {
				lastEventTime = time.Now()
				lock.Unlock()

				// Play a warning sound if not in U.S. location and warnings are enabled
				if showAlert {
					err := playWarningSoundOS("Error", msg)
					if err != nil {
						fmt.Println("Error playing warning sound:", err)
					}
				}
			} else {
				lock.Unlock()
			}
		case shouldKill = <-killSwitchChan:

			// Shutdown Wi-Fi network interface if not in U.S. location and kill-switch is enabled
			if killSwitch && shouldKill {
				err := disableNetworkInterface()
				if err != nil {
					fmt.Println("Error executing kill-switch:", err)
				} else {
					switchStarted = false
				}
			}
			if killSwitch && !shouldKill && !switchStarted {
				err := enableNetworkInterface()
				if err != nil {
					fmt.Println("Error enabling Wi-Fi:", err)
				} else {
					switchStarted = true
				}

			}
		}
	}
}

func checkIp(notifyChan chan string, alertChan chan string, killSwitchChan chan bool) {
	isInUS, err := isPublicIPInUS()
	if err != nil {
		strings.Contains(err.Error(), "")
		fmt.Println("Error:", err)
	}
	errorSubStr := "Client.Timeout exceeded while awaiting headers"
	if err != nil && !strings.Contains(err.Error(), errorSubStr) {
		return
	}

	msg := "Check the logs"
	if err != nil && strings.Contains(err.Error(), errorSubStr) {
		msg = "Deadline exceeded"
	}
	if !isInUS {
		if showNotification {
			notifyChan <- msg
		}
		if showAlert {
			alertChan <- msg
		}
		if killSwitch {
			killSwitchChan <- true
		}
	} else {
		if killSwitch {
			killSwitchChan <- false
		}

	}
}

type IPInfo struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	City      string `json:"city"`
	Region    string `json:"region"`
	Country   string `json:"country"`
	Loc       string `json:"loc"`
	Org       string `json:"org"`
	Postal    string `json:"postal"`
	Timezone  string `json:"timezone"`
	Timestamp time.Time
}

func isPublicIPInUS() (bool, error) {
	// Initialize the SQLite database
	db, err := initDB()
	if err != nil {
		return false, err
	}
	defer db.Close()

	publicIp, err := getPublicIP()
	if err != nil {
		return false, err
	}

	// Check if the cache contains recent IP information
	ipInfo, err := readCache(db, publicIp)
	if err != nil {
		return false, err
	}

	// If cache is empty or stale, fetch new IP information
	if ipInfo == nil || time.Since(ipInfo.Timestamp) > 31*24*time.Hour {
		ipInfo, err = fetchIPInfo(publicIp)
		if err != nil {
			return false, err
		}

		// Update the cache with the new IP information
		err = writeCache(db, ipInfo)
		if err != nil {
			return false, err
		}
	}

	// Check if the country code is "US" to determine if the IP is in the U.S. IP range
	return ipInfo.Country == "US", nil
}

func initDB() (*sql.DB, error) {
	// Initialize the SQLite database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Create the ip_info table if it doesn't exist
	createTableSQL := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL UNIQUE,
			city TEXT,
			region TEXT,
			country TEXT,
			timezone TEXT,
			created_at DATETIME NOT NULL
		);
		-- CREATE INDEX IF NOT EXISTS idx_ip ON %s (ip);
	`, ipInfoTable, ipInfoTable)

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func fetchIPInfo(publicIp *net.IP) (*IPInfo, error) {

	// Make a GET request to ipinfo.io to get information about your public IP
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://ipinfo.io?token=" + apiKey)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	bodyStr := string(bodyBytes)
	fmt.Printf("Fetched the IP info response: %v\n", bodyStr)

	if strings.Contains(bodyStr, "Your client does not have permission to get URL") {
		return &IPInfo{
			IP:        publicIp.String(),
			Hostname:  "",
			City:      "",
			Region:    "",
			Country:   "???",
			Loc:       "",
			Org:       "",
			Postal:    "",
			Timezone:  "",
			Timestamp: time.Now(),
		}, nil

	}

	var ipInfo IPInfo
	err = json.Unmarshal(bodyBytes, &ipInfo)
	if err != nil {
		return nil, err
	}

	ipInfo.Timestamp = time.Now()
	fmt.Printf("Fetched the IP info: %v\n", ipInfo)

	return &ipInfo, nil
}

func getPublicIP() (*net.IP, error) {
	// Get the public IP address
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DisableKeepAlives = true
	client := &http.Client{Transport: t, Timeout: 10 * time.Second}
	resp, err := client.Get("http://icanhazip.com")
	if err != nil {
		fmt.Printf("Failed to get public IP: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()
	ipBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read IP response: %v\n", err)
		return nil, err
	}
	publicIP := strings.TrimSpace(string(ipBytes))

	ip := net.ParseIP(publicIP)
	if ip == nil {
		fmt.Println("Invalid IP address")
		return nil, fmt.Errorf("invalid IP address: %v", ip)
	}

	fmt.Printf("%v\n", ip)

	return &ip, nil
}

func readCache(db *sql.DB, publicIp *net.IP) (*IPInfo, error) {
	// Query the most recent IPInfo for a specific IP from the database
	query := fmt.Sprintf("SELECT ip, city, region, country, created_at FROM %s WHERE ip = ? ORDER BY created_at DESC LIMIT 1;", ipInfoTable)
	row := db.QueryRow(query, publicIp.String())

	var ip, city, region, country string
	var createdAt time.Time
	err := row.Scan(&ip, &city, &region, &country, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Cache is empty for the specified IP
		}
		return nil, err
	}

	// Create an IPInfo struct with the scanned values
	ipInfo := &IPInfo{
		IP:        ip,
		City:      city,
		Region:    region,
		Country:   country,
		Timestamp: createdAt,
	}

	return ipInfo, nil
}

func writeCache(db *sql.DB, ipInfo *IPInfo) error {
	// Insert the IPInfo into the database
	insertSQL := fmt.Sprintf("INSERT INTO %s (ip, city, region, country, timezone, created_at) VALUES (?, ?, ?, ?, ?, ?);", ipInfoTable)
	_, err := db.Exec(insertSQL, ipInfo.IP, ipInfo.City, ipInfo.Region, ipInfo.Country, ipInfo.Timezone, ipInfo.Timestamp)
	if err != nil {
		return err
	}

	return nil
}

func showNotificationOS(title, message string) error {
	if true {
		return beeep.Notify(title, message, "assets/information.png")
	}

	switch runtime.GOOS {
	case "linux":
		// Use the "notify-send" command to display a notification on Linux
		cmd := exec.Command("notify-send", title, message)
		return cmd.Run()
	case "darwin":
		// Use AppleScript to display a notification on macOS
		cmd := exec.Command("osascript", "-e", fmt.Sprintf(`display notification "%s" with title "%s"`, message, title))
		return cmd.Run()
	case "windows":
		// Use the "msg" command to display a message as a notification on Windows
		return beeep.Notify("Title 2", "Message body", "assets/information.png")
		// cmd := exec.Command("msg", "*", fmt.Sprintf(`%s: %s`, title, message))
		// return cmd.Run()
	}
	return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
}

func disableNetworkInterface() error {
	switch runtime.GOOS {
	case "windows":
		// Disable Wi-Fi on Windows using the netsh command
		cmd := exec.Command("netsh", "interface", "set", "interface", "Wi-Fi", "admin=disable")
		err := cmd.Run()
		if err != nil {
			return err
		} else {
			fmt.Println("Wi-Fi disabled successfully.")
			return nil
		}
	default:
		return fmt.Errorf("Wi-Fi control is not supported on this operating system.")
	}

}

func enableNetworkInterface() error {
	switch runtime.GOOS {
	case "windows":
		// Disable Wi-Fi on Windows using the netsh command
		cmd := exec.Command("netsh", "interface", "set", "interface", "Wi-Fi", "admin=enable")
		err := cmd.Run()
		if err != nil {
			return err
		} else {
			fmt.Println("Wi-Fi enabled successfully.")
			return nil
		}
	default:
		return fmt.Errorf("Wi-Fi control is not supported on this operating system.")
	}

}

func playWarningSoundOS(title, message string) error {
	if true {
		return beeep.Alert(title, message, "assets/warning.png")
	}

	switch runtime.GOOS {
	case "linux":
		// Use the "beep" command to play the system default beep sound on Linux
		cmd := exec.Command("beep")
		return cmd.Run()
	case "darwin":
		// Use macOS-specific "afplay" to play the default system alert sound on macOS
		cmd := exec.Command("afplay", "/System/Library/Sounds/Basso.aiff")
		return cmd.Run()
	case "windows":
		// return beeep.Beep(beeep.DefaultFreq, beeep.DefaultDuration)
		return beeep.Alert("Title", "Message body", "assets/warning.png")
	}
	return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
}
