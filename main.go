package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var resolverEndpoint = flag.String("resolver-endpoint", "[fd42:d42:d42:54::1]:53", "The DNS resolver endpoint to use")
var allowInsecure = flag.Bool("allow-insecure", false, "Allow insecure connections")
var feedSourceURL = flag.String("feed-source-url", "https://flaps.collector.dn42/flaps/active/compact", "The URL of the feed source")
var bindUnixSocket = flag.String("bind-unix-socket", "/var/run/flapprefixes.sock", "The Unix socket to bind to")

type FlapPrefixes struct {
	Prefixes []*net.IPNet
}

func generateTestCodeBlock(prefixes []*net.IPNet) []string {
	lines := make([]string, 0)
	lines = append(lines, "        if net ~ [")
	for lineidx, network := range prefixes {
		line := fmt.Sprintf("            %s", network.String())
		if lineidx < len(prefixes)-1 {
			line += ","
		}
		lines = append(lines, line)
	}
	lines = append(lines, "        ] then {")
	lines = append(lines, "            return true;")
	lines = append(lines, "        }")
	return lines
}

func (prefixes *FlapPrefixes) ToBirdTesterFunction() string {
	lines := make([]string, 0)
	lines = append(lines, "function is_flap_prefix(prefix net) -> bool {")

	v4Networks := make([]*net.IPNet, 0)
	v6Networks := make([]*net.IPNet, 0)
	for _, prefix := range prefixes.Prefixes {
		if ip4 := prefix.IP.To4(); ip4 != nil {
			v4Networks = append(v4Networks, prefix)
		} else {
			v6Networks = append(v6Networks, prefix)
		}
	}

	if len(v4Networks) > 0 {
		lines = append(lines, "    if net.type = NET_IP4 then {")
		lines = append(lines, generateTestCodeBlock(v4Networks)...)
		lines = append(lines, "    }")
	}

	if len(v6Networks) > 0 {
		lines = append(lines, "    if net.type = NET_IP6 then {")
		lines = append(lines, generateTestCodeBlock(v6Networks)...)
		lines = append(lines, "    }")
	}

	lines = append(lines, "    return false;")
	lines = append(lines, "}")
	return strings.Join(lines, "\n")
}

type KioubitsFeedSource struct {
	URL string
}

func NewKioubitsFeedSource(url string) (*KioubitsFeedSource, error) {
	feedSource := &KioubitsFeedSource{URL: url}
	return feedSource, nil
}

func getCustomHTTPClient(resolverEndpoint *string, allowInsecure *bool) (*http.Client, error) {
	var customResolver *net.Resolver
	if resolverEndpoint != nil {
		customResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 10 * time.Second,
				}
				return d.DialContext(ctx, network, *resolverEndpoint) // Replace with your desired DNS server
			},
		}
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  customResolver, // Assign the custom resolver to the dialer
	}

	var tlsConfig *tls.Config
	if allowInsecure != nil && *allowInsecure {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Transport: tr}, nil
}

func (kbFS *KioubitsFeedSource) GetPrefixes() (*FlapPrefixes, error) {

	client, err := getCustomHTTPClient(resolverEndpoint, allowInsecure)
	if err != nil {
		return nil, fmt.Errorf("failed to create custom HTTP client: %w", err)
	}

	resp, err := client.Get(kbFS.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to get prefixes from %s: %w", kbFS.URL, err)
	}
	defer resp.Body.Close()
	type kioubitsRespEntry struct {
		Prefix     string `json:"Prefix"`
		TotalCount *int   `json:"TotalCount,omitempty"`
	}
	type kioubitsResp []kioubitsRespEntry
	respData := new(kioubitsResp)
	if err := json.NewDecoder(resp.Body).Decode(respData); err != nil {
		return nil, fmt.Errorf("failed to decode prefixes from %s: %w", kbFS.URL, err)
	}
	prefixes := make([]*net.IPNet, 0)
	for _, entry := range *respData {
		_, network, err := net.ParseCIDR(entry.Prefix)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse prefix %s: %v", entry.Prefix, err)
		}
		prefixes = append(prefixes, network)
	}
	return &FlapPrefixes{Prefixes: prefixes}, nil
}

func main() {
	flag.Parse()
	feedSource, err := NewKioubitsFeedSource(*feedSourceURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create Kioubits feed source: %v", err)
		os.Exit(1)
	}

	listener, err := net.Listen("unix", *bindUnixSocket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on %s: %v", *bindUnixSocket, err)
		os.Exit(1)
	}
	defer listener.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		muxer := http.NewServeMux()
		muxer.HandleFunc("/birdflapprefixtesterconf", func(w http.ResponseWriter, r *http.Request) {
			prefixes, err := feedSource.GetPrefixes()
			if err != nil {
				log.Printf("failed to get prefixes: %v", err)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "max-age=604800, public, stale-while-revalidate")
			fmt.Fprintln(w, prefixes.ToBirdTesterFunction())
		})

		server := &http.Server{
			Handler: muxer,
		}
		log.Printf("server started on %s", listener.Addr())
		err := server.Serve(listener)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				fmt.Fprintf(os.Stderr, "failed to serve: %v", err)
				os.Exit(1)
			}
		}
		log.Printf("server stopped: %v", err)
	}()

	<-sigChan
}
