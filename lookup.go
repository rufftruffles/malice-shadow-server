package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/malice-plugins/pkgs/database"
	"github.com/malice-plugins/pkgs/database/elasticsearch"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "shadow-server"
	category = "intel"
	uagent   = "Mozilla/5.0 (Windows NT x.y; Win64; x64; rv:10.0) Gecko/20100101 Firefox/10.0"

	// binTestURL is the live, keyless ShadowServer "bin-test" whitelist
	// endpoint (verified live 2026-09-04). Query with ?md5=<hash> or
	// ?sha1=<hash>. A no-match returns "<hash>\n"; a match returns
	// "<hash> {json}\n".
	binTestURL = "http://bin-test.shadowserver.org/api"

	// sandboxURL is the legacy ShadowServer sandbox (AV results) endpoint.
	// As of 2026-09-04 it is NXDOMAIN (dead); the lookup is still attempted
	// and any failure is recorded gracefully in the result.
	sandboxURL = "http://innocuous.shadowserver.org/api/"

	// requestTimeout bounds each outbound HTTP lookup so a dead or
	// blackholed endpoint can never hang the scan past the malice timeout.
	requestTimeout = 15 * time.Second
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string

	// es is the elasticsearch database object
	es   elasticsearch.Database
	hash string
)

// ShadowServer json object
type ShadowServer struct {
	Results ResultsData `json:"shadow-server"`
}

// ResultsData json object
type ResultsData struct {
	Found     bool             `json:"found" structs:"found"`
	SandBox   SandBoxResults   `json:"sandbox" structs:"sandbox,omitempty"`
	WhiteList WhiteListResults `json:"whitelist" structs:"whitelist,omitempty"`
	Error     string           `json:"error" structs:"error,omitempty"`
	MarkDown  string           `json:"markdown,omitempty" structs:"markdown,omitempty"`
}

// SandBoxResults is a shadow-server SandboxApi results JSON object
type SandBoxResults struct {
	MetaData  map[string]string `json:"metadata,omitempty" structs:"metadata,omitempty"`
	Antivirus map[string]string `json:"antivirus,omitempty" structs:"antivirus,omitempty"`
	Error     string            `json:"error,omitempty" structs:"error,omitempty"`
}

// WhiteListResults is a shadow-server bin-test results JSON object
type WhiteListResults map[string]string

func assert(err error) {
	if err != nil {
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
			"hash":     hash,
		}).Fatal(err)
	}
}

// httpClient returns an http.Client bounded by requestTimeout.
func httpClient() *http.Client {
	return &http.Client{Timeout: requestTimeout}
}

// get performs a GET with the plugin user-agent and returns the body and
// status code.
func get(url string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", uagent)

	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// parseWhiteListOutput parses the bin-test response. A no-match is
// "<hash>\n" (or the legacy "<hash> \n"); a match is "<hash> {json}\n".
// It returns (nil, nil) on a no-match.
func parseWhiteListOutput(whitelistout string) (WhiteListResults, error) {
	line := strings.SplitN(whitelistout, "\n", 2)[0]
	fields := strings.SplitN(line, " ", 2)
	if len(fields) != 2 || strings.TrimSpace(fields[1]) == "" {
		return nil, nil
	}

	var whitelist WhiteListResults
	if err := json.Unmarshal([]byte(fields[1]), &whitelist); err != nil {
		return nil, err
	}
	return whitelist, nil
}

// whiteListHash tests the hash against the live bin-test whitelist endpoint.
func whiteListHash(hash string) (WhiteListResults, error) {
	hashTyp, err := utils.GetHashType(hash)
	if err != nil {
		return nil, err
	}

	body, status, err := get(fmt.Sprintf("%s?%s=%s", binTestURL, hashTyp, hash))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("bin-test returned status %d", status)
	}

	return parseWhiteListOutput(string(body))
}

// parseSandboxAPIOutput parses the legacy sandbox response. Kept for shape
// fidelity; the endpoint is currently dead so this rarely runs.
func parseSandboxAPIOutput(sandboxapiout string) SandBoxResults {
	var sandbox SandBoxResults

	lines := strings.Split(sandboxapiout, "\n")

	if len(lines) == 1 {
		if strings.Contains(lines[0], "! No match found") || strings.Contains(lines[0], "! Whitelisted:") {
			return sandbox
		}
	}

	if len(lines) == 2 {
		values := strings.Split(lines[0], ",")
		if len(values) == 6 {
			// "2009-07-24 02:09:53"
			const longForm = "2006-01-02 15:04:05"
			timeFirstSeen, _ := time.Parse(longForm, strings.Trim(values[2], "\""))
			timeLastSeen, _ := time.Parse(longForm, strings.Trim(values[3], "\""))
			meta := make(map[string]string)
			meta["md5"] = strings.Trim(values[0], "\"")
			meta["sha1"] = strings.Trim(values[1], "\"")
			meta["first_seen"] = printTableFormattedTime(timeFirstSeen.String())
			meta["last_seen"] = printTableFormattedTime(timeLastSeen.String())
			meta["type"] = strings.Trim(values[4], "\"")
			meta["ssdeep"] = strings.Trim(values[5], "\"")
			sandbox.MetaData = meta
		}
		if len(lines[1]) > 2 {
			if err := json.Unmarshal([]byte(lines[1]), &sandbox.Antivirus); err != nil {
				log.Println("parsing sandbox antivirus:", err)
			}
		}
	}

	return sandbox
}

// sandboxAPISearch searches the legacy sandbox endpoint for AV results.
func sandboxAPISearch(hash string) (SandBoxResults, error) {
	var sandbox SandBoxResults

	body, status, err := get(fmt.Sprintf("%s?query=%s", sandboxURL, hash))
	if err != nil {
		return sandbox, err
	}
	if status != http.StatusOK {
		return sandbox, fmt.Errorf("sandbox returned status %d", status)
	}

	return parseSandboxAPIOutput(string(body)), nil
}

// LookupHash retrieves the shadow-server file report for the given hash.
// It never returns an error: lookup failures (network, DNS, non-200) are
// recorded in the result so a valid document is always written to ES.
func LookupHash(hash string) ResultsData {
	lookup := ResultsData{}

	if whitelist, err := whiteListHash(hash); err != nil {
		lookup.Error = fmt.Sprintf("bin-test lookup failed: %v", err)
	} else if whitelist != nil {
		lookup.WhiteList = whitelist
	}

	if sandbox, err := sandboxAPISearch(hash); err != nil {
		lookup.SandBox.Error = fmt.Sprintf("sandbox endpoint unreachable: %v", err)
	} else {
		lookup.SandBox = sandbox
	}

	// `found` reflects an actual data match only — an endpoint error is not
	// a match.
	lookup.Found = lookup.WhiteList != nil ||
		lookup.SandBox.MetaData != nil ||
		lookup.SandBox.Antivirus != nil

	return lookup
}

func printTableFormattedTime(t string) string {
	timeInTableFormat, _ := time.Parse("2006-01-02 15:04:05 -0700 UTC", t)
	return timeInTableFormat.Format("1/02/2006 3:04PM")
}

func generateMarkDownTable(ss ShadowServer) string {
	var tplOut bytes.Buffer

	t := template.Must(template.New("").Parse(tpl))

	if err := t.Execute(&tplOut, ss.Results); err != nil {
		log.Println("executing template:", err)
	}

	return tplOut.String()
}

func main() {
	app := cli.NewApp()

	app.Name = "shadow-server"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Usage = "Malice ShadowServer Hash Lookup Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "lookup",
			Aliases:   []string{"l"},
			Usage:     "Query ShadowServer for hash",
			ArgsUsage: "MD5/SHA1 hash of file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "elasticsearch",
					Value:       "",
					Usage:       "elasticsearch url for Malice to store results",
					EnvVar:      "MALICE_ELASTICSEARCH_URL",
					Destination: &es.URL,
				},
				cli.IntFlag{
					Name:   "timeout",
					Value:  60,
					Usage:  "malice plugin timeout (in seconds)",
					EnvVar: "MALICE_TIMEOUT",
				},
				cli.BoolFlag{
					Name:  "table, t",
					Usage: "output as Markdown table",
				},
			},
			Action: func(c *cli.Context) error {
				if c.Bool("verbose") {
					log.SetLevel(log.DebugLevel)
				}

				if !c.Args().Present() {
					return errors.New("please supply a MD5/SHA1 hash to query")
				}

				hash = c.Args().First()

				// Validate the hash type up front; the core only invokes this
				// engine with md5/sha1, but be defensive.
				if _, err := utils.GetHashType(hash); err != nil {
					return errors.Wrapf(err, "unable to detect hash type: %s", hash)
				}

				ss := ShadowServer{Results: LookupHash(hash)}
				ss.Results.MarkDown = generateMarkDownTable(ss)

				// upsert into Database
				if len(c.String("elasticsearch")) > 0 {
					if err := es.Init(); err != nil {
						return errors.Wrap(err, "failed to initialize elasticsearch")
					}
					if err := es.StorePluginResults(database.PluginResults{
						ID:       utils.Getopt("MALICE_SCANID", hash),
						Name:     name,
						Category: category,
						Data:     structs.Map(ss.Results),
					}); err != nil {
						return errors.Wrapf(err, "failed to index malice/%s results", name)
					}
				}

				if c.Bool("table") {
					fmt.Println(ss.Results.MarkDown)
				} else {
					ss.Results.MarkDown = ""
					ssJSON, err := json.Marshal(ss)
					assert(err)
					fmt.Println(string(ssJSON))
				}
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	assert(err)
}
