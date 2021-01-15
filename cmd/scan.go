package cmd

import (
  "bufio"
  "fmt"
  "log"
  "net/http"
  "net/http/httptrace"
  "os"
  "net/url"
  "strings"
  "time"
  "errors"
  "bytes"
  "encoding/json"
  "crypto/tls"
  "io/ioutil"

  "github.com/spf13/cobra"
)

var domains string
var crlfPayloads string
var schemePayloads string
var networkPayloads string
var output string
var userAgent string
var timeout int
var threads int
var delay int
var verbose bool
var slackHook string
var httpMethod string
var version = "v0.0.1"

type SlackRequestBody struct {
  Text string `json:"text"`
}

type NetworkResults struct {
  URL string `json:"url"`
  connectionTime float64 `json:"connectionTime"`
}

type SchemeResults struct {
  URL string `json:"url"`
}

// Save results for displaying and processing
var schemeResults []SchemeResults
var networkResults []NetworkResults

func ssrfuzzCmd() *cobra.Command {
  ssrfuzzCmd := &cobra.Command {
    Use:   "scan",
    Short: "A scanner for all your SSRF Fuzzing needs",
    Run: ssrfuzzFunc,
  }

  ssrfuzzCmd.Flags().StringVarP(&domains, "domains", "d", "", "Location of domains with parameters to scan")
  ssrfuzzCmd.Flags().StringVarP(&crlfPayloads, "crlfPayloads", "c", "crlfpayloads.txt", "Location of crlfPayloads to generate on requests")
  ssrfuzzCmd.Flags().StringVarP(&schemePayloads, "schemePayloads", "p", "schemepayloads.txt", "Location of schemePayloads to generate on requests")
  ssrfuzzCmd.Flags().StringVarP(&networkPayloads, "networkPayloads", "n", "networkpayloads.txt", "Location of networkPayloads to generate on requests")
  ssrfuzzCmd.Flags().StringVarP(&output, "output", "o", "", "Location to save results")
  ssrfuzzCmd.Flags().StringVarP(&userAgent, "user-agent", "u", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36", "User agent for requests")
  ssrfuzzCmd.Flags().IntVarP(&timeout, "timeout", "", 10, "The amount of time needed to close a connection that could be hung")
  ssrfuzzCmd.Flags().IntVarP(&delay, "delay", "", 100, "The time each threads waits between requests in milliseconds")
  ssrfuzzCmd.Flags().IntVarP(&threads, "threads", "t", 50, "Number of threads to run crlfmap on")
  ssrfuzzCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
  ssrfuzzCmd.Flags().StringVarP(&slackHook, "slack-webhook", "s", "",  "Slack webhook to send findings to a channel")
  ssrfuzzCmd.Flags().StringVarP(&httpMethod, "http-method", "x", "GET",  "HTTP Method - GET or POST.")

  return ssrfuzzCmd
}

func ssrfuzzFunc(cmd *cobra.Command, args []string) {

    fmt.Printf(`

  ██████   ██████  ██▀███    █████▒█    ██ ▒███████▒▒███████▒
▒██    ▒ ▒██    ▒ ▓██ ▒ ██▒▓██   ▒ ██  ▓██▒▒ ▒ ▒ ▄▀░▒ ▒ ▒ ▄▀░
░ ▓██▄   ░ ▓██▄   ▓██ ░▄█ ▒▒████ ░▓██  ▒██░░ ▒ ▄▀▒░ ░ ▒ ▄▀▒░ 
  ▒   ██▒  ▒   ██▒▒██▀▀█▄  ░▓█▒  ░▓▓█  ░██░  ▄▀▒   ░  ▄▀▒   ░
▒██████▒▒▒██████▒▒░██▓ ▒██▒░▒█░   ▒▒█████▓ ▒███████▒▒███████▒
▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░ ▒▓ ░▒▓░ ▒ ░   ░▒▓▒ ▒ ▒ ░▒▒ ▓░▒░▒░▒▒ ▓░▒░▒
░ ░▒  ░ ░░ ░▒  ░ ░  ░▒ ░ ▒░ ░     ░░▒░ ░ ░ ░░▒ ▒ ░ ▒░░▒ ▒ ░ ▒
░  ░  ░  ░  ░  ░    ░░   ░  ░ ░    ░░░ ░ ░ ░ ░ ░ ░ ░░ ░ ░ ░ ░
      ░        ░     ░               ░       ░ ░      ░ ░    
                                           ░        ░        

    %s                                
-----------------------
:: Domains        : %s
:: CRLFPayloads   : %s
:: SchemePayloads : %s
:: Threads        : %d
:: Output         : %s
:: User Agent     : %s
:: Timeout        : %d
:: Delay          : %d
:: Slack Hook     : %s
:: HTTP Method    : %s
-----------------------
`, version, domains, crlfPayloads, schemePayloads, threads, output, userAgent, timeout, delay, slackHook, httpMethod)

    fmt.Println("[+] Fuzzing SSRF Scheme Payloads\n")

    if threads <= 0 {
      fmt.Println("Threads must be larger than 0")
      os.Exit(1)
    }

    crlfPayloadsFile := fileReader(crlfPayloads)
    schemePayloadsFile := fileReader(schemePayloads)
    networkPayloadsFile := fileReader(networkPayloads)

    threadsChannel := make(chan struct{}, threads)
    // If domains flag is present
    if domains != "" {
      domainsFile := fileReader(domains)
      for _, domain := range domainsFile {
        for _, schemePayload := range schemePayloadsFile {
	  for _, crlfPayload := range crlfPayloadsFile {

            fuzzedURL := fuzzURL(domain, crlfPayload, schemePayload)

            for _, requestURI := range *fuzzedURL {
	      threadsChannel <- struct{}{}
              go makeRequest(requestURI, timeout, threadsChannel, false, true)
              if delay > 0 {
                time.Sleep(time.Duration(delay) * time.Millisecond)
              }
            }
          }
        }
      }
    } else if domains == "" { // Read from stdin
        stdinScanner := bufio.NewScanner(os.Stdin)
        for stdinScanner.Scan() {
          for _, schemePayload := range schemePayloadsFile {
            for _, crlfPayload := range crlfPayloadsFile {

              fuzzedURL := fuzzURL(stdinScanner.Text(), crlfPayload, schemePayload)

              for _, requestURI := range *fuzzedURL {
		threadsChannel <- struct{}{}
                go makeRequest(requestURI, timeout, threadsChannel, false, true)
                if delay > 0 {
                  time.Sleep(time.Duration(delay) * time.Millisecond)
                }
              }
            }
          }
        }
      }

    // TODO Add logic for network payloads 
    // Fuzz Internal Connections
    if domains != "" {
      domainsFile := fileReader(domains)
      for _, domain := range domainsFile {
        for _, networkPayload := range networkPayloadsFile {
          for _, crlfPayload := range crlfPayloadsFile {

            fuzzedURL := fuzzURL(domain, crlfPayload, networkPayload)

            for _, requestURI := range *fuzzedURL {
              threadsChannel <- struct{}{}
              go makeRequest(requestURI, timeout, threadsChannel, true, false)
              if delay > 0 {
                time.Sleep(time.Duration(delay) * time.Millisecond)
              }
            }
          }
        }
      }
    } else if domains == "" { // Read from stdin
        stdinScanner := bufio.NewScanner(os.Stdin)
        for stdinScanner.Scan() {
          for _, networkPayload := range networkPayloadsFile {
            for _, crlfPayload := range crlfPayloadsFile {

              fuzzedURL := fuzzURL(stdinScanner.Text(), crlfPayload, networkPayload)

              for _, requestURI := range *fuzzedURL {
		threadsChannel <- struct{}{}
                go makeRequest(requestURI, timeout, threadsChannel, true, false)
                if delay > 0 {
                  time.Sleep(time.Duration(delay) * time.Millisecond)
                }
              }
            }
          }
        }
      }

    close(threadsChannel)
    fmt.Println("Network results", networkResults)
    fmt.Println("Scheme results", schemeResults)
    }

func fuzzURL(domain string, payload string, schemePayload string) *[]string {
  var fuzzedURL []string
  var fuzzedParams []string

  // Make sure parameter are present
  if strings.Contains(domain, "?") {
    paramStr := strings.Split(domain, "?")[1]
    params := strings.Split(paramStr, "&")
    domainPrefix := strings.Split(domain, "?")[0]
    URL := domainPrefix+"?"

    paramFuzzCount := 0
    // Rebuild parameters so we can work with each parameter individually (I may be doing this wrong)
    // Clear list before concatentation again
    fuzzedParams = nil
    for _, param := range params {
      baseParam := strings.Split(param,"=")[0] // Remove everything after '=' so we can replace with our SSRF payloads 
      fuzzedParams = append(fuzzedParams,baseParam+"="+schemePayload)

      if paramFuzzCount != (len(params) - 1) {
        fuzzedParams = append(fuzzedParams,"&")
      }
      paramFuzzCount += 1
    }

    // Inject payload into each parameter consecutively.  We don't want to 
    // have server errors for actions that could require specific strings
    for paramPayloadCount := 0; paramPayloadCount < len(fuzzedParams); paramPayloadCount++ {
      finalFuzzedParams := make([]string, len(fuzzedParams))
      copy(finalFuzzedParams, fuzzedParams)
      finalFuzzedParams[paramPayloadCount] = fuzzedParams[paramPayloadCount] + payload

      flattenedURL := URL+strings.Join(finalFuzzedParams[:], "")
      fuzzedURL = append(fuzzedURL,flattenedURL)
    }
  }

  //Fuzz endpoints.  Keeping this seperated from parameters.  Maybe add flags for types of fuzzing later?
  u, err := url.Parse(domain)
  if err != nil {
    panic(err)
  }

  endpoint := u.Path
  scheme := u.Scheme
  host := u.Host

  for endpointPayloadCount := 0; endpointPayloadCount < strings.Count(endpoint, "/"); endpointPayloadCount++ {
    finalEndpoint := replaceNth(endpoint, "/", "/"+schemePayload+payload, endpointPayloadCount+1)
    finalEndpointUrl := []string{scheme,"://", host, finalEndpoint}
    flattenedURL := strings.Join(finalEndpointUrl, "")
    fuzzedURL = append(fuzzedURL,flattenedURL)
  }

  return &fuzzedURL
}


// Thanks stackoverflow
func replaceNth(s, old, new string, n int) string {
    i := 0
    for m := 1; m <= n; m++ {
        x := strings.Index(s[i:], old)
        if x < 0 {
            break
        }
        i += x
        if m == n {
            return s[:i] + new + s[i+len(old):]
        }
        i += len(old)
    }
    return s
}

// Thanks golangcode.com
func SendSlackNotification(slackHook string, msg string) error {

    slackBody, _ := json.Marshal(SlackRequestBody{Text: msg})
    req, err := http.NewRequest(http.MethodPost, slackHook, bytes.NewBuffer(slackBody))
    if err != nil {
        return err
    }

    req.Header.Add("Content-Type", "application/json")

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return err
    }

    buf := new(bytes.Buffer)
    buf.ReadFrom(resp.Body)
    if buf.String() != "ok" {
        return errors.New("Non-ok response returned from Slack")
    }
    return nil
}

func fileReader(ulist string) []string {
	var buffer []string
	file, err := os.Open(ulist)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		list := scanner.Text()
		buffer = append(buffer, list)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return buffer

}

func checkResponse(content string) bool {
  ssrfMatchFile := fileReader("ssrfmatch.txt")
    for _, ssrfMatch := range ssrfMatchFile {
      if strings.Contains(content, ssrfMatch) {
        return true
      } else {
        return false
    }
  }
  return false
}

func makeRequest(uri string, timeoutFlag int, threadsChannel chan struct{}, networkPayload bool, schemePayload bool) {
  URL := uri
  client := &http.Client{
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
      return http.ErrUseLastResponse
    },
    Timeout: time.Duration(timeoutFlag)*time.Second,
    Transport: &http.Transport{
      MaxIdleConns: 100,
      MaxIdleConnsPerHost: 100,
      TLSClientConfig: &tls.Config{
        InsecureSkipVerify: true,
      },
    }}

  req, err := http.NewRequest(httpMethod, URL, nil)

  if err != nil {
    if verbose == true {
      fmt.Println(err)
    }
    <-threadsChannel
    return
  }


  req.Header.Set("User-Agent",userAgent)

  var start, connect time.Time
  var connectDone, ttfb time.Duration
  trace := &httptrace.ClientTrace{
    ConnectStart: func(network, addr string) { connect = time.Now() },
    ConnectDone: func(network, addr string, err error) { connectDone = time.Since(connect) },
    GotFirstResponseByte: func() { ttfb = time.Since(start) },
  }

  req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

  if err != nil {
    if verbose == true {
      fmt.Println(err)
    }
    <-threadsChannel
    return
  }

  resp, err := client.Do(req)
  if err != nil {
    fmt.Println(err)
  }


  if err != nil {
    if verbose == true {
      fmt.Println(err)
    }
    <-threadsChannel
    return
  }


  if verbose == true {
    fmt.Printf("%s (Status : %d, %f)\n", URL, resp.StatusCode, float64(connectDone))
  }

  if resp.StatusCode == 200 {
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
      fmt.Println(err)
    }
    // Save results for network payloads
    if networkPayload {
      networkResults = append(networkResults, NetworkResults{URL: URL, connectionTime: float64(connectDone)})
    }
    // Save results for scheme payloads
    if schemePayload {
      if checkResponse(string(body)) {
	schemeResults = append(schemeResults, SchemeResults{URL: URL})
	if verbose {
          fmt.Println("[*]Found "+URL+"\n")
          fmt.Println(string(body))
        }
      }
    }
  }
  <-threadsChannel
}

func init() {
  rootCmd.AddCommand(ssrfuzzCmd())
}
