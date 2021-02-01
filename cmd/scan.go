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
  "strconv"
  "regexp"
  "sort"

  "github.com/ryandamour/ssrfuzz/pkg"
  "github.com/spf13/cobra"
)

var domains string
var output string
var userAgent string
var timeout int
var threads int
var delay int
var verbose bool
var slackHook string
var httpMethod string
var cookie string
var skipCRLF bool
var CRLFPath bool
var skipNetwork bool
var skipScheme bool
var version = "v1.0"

type SlackRequestBody struct {
  Text string `json:"text"`
}

type NetworkResults struct {
  StatusCode int `json:"statusCode"`
  Port int `json:"port"`
  URL string `json:"url"`
  connectionTime float64 `json:"connectionTime"`
}

// struct for finding anomalies
type NetworkPrunedResults struct {
  Payload    string
  BaseURL    string
  Port	     string
  StatusCode int
}

type SchemeResults struct {
  URL string `json:"url"`
}

// Save results for displaying and processing
var schemeResults []SchemeResults
var networkResults []NetworkResults
var networkAnomalies []NetworkPrunedResults

func ssrfuzzCmd() *cobra.Command {
  ssrfuzzCmd := &cobra.Command {
    Use:   "scan",
    Short: "A scanner for all your SSRF Fuzzing needs",
    Run: ssrfuzzFunc,
  }

  ssrfuzzCmd.Flags().StringVarP(&domains, "domains", "d", "", "Location of domains with parameters to scan")
  ssrfuzzCmd.Flags().StringVarP(&output, "output", "o", "", "Location to save results")
  ssrfuzzCmd.Flags().StringVarP(&userAgent, "user-agent", "u", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36", "User agent for requests")
  ssrfuzzCmd.Flags().StringVarP(&cookie, "cookie", "c", "", "Cookie to use for requests")
  ssrfuzzCmd.Flags().IntVarP(&timeout, "timeout", "", 10, "The amount of time needed to close a connection that could be hung")
  ssrfuzzCmd.Flags().IntVarP(&delay, "delay", "", 100, "The time each threads waits between requests in milliseconds")
  ssrfuzzCmd.Flags().IntVarP(&threads, "threads", "t", 50, "Number of threads to run ssrfuzz on")
  ssrfuzzCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
  ssrfuzzCmd.Flags().StringVarP(&slackHook, "slack-webhook", "s", "",  "Slack webhook to send findings to a channel")
  ssrfuzzCmd.Flags().StringVarP(&httpMethod, "http-method", "x", "GET",  "HTTP Method - GET or POST")
  ssrfuzzCmd.Flags().BoolVarP(&skipCRLF, "skip-crlf", "", false,  "Skip CRLF fuzzing")
  ssrfuzzCmd.Flags().BoolVarP(&CRLFPath, "crlf-path", "", false,  "Add CRLF payloads to all available paths (ie: site.com/%0Atest.php)")
  ssrfuzzCmd.Flags().BoolVarP(&skipNetwork, "skip-network", "", false,  "Skip network fuzzing")
  ssrfuzzCmd.Flags().BoolVarP(&skipScheme, "skip-scheme", "", false,  "Skip scheme fuzzing")

  return ssrfuzzCmd
}

func ssrfuzzFunc(cmd *cobra.Command, args []string) {
  var stdinResults []string

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
:: Threads        : %d
:: Output         : %s
:: User Agent     : %s
:: Cookie         : %s
:: Timeout        : %d
:: Delay          : %d
:: Slack Hook     : %s
:: HTTP Method    : %s
:: Skip CRLF      : %v
:: Skip Network   : %v
:: Skip Scheme    : %v
-----------------------
`, version, domains, threads, output, userAgent, cookie, timeout, delay, slackHook, httpMethod, skipCRLF, skipNetwork, skipScheme)

    fmt.Println("[+] Starting SSRF Fuzzing\n")

    if threads <= 0 {
      fmt.Println("Threads must be larger than 0")
      os.Exit(1)
    }

    crlfPayloadsSlice := []string{}
    schemePayloadsSlice := []string{}
    networkPayloadsSlice := []string{}

    if skipScheme != true {
      schemePayloadsSlice = pkg.GetSchemePayloads()
    }

    if skipNetwork != true {
      networkPayloadsSlice = pkg.GetNetworkPayloads()
    }

    if skipCRLF != true {
      crlfPayloadsSlice = pkg.GetCRLFPayloads()
    }

    threadsChannel := make(chan struct{}, threads)

    // Create array if using stdin
    if domains == "" {
      stdinScanner := bufio.NewScanner(os.Stdin)
      for stdinScanner.Scan() {
        stdinResults = append(stdinResults, stdinScanner.Text())
      }
    }


    // CRLF Fuzzing 

    if skipCRLF == false {
    // If domains flag is present
      if domains != "" {
        domainsFile := fileReader(domains)
        for _, domain := range domainsFile {
          for _, schemePayload := range schemePayloadsSlice {
	    for _, crlfPayload := range crlfPayloadsSlice {

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
	  for _, url := range stdinResults  {
            for _, schemePayload := range schemePayloadsSlice {
              for _, crlfPayload := range crlfPayloadsSlice {

                fuzzedURL := fuzzURL(url, crlfPayload, schemePayload)

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
    } else if skipCRLF == true {
    // Normal Fuzzing
    // If domains flag is present
      if domains != "" {
        domainsFile := fileReader(domains)
        for _, domain := range domainsFile {
          for _, schemePayload := range schemePayloadsSlice {

            fuzzedURL := fuzzURL(domain, "", schemePayload)

            for _, requestURI := range *fuzzedURL {
              threadsChannel <- struct{}{}
              go makeRequest(requestURI, timeout, threadsChannel, false, true)
              if delay > 0 {
                time.Sleep(time.Duration(delay) * time.Millisecond)
              }
            }
          }
        }
      } else if domains == "" { // Read from stdin
          for _, url := range stdinResults  {
            for _, schemePayload := range schemePayloadsSlice {

              fuzzedURL := fuzzURL(url, "", schemePayload)

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

    // Normal Fuzzing

    // TODO Add logic for network payloads 
    // Fuzz Internal Connections
    if skipCRLF == false {
      if domains != "" {
        domainsFile := fileReader(domains)
        for _, domain := range domainsFile {
          for _, networkPayload := range networkPayloadsSlice {
            for _, crlfPayload := range crlfPayloadsSlice {

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
	  for _,url := range(stdinResults) {
            for _, networkPayload := range networkPayloadsSlice {
              for _, crlfPayload := range crlfPayloadsSlice {

                fuzzedURL := fuzzURL(url, crlfPayload, networkPayload)

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
    } else if skipCRLF == true {
    // If domains flag is present
      if domains != "" {
        domainsFile := fileReader(domains)
        for _, domain := range domainsFile {
          for _, networkPayload := range networkPayloadsSlice {

            fuzzedURL := fuzzURL(domain, "", networkPayload)

            for _, requestURI := range *fuzzedURL {
              threadsChannel <- struct{}{}
              go makeRequest(requestURI, timeout, threadsChannel, true, false)
              if delay > 0 {
                time.Sleep(time.Duration(delay) * time.Millisecond)
              }
            }
          }
        }
      } else if domains == "" { // Read from stdin
          for _, url := range stdinResults  {
            for _, networkPayload := range networkPayloadsSlice {

              fuzzedURL := fuzzURL(url, "", networkPayload)

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

    findAnomalies(networkResults, schemeResults)
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
      fuzzedParams = append(fuzzedParams,param)

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
      if skipCRLF == false {
	// We take the recompliled parameter string, split it by the special character, and then keep the first element after the split.
	// This is so we can fuzz other parts of the string at a later point in time if we want.
	// ie: param=123 gets split so we can parse and append to "param" with our payloads.
	// However, we may want to add things such as crlf payloads in a different order, such as param%0A=123
        if finalFuzzedParams[paramPayloadCount] != "&" {
          finalFuzzedParams[paramPayloadCount] = strings.Split(fuzzedParams[paramPayloadCount], "=")[0] + "=" + schemePayload + payload
        }
      } else if skipCRLF == true {
	  if finalFuzzedParams[paramPayloadCount] != "&" {
            finalFuzzedParams[paramPayloadCount] = strings.Split(fuzzedParams[paramPayloadCount], "=")[0] + "=" + schemePayload
          }
      }

      // Keeping this logic abstracted for reasonings mentioned above.  I may want to fuzz "&" specifically for crlf injections through this process.
      if finalFuzzedParams[paramPayloadCount] != "&" {
        flattenedURL := URL+strings.Join(finalFuzzedParams[:], "")
        fuzzedURL = append(fuzzedURL,flattenedURL)
      }
    }
  }

  //Fuzz endpoints.  Keeping this seperated from parameters.
  u, err := url.Parse(domain)
  if err != nil {
    panic(err)
  }

  scheme := u.Scheme
  host := u.Host
  endpoint := u.Path
  query := u.RawQuery

  if skipCRLF == false && CRLFPath == true {
    for endpointPayloadCount := 0; endpointPayloadCount < strings.Count(endpoint, "/"); endpointPayloadCount++ {
      finalEndpoint := replaceNth(endpoint, "/", "/"+payload, endpointPayloadCount+1)
      finalEndpointUrl := []string{scheme,"://", host,finalEndpoint+"?"+query}
      flattenedURL := strings.Join(finalEndpointUrl, "")
      fuzzedURL = append(fuzzedURL,flattenedURL)
    }
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
  ssrfMatchFile := pkg.GetSSRFMatch()
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
      ResponseHeaderTimeout: time.Duration(timeoutFlag)*time.Second,
      MaxIdleConns: 1000,
      MaxIdleConnsPerHost: 1000,
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

  if cookie != "" {
    req.Header.Add("Cookie", cookie)
  }

  var start, connect time.Time
  var connectStart, connectDone, ttfb time.Duration
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
    fmt.Printf("%s (Status : %d, %f, %f, %f)\n", URL, resp.StatusCode, float64(connectStart), float64(ttfb / time.Millisecond), float64(connectDone / time.Millisecond))
  }


  // Save results for network payloads.  We don't care much about response code of 200 as much as the response time.
  if networkPayload {
    portString := strings.TrimLeft(strings.TrimRight(URL,"/"),":")
    port,_ := strconv.Atoi(portString)
    networkResults = append(networkResults, NetworkResults{Port: port, URL: URL, StatusCode: resp.StatusCode, connectionTime: float64(connectDone / time.Millisecond)})
  }

  defer resp.Body.Close()

  if resp.StatusCode == 200 {
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
      fmt.Println(err)
    }
    // Save results for scheme payloads
    if schemePayload {
      if checkResponse(string(body)) {
	schemeResults = append(schemeResults, SchemeResults{URL: URL})
	if verbose {
	  fmt.Println("[!] Scheme payload match: "+URL+"\n")
          fmt.Println(string(body))
        }
      }
    }
  }
  <-threadsChannel
}

func findAnomalies(networkResults []NetworkResults, schemeResults []SchemeResults) {


  //Network Anomalies
  for _, network := range networkResults {
    re := regexp.MustCompile(":([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])")
    // Find last occurence of port regex, since this should happen at the end w/ params
    ports := re.FindAllStringSubmatch(network.URL, -1)
    port := ports[len(ports)-1][0]
    prunedURL := strings.Replace(network.URL, port, "", -1)

    networkAnomalies = append(networkAnomalies, NetworkPrunedResults{BaseURL: prunedURL, Payload: network.URL, Port: port, StatusCode: network.StatusCode})
  }

  //Order struct alphabetically
  sort.SliceStable(networkAnomalies, func(i, j int) bool {
    return networkAnomalies[i].BaseURL < networkAnomalies[j].BaseURL
  })

  //Create output file if it doesn't exist

  var statusCodePlaceHolder []int
  var baseURLPlaceHolder = ""
  for _, result := range networkAnomalies {
    if baseURLPlaceHolder != result.BaseURL {
      statusCodeResults := findUniqueValue(statusCodePlaceHolder)
      if len(statusCodeResults) > 1 {
        //Write to output file
        if output != "" {
          f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
          if err != nil {
            if verbose == true {
              fmt.Println(err)
            }
          }
          f.WriteString("[!] Interesting payloads found"+"\n")
          for _, finalResult := range networkAnomalies {
            if finalResult.BaseURL == baseURLPlaceHolder {
              f.WriteString("* "+string(finalResult.Payload)+" "+strconv.Itoa(finalResult.StatusCode)+"\n")
            }
          }
        defer f.Close()
        }

        fmt.Println("[!] Interesting payloads found")
        if slackHook != "" {
          SendSlackNotification(slackHook, "[!] Interesting payloads found")
        }

	for _, finalResult := range networkAnomalies {
          if finalResult.BaseURL == baseURLPlaceHolder {
            fmt.Println("*",finalResult.Payload,finalResult.StatusCode)
              if slackHook != "" {
                SendSlackNotification(slackHook, "*"+finalResult.Payload+strconv.Itoa(finalResult.StatusCode))
              }
	  }
	}
      }
      statusCodePlaceHolder = nil
      baseURLPlaceHolder = result.BaseURL
    }

    statusCodePlaceHolder = append(statusCodePlaceHolder, result.StatusCode)
  }

  //Scheme Anomalies

  //Write to output file
  if output != "" {
    f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
      if verbose == true {
        fmt.Println(err)
      }
    }
    for _, scheme := range schemeResults {
      f.WriteString("[!] Scheme payload match: "+scheme.URL+"\n")
    }
  defer f.Close()
  }

  for _, scheme := range schemeResults {
    fmt.Println("[!] Scheme payload match: "+scheme.URL+"\n")
    if slackHook != "" {
      SendSlackNotification(slackHook, "[!] Scheme payload match: "+scheme.URL)
    }
  }

}

func findUniqueValue(arr []int) []int {
    keys := make(map[int]bool)
    list := []int{}

    // If the key(values of the slice) is not equal 
    // to the already present value in new slice (list) 
    // then we append it. else we jump on another element. 
    for _, entry := range arr {
        if _, value := keys[entry]; !value {
            keys[entry] = true
            list = append(list, entry)
        }
    }
    return list
}

func init() {
  rootCmd.AddCommand(ssrfuzzCmd())
}
