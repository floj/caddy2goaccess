package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"os"
	"strconv"
	"strings"
)

type CaddyLog struct {
	Ts      float64 `json:"ts"`
	Logger  string  `json:"logger"`
	Msg     string  `json:"msg"`
	Request struct {
		RemoteAddr        string              `json:"remote_addr"`
		Proto             string              `json:"proto"`
		Method            string              `json:"method"`
		Host              string              `json:"host"`
		URI               string              `json:"uri"`
		Headers           map[string][]string `json:"headers"`
		normalizedHeaders map[string]string
		TLS               struct {
			Resumed     bool   `json:"resumed"`
			Version     int    `json:"version"`
			CipherSuite int    `json:"cipher_suite"`
			Proto       string `json:"proto"`
			ProtoMutual bool   `json:"proto_mutual"`
			ServerName  string `json:"server_name"`
		} `json:"tls"`
	} `json:"request"`
	Duration              float64             `json:"duration"`
	Size                  int                 `json:"size"`
	Status                int                 `json:"status"`
	RespHeaders           map[string][]string `json:"resp_headers"`
	normalizedRespHeaders map[string]string
}

func (l *CaddyLog) Format(conf Config) (string, bool) {
	// %x  A date and time field matching the time-format and date-format variables. This is used when a timestamp is given instead of the date and time being in two separate variables.
	// %t  time field matching the time-format variable.
	// %d  date field matching the date-format variable.
	// %v  The server name according to the canonical name setting (Server Blocks or Virtual Host).
	// %e  This is the userid of the person requesting the document as determined by HTTP authentication.
	// %C  The cache status of the object the server served.
	// %h  host (the client IP address, either IPv4 or IPv6)
	// %r  The request line from the client. This requires specific delimiters around the request (single quotes, double quotes, etc) to be parsable. Otherwise, use a combination of special format specifiers such as %m, %U, %q and %H to parse individual fields. Note: Use either %r to get the full request OR %m, %U, %q and %H to form your request, do not use both.
	// %m  The request method.
	// %U  The URL path requested. Note: If the query string is in %U, there is no need to use %q. However, if the URL path, does not include any query string, you may use %q and the query string will be appended to the request.
	// %q The query string.
	// %H The request protocol.
	// %s The status code that the server sends back to the client.
	// %b The size of the object returned to the client.
	// %R The "Referer" HTTP request header.
	// %u The user-agent HTTP request header.
	// %K The TLS encryption settings chosen for the connection. (In Apache LogFormat: %{SSL_PROTOCOL}x).
	// %k The TLS encryption settings chosen for the connection. (In Apache LogFormat: %{SSL_CIPHER}x).
	// %M The MIME-type of the requested resource. (In Apache LogFormat: %{Content-Type}o)
	// %D The time taken to serve the request, in microseconds.
	// %T The time taken to serve the request, in seconds with milliseconds resolution.
	// %L The time taken to serve the request, in milliseconds as a decimal number.
	// %^Ignore this field.
	// %~ Move forward through the log string until a non-space (!isspace) char is found.
	// ~h The host (the client IP address, either IPv4 or IPv6) in a X-Forwarded-For (XFF) field.

	//%v:%^ %h %^[%d:%t %^] "%r" %s %b "%R" "%u"

	if conf.IncludeHosts != "" && !strings.HasPrefix(l.Request.Host, conf.IncludeHosts) {
		return "", false
	}

	if conf.ExcludeURLs != "" && strings.HasPrefix(l.Request.URI, conf.ExcludeURLs) {
		return "", false
	}

	l.Request.normalizedHeaders = normalizeHeaders(l.Request.Headers)
	l.normalizedRespHeaders = normalizeHeaders(l.RespHeaders)
	remote_host, _, _ := net.SplitHostPort(l.Request.RemoteAddr)
	if xff := l.Request.normalizedHeaders["x-forwarded-for"]; xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		remote_host = strings.TrimSpace(parts[0])
	}
	if conf.ExcludeClients != "" && strings.HasPrefix(remote_host, conf.ExcludeClients) {
		return "", false
	}

	contentType, _, _ := mime.ParseMediaType(l.normalizedRespHeaders["content-type"])

	// TS VHost ClientIP Method URI Status Size Referer UserAgent MimeType Duration
	// %x %v    %h       %m     %U  %s     %b   %R      %u        %M       %T
	// %x\t%v\t%h\t%m\t%U\t%s\t%b\t%R\t%u\t%M\t%T
	fields := []string{
		strconv.Itoa(int(l.Ts)),                      // %x
		l.Request.Host,                               // %v
		remote_host,                                  // %h
		l.Request.Method,                             // %m
		l.Request.URI,                                // %U
		strconv.Itoa(l.Status),                       // %s
		strconv.Itoa(l.Size),                         // %b
		l.Request.normalizedHeaders["referer"],       // %R
		l.Request.normalizedHeaders["user-agent"],    // %u
		contentType,                                  // %M
		strconv.FormatFloat(l.Duration, 'f', -1, 64), // %T
	}

	return strings.Join(fields, "\t"), true
}

func normalizeHeaders(h map[string][]string) map[string]string {
	m := map[string]string{}
	for k, v := range h {
		if len(v) == 0 {
			continue
		}
		m[strings.ToLower(k)] = v[0]
	}
	return m
}

type Config struct {
	IncludeHosts   string
	ExcludeClients string
	ExcludeURLs    string
}

const logFormat = `%x\t%v\t%h\t%m\t%U\t%s\t%b\t%R\t%u\t%M\t%T`

func main() {
	printLogFormat := flag.Bool("print-log-format", false, "Print the log-format to use in goaccess")
	includeHosts := flag.String("include-hosts", "", "Only include hosts having this prefix")
	excludeClients := flag.String("exclude-client", "", "Ignores clients having this prefix")
	excludeURLs := flag.String("exclude-urls", "", "Ignores URLs having this prefix")
	flag.Parse()

	if *printLogFormat {
		fmt.Println(logFormat)
		os.Exit(0)
	}

	conf := Config{
		IncludeHosts:   *includeHosts,
		ExcludeClients: *excludeClients,
		ExcludeURLs:    *excludeURLs,
	}

	for _, file := range flag.Args() {
		err := processFile(file, conf)
		if err != nil {
			fmt.Printf("Could not process %s: %v\n", file, err)
			os.Exit(1)
		}
	}
}

func processFile(file string, conf Config) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = bufio.NewReader(f)

	if strings.HasSuffix(file, ".gz") {
		r, err = gzip.NewReader(f)
		if err != nil {
			return err
		}
	}

	total, included, excluded := 0, 0, 0
	dec := json.NewDecoder(r)
	for dec.More() {
		l := CaddyLog{}
		err := dec.Decode(&l)
		if err != nil {
			return err
		}
		if line, ok := l.Format(conf); ok {
			fmt.Println(line)
			included++
		} else {
			excluded++
		}
		total++
		if total%1000 == 0 {
			fmt.Fprintf(os.Stderr, "processed %d (%d included, %d excluded)\n", total, included, excluded)
		}
	}
	return nil
}
