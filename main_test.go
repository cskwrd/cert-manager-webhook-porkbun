package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
	"github.com/cskwrd/cert-manager-webhook-porkbun/porkbun"
	"github.com/miekg/dns"
	porkbunapi "github.com/nrdcg/porkbun"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

// DNSRecord represents a DNS record in our mock DNS server
type DNSRecord struct {
	Name    string
	Type    uint16
	Content string
	TTL     uint32
}

// MockDNSServer is a mock DNS server implementation
type MockDNSServer struct {
	server   *dns.Server
	records  map[string][]DNSRecord
	recordMu sync.RWMutex
}

// NewMockDNSServer creates a new mock DNS server
func NewMockDNSServer(addr string) (*MockDNSServer, error) {
	mockServer := &MockDNSServer{
		records: make(map[string][]DNSRecord),
	}

	// Create DNS server
	server := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(mockServer.handleDNSRequest),
	}

	mockServer.server = server

	// Start the server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to start DNS server: %v\n", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return mockServer, nil
}

// Stop stops the mock DNS server
func (m *MockDNSServer) Stop() {
	if m.server != nil {
		m.server.Shutdown()
	}
}

// AddRecord adds a DNS record to the mock server
func (m *MockDNSServer) AddRecord(name, recordType, content string, ttl uint32) {
	m.recordMu.Lock()
	defer m.recordMu.Unlock()

	var recordTypeCode uint16
	switch recordType {
	case "A":
		recordTypeCode = dns.TypeA
	case "AAAA":
		recordTypeCode = dns.TypeAAAA
	case "TXT":
		recordTypeCode = dns.TypeTXT
	case "CNAME":
		recordTypeCode = dns.TypeCNAME
	case "MX":
		recordTypeCode = dns.TypeMX
	default:
		// Default to TXT if unknown
		recordTypeCode = dns.TypeTXT
	}

	// Ensure name ends with a dot
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}

	// Add record to map
	record := DNSRecord{
		Name:    strings.ToLower(name),
		Type:    recordTypeCode,
		Content: content,
		TTL:     ttl,
	}

	m.records[strings.ToLower(name)] = append(m.records[strings.ToLower(name)], record)
}

// RemoveRecord removes a DNS record from the mock server
func (m *MockDNSServer) RemoveRecord(name, content string) {
	m.recordMu.Lock()
	defer m.recordMu.Unlock()

	// Ensure name ends with a dot
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}

	name = strings.ToLower(name)
	records := m.records[name]
	var newRecords []DNSRecord

	for _, record := range records {
		if record.Content != content {
			newRecords = append(newRecords, record)
		}
	}

	if len(newRecords) == 0 {
		delete(m.records, name)
	} else {
		m.records[name] = newRecords
	}
}

// handleDNSRequest handles incoming DNS requests
func (m *MockDNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m.recordMu.RLock()
	defer m.recordMu.RUnlock()

	// Create response message
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	// Process each question
	for _, q := range r.Question {
		name := strings.ToLower(q.Name)

		// Check if we have records for this name
		if records, ok := m.records[name]; ok {
			for _, record := range records {
				if record.Type == q.Qtype || q.Qtype == dns.TypeANY {
					// Add matching record to response
					switch record.Type {
					case dns.TypeA:
						rr := &dns.A{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    record.TTL,
							},
							A: net.ParseIP(record.Content),
						}
						msg.Answer = append(msg.Answer, rr)
					case dns.TypeTXT:
						rr := &dns.TXT{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeTXT,
								Class:  dns.ClassINET,
								Ttl:    record.TTL,
							},
							Txt: []string{record.Content},
						}
						msg.Answer = append(msg.Answer, rr)
					}
				}
			}
		}
	}

	// Send response
	w.WriteMsg(msg)
}

// mockPorkbunHandler handles HTTP requests to mock the Porkbun API
type mockPorkbunHandler struct {
	// Track created records to allow for deletion
	records      map[string]map[string]porkbunapi.Record // domain -> recordID -> record
	mockDNS      *MockDNSServer                          // Reference to the mock DNS server
	nextRecordID int                                     // For generating unique record IDs
}

func newMockHandler(mockDNS *MockDNSServer) *mockPorkbunHandler {
	return &mockPorkbunHandler{
		records:      make(map[string]map[string]porkbunapi.Record),
		mockDNS:      mockDNS,
		nextRecordID: 100000,
	}
}

func (h *mockPorkbunHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check authentication for all requests
	if r.Method != http.MethodPost {
		http.Error(w, "invalid method: "+r.Method, http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Verify auth is present in all requests
	// if !strings.HasPrefix(string(body), `{"apikey":"key","secretapikey":"secret"`) {
	// 	w.Header().Set("Content-Type", "application/json")
	// 	w.Write([]byte(`{"status": "ERROR","message": "invalid auth"}`))
	// 	return
	// }
	if !strings.Contains(string(body), `"apikey":"key"`) || !strings.Contains(string(body), `"secretapikey":"secret"`) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ERROR","message": "invalid auth"}`))
		return
	}

	// Handle different API endpoints
	switch {
	case strings.Contains(r.URL.Path, "/dns/retrieve/"):
		h.handleRetrieveRecords(w, r, body)
	case strings.Contains(r.URL.Path, "/dns/create/"):
		h.handleCreateRecord(w, r, body)
	case strings.Contains(r.URL.Path, "/dns/delete/"):
		h.handleDeleteRecord(w, r, body)
	default:
		http.Error(w, "unsupported operation: "+r.URL.Path, http.StatusBadRequest)
	}
}

func (h *mockPorkbunHandler) handleRetrieveRecords(w http.ResponseWriter, r *http.Request, body []byte) {
	// Extract domain from path
	pathParts := strings.Split(r.URL.Path, "/")
	domain := pathParts[len(pathParts)-1]

	// Initialize domain map if not exists
	if _, ok := h.records[domain]; !ok {
		h.records[domain] = make(map[string]porkbunapi.Record)
	}

	// Build response with existing records
	var records []map[string]string
	for id, record := range h.records[domain] {
		records = append(records, map[string]string{
			"id":      id,
			"name":    record.Name,
			"type":    record.Type,
			"content": record.Content,
			"ttl":     record.TTL,
			"prio":    "0",
			"notes":   "",
		})
	}

	// If no records exist yet, return empty records array
	if records == nil {
		records = []map[string]string{}
	}

	response := map[string]interface{}{
		"status":  "SUCCESS",
		"records": records,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *mockPorkbunHandler) handleCreateRecord(w http.ResponseWriter, r *http.Request, body []byte) {
	// Extract domain from path
	pathParts := strings.Split(r.URL.Path, "/")
	domain := pathParts[len(pathParts)-1]

	// Parse request body to get record details
	var req struct {
		APIKey       string `json:"apikey"`
		SecretAPIKey string `json:"secretapikey"`
		Name         string `json:"name"`
		Type         string `json:"type"`
		Content      string `json:"content"`
		TTL          string `json:"ttl"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Initialize domain map if not exists
	if _, ok := h.records[domain]; !ok {
		h.records[domain] = make(map[string]porkbunapi.Record)
	}

	// Add record to mock DNS server for verification
	ttl, _ := time.ParseDuration(req.TTL + "s")
	recordName := req.Name
	if recordName == "" {
		recordName = domain
	} else {
		recordName = recordName + "." + domain
	}
	h.mockDNS.AddRecord(recordName, req.Type, req.Content, uint32(ttl.Seconds()))

	// Generate a unique record ID
	h.nextRecordID++
	recordID := h.nextRecordID

	// Store the record
	h.records[domain][fmt.Sprint(recordID)] = porkbunapi.Record{
		Name:    recordName,
		Type:    req.Type,
		Content: req.Content,
		TTL:     req.TTL,
	}

	// Return success response with record ID
	// response := map[string]interface{}{
	// 	"status": "SUCCESS",
	// 	"id":     recordID,
	// }
	response := struct {
		Status string `json:"status"`
		Id     int    `json:"id"`
	}{
		Status: "SUCCESS",
		Id:     recordID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *mockPorkbunHandler) handleDeleteRecord(w http.ResponseWriter, r *http.Request, body []byte) {
	// Extract domain and record ID from path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	domain := pathParts[len(pathParts)-2]
	recordID := pathParts[len(pathParts)-1]

	// Check if domain and record exist
	if _, ok := h.records[domain]; !ok {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}

	// Get the record before deleting it
	record, exists := h.records[domain][recordID]
	if !exists {
		http.Error(w, "record not found", http.StatusNotFound)
		return
	}

	// Delete the record
	delete(h.records[domain], recordID)

	// Remove from mock DNS server
	recordName := record.Name
	// I am not sure the following if is need or really correct.
	// it feels strange to build the record name like this when deleting
	// if recordName == "" {
	// 	recordName = domain
	// } else {
	// 	recordName = recordName + "." + domain
	// }
	h.mockDNS.RemoveRecord(recordName, record.Content)

	// Return success response
	response := map[string]string{
		"status": "SUCCESS",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func setupMockServices(t *testing.T) (*porkbunapi.Client, *testclient.Clientset, *MockDNSServer) {
	t.Helper()

	// Start mock DNS server
	mockDNS, err := NewMockDNSServer("127.0.0.1:59351") // Using the port from your test configuration
	require.NoError(t, err, "Failed to start mock DNS server")
	t.Cleanup(func() {
		mockDNS.Stop()
	})

	// Create the mock HTTP handler with reference to DNS server
	handler := newMockHandler(mockDNS)

	// Create test HTTP server
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	// Create Porkbun client that points to our test server
	client := porkbunapi.New("secret", "key")
	client.BaseURL, _ = url.Parse(server.URL)

	// Create fake k8s client with necessary secrets
	k8sClient := testclient.NewSimpleClientset(
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "porkbun-api-key",
				Namespace: "cert-manager",
			},
			Data: map[string][]byte{
				"api-key": []byte("key"),
			},
		},
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "porkbun-secret-key",
				Namespace: "cert-manager",
			},
			Data: map[string][]byte{
				"secret-key": []byte("secret"),
			},
		},
	)

	return client, k8sClient, mockDNS
}

func TestRunsSuite(t *testing.T) {

	// Setup mock services
	porkbunClient, k8sClient, mockDNS := setupMockServices(t)

	// Add initial zone records to DNS server for testing
	// zone must have a trailing "."
	mockDNS.AddRecord(zone, "A", "192.0.2.1", 3600)

	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	//

	solver := porkbun.NewFromFakeObjects(k8sClient, porkbunClient)
	// Uncomment the below fixture when implementing your custom DNS provider
	//fixture := acmetest.NewFixture(solver,
	//	acmetest.SetResolvedZone(zone),
	//	acmetest.SetAllowAmbientCredentials(false),
	//	acmetest.SetManifestPath("testdata/for-porkbun-solver"),
	//	acmetest.SetBinariesPath("_test/kubebuilder/bin"),
	//)
	fixture := acmetest.NewFixture(solver,
		// acmetest.SetResolvedZone("example.com."),
		acmetest.SetResolvedZone(zone),
		acmetest.SetManifestPath("testdata/for-porkbun-solver"),
		acmetest.SetDNSServer("127.0.0.1:59351"),
		acmetest.SetUseAuthoritative(false),
		acmetest.SetPollInterval(time.Second),
		acmetest.SetPropagationLimit(10*time.Second),
	)
	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)

}
