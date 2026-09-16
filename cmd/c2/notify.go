package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

// Notifier pushes operator-facing alerts (new bot, command result) to a
// Telegram bot chat or a generic Discord-style webhook. Fire-and-forget:
// failures are logged, never retried in-band.
type Notifier struct {
	telegramToken string
	telegramChat  string
	webhookURL    string
	log           *log.Logger
	client        *http.Client
}

func NewNotifier(telegramToken, telegramChat, webhookURL string, logger *log.Logger) *Notifier {
	if telegramToken == "" && webhookURL == "" {
		return nil
	}
	return &Notifier{
		telegramToken: telegramToken,
		telegramChat:  telegramChat,
		webhookURL:    webhookURL,
		log:           logger,
		client:        &http.Client{Timeout: 10 * time.Second},
	}
}

// Send routes a message to whichever channel is configured.
func (n *Notifier) Send(text string) {
	if n == nil {
		return
	}
	if n.telegramToken != "" {
		n.sendTelegram(text)
	}
	if n.webhookURL != "" {
		n.sendWebhook(text)
	}
}

func (n *Notifier) sendTelegram(text string) {
	body, _ := json.Marshal(map[string]string{
		"chat_id": n.telegramChat,
		"text":    text,
	})
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.telegramToken)
	resp, err := n.client.Post(api, "application/json", bytes.NewReader(body))
	if err != nil {
		n.log.Printf("notify: telegram send failed: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		n.log.Printf("notify: telegram status %d", resp.StatusCode)
	}
}

func (n *Notifier) sendWebhook(text string) {
	body, _ := json.Marshal(map[string]string{"content": text})
	resp, err := n.client.Post(n.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		n.log.Printf("notify: webhook send failed: %v", err)
		return
	}
	resp.Body.Close()
}

// notifyURL validates a webhook URL when provided.
func notifyURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return raw
}
