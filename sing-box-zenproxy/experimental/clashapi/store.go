package clashapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/log"
)

type StoredProxy struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Type           string          `json:"type"`
	Server         string          `json:"server"`
	Port           uint16          `json:"port"`
	Outbound       json.RawMessage `json:"outbound"`
	Source         string          `json:"source"`
	SubscriptionID string          `json:"subscription_id,omitempty"`
	LocalPort      uint16          `json:"local_port,omitempty"`
	AddedAt        string          `json:"added_at"`
}

type StoredSubscription struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	URL        string `json:"url,omitempty"`
	ProxyCount int    `json:"proxy_count"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type StoreData struct {
	Proxies       []StoredProxy       `json:"proxies"`
	Subscriptions []StoredSubscription `json:"subscriptions"`
}

type ProxyStore struct {
	mu       sync.RWMutex
	data     StoreData
	filePath string
	logger   log.Logger
}

func NewProxyStore(dataDir string, logger log.Logger) *ProxyStore {
	ps := &ProxyStore{
		filePath: filepath.Join(dataDir, "store.json"),
		logger:   logger,
	}
	ps.load()
	return ps
}

func (ps *ProxyStore) load() {
	data, err := os.ReadFile(ps.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			ps.logger.Warn("failed to load store: ", err)
		}
		ps.data = StoreData{}
		return
	}
	if err := json.Unmarshal(data, &ps.data); err != nil {
		ps.logger.Warn("failed to parse store: ", err)
		ps.data = StoreData{}
	}
}

func (ps *ProxyStore) save() {
	go func() {
		ps.mu.RLock()
		data, err := json.MarshalIndent(ps.data, "", "  ")
		ps.mu.RUnlock()
		if err != nil {
			ps.logger.Warn("failed to marshal store: ", err)
			return
		}
		dir := filepath.Dir(ps.filePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			ps.logger.Warn("failed to create store dir: ", err)
			return
		}
		if err := os.WriteFile(ps.filePath, data, 0644); err != nil {
			ps.logger.Warn("failed to save store: ", err)
		}
	}()
}

func (ps *ProxyStore) AddProxy(proxy StoredProxy) StoredProxy {
	ps.mu.Lock()
	if proxy.ID == "" {
		proxy.ID = uuid.Must(uuid.NewV4()).String()
	}
	if proxy.AddedAt == "" {
		proxy.AddedAt = time.Now().UTC().Format(time.RFC3339)
	}
	ps.data.Proxies = append(ps.data.Proxies, proxy)
	ps.mu.Unlock()
	ps.save()
	return proxy
}

func (ps *ProxyStore) AddProxies(proxies []StoredProxy) []StoredProxy {
	ps.mu.Lock()
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range proxies {
		if proxies[i].ID == "" {
			proxies[i].ID = uuid.Must(uuid.NewV4()).String()
		}
		if proxies[i].AddedAt == "" {
			proxies[i].AddedAt = now
		}
	}
	ps.data.Proxies = append(ps.data.Proxies, proxies...)
	ps.mu.Unlock()
	ps.save()
	return proxies
}

func (ps *ProxyStore) RemoveProxy(id string) bool {
	ps.mu.Lock()
	found := false
	for i, p := range ps.data.Proxies {
		if p.ID == id {
			ps.data.Proxies = append(ps.data.Proxies[:i], ps.data.Proxies[i+1:]...)
			found = true
			break
		}
	}
	ps.mu.Unlock()
	if found {
		ps.save()
	}
	return found
}

func (ps *ProxyStore) GetProxy(id string) *StoredProxy {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for _, p := range ps.data.Proxies {
		if p.ID == id {
			cp := p
			return &cp
		}
	}
	return nil
}

func (ps *ProxyStore) ListProxies() []StoredProxy {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	result := make([]StoredProxy, len(ps.data.Proxies))
	copy(result, ps.data.Proxies)
	return result
}

func (ps *ProxyStore) GetBySubscription(subID string) []StoredProxy {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	var result []StoredProxy
	for _, p := range ps.data.Proxies {
		if p.SubscriptionID == subID {
			result = append(result, p)
		}
	}
	return result
}

func (ps *ProxyStore) RemoveBySubscription(subID string) int {
	ps.mu.Lock()
	var kept []StoredProxy
	removed := 0
	for _, p := range ps.data.Proxies {
		if p.SubscriptionID == subID {
			removed++
		} else {
			kept = append(kept, p)
		}
	}
	ps.data.Proxies = kept
	ps.mu.Unlock()
	if removed > 0 {
		ps.save()
	}
	return removed
}

func (ps *ProxyStore) ClearProxies() int {
	ps.mu.Lock()
	count := len(ps.data.Proxies)
	ps.data.Proxies = nil
	ps.mu.Unlock()
	ps.save()
	return count
}

func (ps *ProxyStore) SetLocalPort(proxyID string, port uint16) {
	ps.mu.Lock()
	for i := range ps.data.Proxies {
		if ps.data.Proxies[i].ID == proxyID {
			ps.data.Proxies[i].LocalPort = port
			break
		}
	}
	ps.mu.Unlock()
	ps.save()
}

// Subscription methods

func (ps *ProxyStore) AddSubscription(sub StoredSubscription) StoredSubscription {
	ps.mu.Lock()
	if sub.ID == "" {
		sub.ID = uuid.Must(uuid.NewV4()).String()
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if sub.CreatedAt == "" {
		sub.CreatedAt = now
	}
	if sub.UpdatedAt == "" {
		sub.UpdatedAt = now
	}
	ps.data.Subscriptions = append(ps.data.Subscriptions, sub)
	ps.mu.Unlock()
	ps.save()
	return sub
}

func (ps *ProxyStore) GetSubscription(id string) *StoredSubscription {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for _, s := range ps.data.Subscriptions {
		if s.ID == id {
			cp := s
			return &cp
		}
	}
	return nil
}

func (ps *ProxyStore) ListSubscriptions() []StoredSubscription {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	result := make([]StoredSubscription, len(ps.data.Subscriptions))
	copy(result, ps.data.Subscriptions)
	return result
}

func (ps *ProxyStore) RemoveSubscription(id string) bool {
	ps.mu.Lock()
	found := false
	for i, s := range ps.data.Subscriptions {
		if s.ID == id {
			ps.data.Subscriptions = append(ps.data.Subscriptions[:i], ps.data.Subscriptions[i+1:]...)
			found = true
			break
		}
	}
	ps.mu.Unlock()
	if found {
		ps.save()
	}
	return found
}

func (ps *ProxyStore) UpdateSubscription(id string, proxyCount int) {
	ps.mu.Lock()
	for i := range ps.data.Subscriptions {
		if ps.data.Subscriptions[i].ID == id {
			ps.data.Subscriptions[i].ProxyCount = proxyCount
			ps.data.Subscriptions[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			break
		}
	}
	ps.mu.Unlock()
	ps.save()
}
