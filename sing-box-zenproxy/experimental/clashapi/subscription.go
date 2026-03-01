package clashapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sagernet/sing-box/experimental/clashapi/parser"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func subscriptionRouter(bm *BindingManager) http.Handler {
	r := chi.NewRouter()
	r.Get("/", bm.listSubscriptions)
	r.Post("/", bm.addSubscription)
	r.Delete("/{id}", bm.deleteSubscription)
	r.Post("/{id}/refresh", bm.refreshSubscription)
	return r
}

func (bm *BindingManager) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	subs := bm.store.ListSubscriptions()
	render.JSON(w, r, render.M{
		"subscriptions": subs,
		"count":         len(subs),
	})
}

type addSubscriptionRequest struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

func (bm *BindingManager) addSubscription(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("failed to read body"))
		return
	}

	var req addSubscriptionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid JSON: "+err.Error()))
		return
	}

	if req.URL == "" && req.Content == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("url or content is required"))
		return
	}
	if req.Name == "" {
		req.Name = "subscription"
	}
	if req.Type == "" {
		req.Type = "auto"
	}

	var content string
	if req.URL != "" {
		fetched, err := fetchURL(req.URL)
		if err != nil {
			render.Status(r, http.StatusBadGateway)
			render.JSON(w, r, newError("failed to fetch URL: "+err.Error()))
			return
		}
		content = fetched
	} else {
		content = req.Content
	}

	configs := parser.Parse(content, req.Type)
	if len(configs) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("no proxies found in subscription content"))
		return
	}

	sub := bm.store.AddSubscription(StoredSubscription{
		Name:       req.Name,
		Type:       req.Type,
		URL:        req.URL,
		ProxyCount: len(configs),
	})

	proxies := make([]StoredProxy, 0, len(configs))
	for _, pc := range configs {
		proxies = append(proxies, StoredProxy{
			Name:           pc.Name,
			Type:           pc.Type,
			Server:         pc.Server,
			Port:           pc.Port,
			Outbound:       pc.Outbound,
			Source:         "subscription",
			SubscriptionID: sub.ID,
		})
	}
	bm.store.AddProxies(proxies)

	bm.logger.Info("added subscription ", sub.Name, " with ", len(configs), " proxies")
	render.Status(r, http.StatusCreated)
	render.JSON(w, r, render.M{
		"subscription": sub,
		"added":        len(configs),
	})
}

func (bm *BindingManager) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	sub := bm.store.GetSubscription(id)
	if sub == nil {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("subscription not found: "+id))
		return
	}

	// Remove all proxies belonging to this subscription
	removed := bm.store.RemoveBySubscription(id)
	bm.store.RemoveSubscription(id)

	bm.logger.Info("deleted subscription ", sub.Name, " and ", removed, " proxies")
	render.JSON(w, r, render.M{
		"message":        fmt.Sprintf("Deleted subscription '%s' and %d proxies", sub.Name, removed),
		"proxies_removed": removed,
	})
}

func (bm *BindingManager) refreshSubscription(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	sub := bm.store.GetSubscription(id)
	if sub == nil {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("subscription not found: "+id))
		return
	}

	if sub.URL == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("subscription has no URL to refresh"))
		return
	}

	content, err := fetchURL(sub.URL)
	if err != nil {
		render.Status(r, http.StatusBadGateway)
		render.JSON(w, r, newError("failed to fetch URL: "+err.Error()))
		return
	}

	configs := parser.Parse(content, sub.Type)
	if len(configs) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("no proxies found in refreshed subscription"))
		return
	}

	// Remove old proxies for this subscription
	removed := bm.store.RemoveBySubscription(id)

	// Add new proxies
	proxies := make([]StoredProxy, 0, len(configs))
	for _, pc := range configs {
		proxies = append(proxies, StoredProxy{
			Name:           pc.Name,
			Type:           pc.Type,
			Server:         pc.Server,
			Port:           pc.Port,
			Outbound:       pc.Outbound,
			Source:         "subscription",
			SubscriptionID: id,
		})
	}
	bm.store.AddProxies(proxies)
	bm.store.UpdateSubscription(id, len(configs))

	bm.logger.Info("refreshed subscription ", sub.Name, ": removed ", removed, ", added ", len(configs))
	render.JSON(w, r, render.M{
		"removed": removed,
		"added":   len(configs),
		"message": fmt.Sprintf("Refreshed: removed %d, added %d proxies", removed, len(configs)),
	})
}

func fetchURL(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
