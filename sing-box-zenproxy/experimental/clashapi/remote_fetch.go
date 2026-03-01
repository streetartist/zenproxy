package clashapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func fetchRouter(bm *BindingManager) http.Handler {
	r := chi.NewRouter()
	r.Post("/", bm.remoteFetch)
	return r
}

type remoteFetchRequest struct {
	Server   string `json:"server"`
	APIKey   string `json:"api_key"`
	Count    int    `json:"count"`
	Country  string `json:"country"`
	ChatGPT  *bool  `json:"chatgpt"`
	Type     string `json:"type"`
	AutoBind bool   `json:"auto_bind"`
}

type serverProxy struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Server   string          `json:"server"`
	Port     uint16          `json:"port"`
	Outbound json.RawMessage `json:"outbound"`
	Quality  json.RawMessage `json:"quality,omitempty"`
}

type serverFetchResponse struct {
	Proxies []serverProxy `json:"proxies"`
	Count   int           `json:"count"`
}

func (bm *BindingManager) remoteFetch(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("failed to read body"))
		return
	}

	var req remoteFetchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid JSON: "+err.Error()))
		return
	}

	if req.Server == "" || req.APIKey == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("server and api_key are required"))
		return
	}
	if req.Count <= 0 {
		req.Count = 10
	}

	// Build server URL
	params := url.Values{}
	params.Set("api_key", req.APIKey)
	params.Set("count", fmt.Sprintf("%d", req.Count))
	if req.Country != "" {
		params.Set("country", req.Country)
	}
	if req.ChatGPT != nil && *req.ChatGPT {
		params.Set("chatgpt", "true")
	}
	if req.Type != "" {
		params.Set("type", req.Type)
	}

	fetchURL := fmt.Sprintf("%s/api/client/fetch?%s", req.Server, params.Encode())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(fetchURL)
	if err != nil {
		render.Status(r, http.StatusBadGateway)
		render.JSON(w, r, newError("failed to fetch from server: "+err.Error()))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		render.Status(r, resp.StatusCode)
		render.JSON(w, r, newError(fmt.Sprintf("server returned %d: %s", resp.StatusCode, string(respBody))))
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		render.Status(r, http.StatusBadGateway)
		render.JSON(w, r, newError("failed to read server response: "+err.Error()))
		return
	}

	var serverResp serverFetchResponse
	if err := json.Unmarshal(respBody, &serverResp); err != nil {
		render.Status(r, http.StatusBadGateway)
		render.JSON(w, r, newError("failed to parse server response: "+err.Error()))
		return
	}

	// Store proxies
	proxies := make([]StoredProxy, 0, len(serverResp.Proxies))
	for _, sp := range serverResp.Proxies {
		proxies = append(proxies, StoredProxy{
			ID:       sp.ID,
			Name:     sp.Name,
			Type:     sp.Type,
			Server:   sp.Server,
			Port:     sp.Port,
			Outbound: sp.Outbound,
			Source:   "server",
		})
	}

	added := bm.store.AddProxies(proxies)

	// Auto-bind if requested
	bindCount := 0
	if req.AutoBind && bm.portPool != nil {
		for _, p := range added {
			if _, err := bm.createBindingForProxy(p); err != nil {
				bm.logger.Warn("auto-bind failed for ", p.Name, ": ", err)
			} else {
				bindCount++
			}
		}
	}

	bm.logger.Info("fetched ", len(added), " proxies from server")
	result := render.M{
		"added":   len(added),
		"message": fmt.Sprintf("Fetched %d proxies from server", len(added)),
	}
	if req.AutoBind {
		result["bound"] = bindCount
	}
	render.JSON(w, r, result)
}
