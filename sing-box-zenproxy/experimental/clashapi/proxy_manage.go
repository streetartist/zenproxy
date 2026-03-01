package clashapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/experimental/clashapi/parser"
	"github.com/sagernet/sing-box/log"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func proxyManageRouter(bm *BindingManager) http.Handler {
	r := chi.NewRouter()
	r.Get("/", bm.listStoredProxies)
	r.Post("/", bm.addStoredProxy)
	r.Delete("/", bm.clearStoredProxies)
	r.Delete("/{id}", bm.deleteStoredProxy)
	return r
}

func (bm *BindingManager) listStoredProxies(w http.ResponseWriter, r *http.Request) {
	proxies := bm.store.ListProxies()
	render.JSON(w, r, render.M{
		"proxies": proxies,
		"count":   len(proxies),
	})
}

type addProxyRequest struct {
	URI      string          `json:"uri"`
	Outbound json.RawMessage `json:"outbound"`
}

func (bm *BindingManager) addStoredProxy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("failed to read body"))
		return
	}

	var req addProxyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid JSON: "+err.Error()))
		return
	}

	if req.URI == "" && len(req.Outbound) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("uri or outbound is required"))
		return
	}

	var proxy StoredProxy

	if req.URI != "" {
		pc := parser.ParseURI(strings.TrimSpace(req.URI))
		if pc == nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("failed to parse URI"))
			return
		}
		proxy = StoredProxy{
			Name:     pc.Name,
			Type:     pc.Type,
			Server:   pc.Server,
			Port:     pc.Port,
			Outbound: pc.Outbound,
			Source:   "manual",
		}
	} else {
		var outboundMap map[string]interface{}
		if err := json.Unmarshal(req.Outbound, &outboundMap); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid outbound JSON"))
			return
		}
		proxyType, _ := outboundMap["type"].(string)
		server, _ := outboundMap["server"].(string)
		var port uint16
		if p, ok := outboundMap["server_port"].(float64); ok {
			port = uint16(p)
		}
		name := fmt.Sprintf("%s:%d", server, port)
		proxy = StoredProxy{
			Name:     name,
			Type:     proxyType,
			Server:   server,
			Port:     port,
			Outbound: req.Outbound,
			Source:   "manual",
		}
	}

	proxy = bm.store.AddProxy(proxy)
	bm.logger.Info("added proxy to store: ", proxy.Name)
	render.Status(r, http.StatusCreated)
	render.JSON(w, r, proxy)
}

func (bm *BindingManager) deleteStoredProxy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !bm.store.RemoveProxy(id) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("proxy not found: "+id))
		return
	}
	bm.logger.Info("removed proxy from store: ", id)
	render.NoContent(w, r)
}

func (bm *BindingManager) clearStoredProxies(w http.ResponseWriter, r *http.Request) {
	count := bm.store.ClearProxies()
	bm.logger.Info("cleared all proxies from store: ", count)
	render.JSON(w, r, render.M{
		"removed": count,
		"message": fmt.Sprintf("Removed %d proxies", count),
	})
}

// --- Port Pool ---

type PortPool struct {
	basePort uint16
	maxPorts uint16
	used     map[uint16]string // port -> proxy_id
	mu       sync.Mutex
	logger   log.Logger
}

func newPortPool(basePort, maxPorts uint16, logger log.Logger) *PortPool {
	return &PortPool{
		basePort: basePort,
		maxPorts: maxPorts,
		used:     make(map[uint16]string),
		logger:   logger,
	}
}

func (pp *PortPool) Allocate(proxyID string) (uint16, error) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	for i := uint16(0); i < pp.maxPorts; i++ {
		port := pp.basePort + i
		if _, ok := pp.used[port]; !ok {
			pp.used[port] = proxyID
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available ports in range %d-%d", pp.basePort, pp.basePort+pp.maxPorts-1)
}

func (pp *PortPool) Release(port uint16) {
	pp.mu.Lock()
	delete(pp.used, port)
	pp.mu.Unlock()
}

func (pp *PortPool) GetProxyID(port uint16) string {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	return pp.used[port]
}

func (pp *PortPool) UsedCount() int {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	return len(pp.used)
}
