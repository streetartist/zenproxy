package clashapi

import (
	stdjson "encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// BindingInfo tracks a dynamically created inbound+outbound pair.
type BindingInfo struct {
	Tag         string `json:"tag"`
	InboundTag  string `json:"inbound_tag"`
	OutboundTag string `json:"outbound_tag"`
	ListenPort  uint16 `json:"listen_port"`
	ProxyID     string `json:"proxy_id,omitempty"`
}

// BindingManager holds state for dynamic proxy bindings.
type BindingManager struct {
	server   *Server
	logger   log.ContextLogger
	bindings map[string]*BindingInfo
	mu       sync.Mutex
	store    *ProxyStore
	portPool *PortPool
}

func newBindingManager(server *Server, logFactory log.Factory, store *ProxyStore, portPool *PortPool) *BindingManager {
	return &BindingManager{
		server:   server,
		logger:   logFactory.NewLogger("bindings"),
		bindings: make(map[string]*BindingInfo),
		store:    store,
		portPool: portPool,
	}
}

func bindingRouter(bm *BindingManager) http.Handler {
	r := chi.NewRouter()
	r.Get("/", bm.listBindings)
	r.Post("/", bm.createBinding)
	r.Post("/batch", bm.batchCreateBindings)
	r.Delete("/all", bm.deleteAllBindings)
	r.Delete("/{tag}", bm.deleteBinding)
	return r
}

func (bm *BindingManager) listBindings(w http.ResponseWriter, r *http.Request) {
	bm.mu.Lock()
	result := make([]*BindingInfo, 0, len(bm.bindings))
	for _, b := range bm.bindings {
		result = append(result, b)
	}
	bm.mu.Unlock()
	render.JSON(w, r, result)
}

type createBindingRequest struct {
	Tag        string             `json:"tag"`
	ListenPort uint16             `json:"listen_port"`
	Outbound   stdjson.RawMessage `json:"outbound"`
	ProxyID    string             `json:"proxy_id"`
}

func (bm *BindingManager) createBinding(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("failed to read body"))
		return
	}

	var req createBindingRequest
	if err := stdjson.Unmarshal(body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid JSON: "+err.Error()))
		return
	}

	// If proxy_id is specified, load outbound from store and auto-assign port
	if req.ProxyID != "" {
		proxy := bm.store.GetProxy(req.ProxyID)
		if proxy == nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError("proxy not found in store: "+req.ProxyID))
			return
		}
		req.Outbound = proxy.Outbound
		if req.Tag == "" {
			req.Tag = req.ProxyID
		}
		if req.ListenPort == 0 && bm.portPool != nil {
			port, err := bm.portPool.Allocate(req.ProxyID)
			if err != nil {
				render.Status(r, http.StatusServiceUnavailable)
				render.JSON(w, r, newError(err.Error()))
				return
			}
			req.ListenPort = port
		}
	}

	if req.Tag == "" || req.ListenPort == 0 || len(req.Outbound) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("tag, listen_port, and outbound are required"))
		return
	}

	binding, err := bm.createBindingInternal(req.Tag, req.ListenPort, req.Outbound, req.ProxyID)
	if err != nil {
		// Release port if auto-allocated
		if req.ProxyID != "" && bm.portPool != nil {
			bm.portPool.Release(req.ListenPort)
		}
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	// Update store with local port
	if req.ProxyID != "" {
		bm.store.SetLocalPort(req.ProxyID, req.ListenPort)
	}

	render.Status(r, http.StatusCreated)
	render.JSON(w, r, binding)
}

func (bm *BindingManager) createBindingInternal(tag string, listenPort uint16, outbound stdjson.RawMessage, proxyID string) (*BindingInfo, error) {
	bm.mu.Lock()
	if _, exists := bm.bindings[tag]; exists {
		bm.mu.Unlock()
		return nil, fmt.Errorf("binding already exists: %s", tag)
	}
	bm.mu.Unlock()

	// Parse outbound options using the context with registries
	var outboundOpt option.Outbound
	if err := json.UnmarshalContext(bm.server.ctx, outbound, &outboundOpt); err != nil {
		return nil, fmt.Errorf("invalid outbound config: %w", err)
	}

	outboundTag := "bind-out-" + tag
	inboundTag := "bind-in-" + tag

	// Create outbound
	if err := bm.server.outbound.Create(
		bm.server.ctx, bm.server.router, bm.logger,
		outboundTag, outboundOpt.Type, outboundOpt.Options,
	); err != nil {
		return nil, fmt.Errorf("failed to create outbound: %w", err)
	}

	// Create inbound (mixed HTTP+SOCKS5 on 127.0.0.1:listen_port)
	inboundJSON := fmt.Sprintf(`{"type":"mixed","listen":"127.0.0.1","listen_port":%d}`, listenPort)
	var inboundOpt option.Inbound
	if err := json.UnmarshalContext(bm.server.ctx, []byte(inboundJSON), &inboundOpt); err != nil {
		// Rollback: remove outbound
		bm.server.outbound.Remove(outboundTag)
		return nil, fmt.Errorf("failed to parse inbound config: %w", err)
	}

	inboundMgr := service.FromContext[adapter.InboundManager](bm.server.ctx)
	if err := inboundMgr.Create(
		bm.server.ctx, bm.server.router, bm.logger,
		inboundTag, inboundOpt.Type, inboundOpt.Options,
	); err != nil {
		// Rollback: remove outbound
		bm.server.outbound.Remove(outboundTag)
		return nil, fmt.Errorf("failed to create inbound: %w", err)
	}

	// Bind inbound → outbound in router
	bm.server.router.BindInboundOutbound(inboundTag, outboundTag)

	binding := &BindingInfo{
		Tag:         tag,
		InboundTag:  inboundTag,
		OutboundTag: outboundTag,
		ListenPort:  listenPort,
		ProxyID:     proxyID,
	}
	bm.mu.Lock()
	bm.bindings[tag] = binding
	bm.mu.Unlock()

	bm.logger.Info("created binding: ", tag, " (port ", listenPort, " → ", outboundOpt.Type, ")")
	return binding, nil
}

// createBindingForProxy creates a binding for a stored proxy with auto-allocated port.
func (bm *BindingManager) createBindingForProxy(proxy StoredProxy) (*BindingInfo, error) {
	if bm.portPool == nil {
		return nil, fmt.Errorf("port pool not initialized")
	}

	port, err := bm.portPool.Allocate(proxy.ID)
	if err != nil {
		return nil, err
	}

	binding, err := bm.createBindingInternal(proxy.ID, port, proxy.Outbound, proxy.ID)
	if err != nil {
		bm.portPool.Release(port)
		return nil, err
	}

	bm.store.SetLocalPort(proxy.ID, port)
	return binding, nil
}

func (bm *BindingManager) deleteBinding(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")

	bm.mu.Lock()
	binding, exists := bm.bindings[tag]
	if !exists {
		bm.mu.Unlock()
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("binding not found: "+tag))
		return
	}
	delete(bm.bindings, tag)
	bm.mu.Unlock()

	bm.removeBindingResources(binding)

	bm.logger.Info("deleted binding: ", tag)
	render.NoContent(w, r)
}

func (bm *BindingManager) removeBindingResources(binding *BindingInfo) {
	// Unbind route
	bm.server.router.UnbindInbound(binding.InboundTag)

	// Remove inbound first (stops listening)
	inboundMgr := service.FromContext[adapter.InboundManager](bm.server.ctx)
	if err := inboundMgr.Remove(binding.InboundTag); err != nil {
		bm.logger.Warn("failed to remove inbound ", binding.InboundTag, ": ", err)
	}

	// Remove outbound
	if err := bm.server.outbound.Remove(binding.OutboundTag); err != nil {
		bm.logger.Warn("failed to remove outbound ", binding.OutboundTag, ": ", err)
	}

	// Release port
	if bm.portPool != nil {
		bm.portPool.Release(binding.ListenPort)
	}

	// Clear local port in store
	if binding.ProxyID != "" {
		bm.store.SetLocalPort(binding.ProxyID, 0)
	}
}

// --- Batch operations ---

type batchCreateRequest struct {
	ProxyIDs []string          `json:"proxy_ids"`
	All      bool              `json:"all"`
	Count    int               `json:"count"`
	Filter   *batchFilter      `json:"filter"`
}

type batchFilter struct {
	Type   string `json:"type"`
	Source string `json:"source"`
}

type batchBindingResult struct {
	ProxyID   string `json:"proxy_id"`
	LocalPort uint16 `json:"local_port"`
}

func (bm *BindingManager) batchCreateBindings(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("failed to read body"))
		return
	}

	var req batchCreateRequest
	if err := stdjson.Unmarshal(body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid JSON: "+err.Error()))
		return
	}

	if bm.portPool == nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError("port pool not initialized"))
		return
	}

	// Determine which proxies to bind
	var proxies []StoredProxy
	if len(req.ProxyIDs) > 0 {
		for _, id := range req.ProxyIDs {
			if p := bm.store.GetProxy(id); p != nil {
				proxies = append(proxies, *p)
			}
		}
	} else {
		proxies = bm.store.ListProxies()
	}

	// Apply filter
	if req.Filter != nil {
		var filtered []StoredProxy
		for _, p := range proxies {
			if req.Filter.Type != "" && p.Type != req.Filter.Type {
				continue
			}
			if req.Filter.Source != "" && p.Source != req.Filter.Source {
				continue
			}
			filtered = append(filtered, p)
		}
		proxies = filtered
	}

	// Apply count limit
	if !req.All && req.Count > 0 && req.Count < len(proxies) {
		proxies = proxies[:req.Count]
	}

	// Skip proxies that already have bindings
	var toBind []StoredProxy
	bm.mu.Lock()
	for _, p := range proxies {
		if _, exists := bm.bindings[p.ID]; !exists {
			toBind = append(toBind, p)
		}
	}
	bm.mu.Unlock()

	created := 0
	failed := 0
	var bindings []batchBindingResult
	for _, p := range toBind {
		binding, err := bm.createBindingForProxy(p)
		if err != nil {
			bm.logger.Warn("batch bind failed for ", p.Name, ": ", err)
			failed++
			continue
		}
		created++
		bindings = append(bindings, batchBindingResult{
			ProxyID:   p.ID,
			LocalPort: binding.ListenPort,
		})
	}

	bm.logger.Info("batch created ", created, " bindings (", failed, " failed)")
	render.JSON(w, r, render.M{
		"created":  created,
		"failed":   failed,
		"bindings": bindings,
	})
}

func (bm *BindingManager) deleteAllBindings(w http.ResponseWriter, r *http.Request) {
	bm.mu.Lock()
	allBindings := make([]*BindingInfo, 0, len(bm.bindings))
	for _, b := range bm.bindings {
		allBindings = append(allBindings, b)
	}
	// Clear the map
	bm.bindings = make(map[string]*BindingInfo)
	bm.mu.Unlock()

	for _, binding := range allBindings {
		bm.removeBindingResources(binding)
	}

	bm.logger.Info("deleted all bindings: ", len(allBindings))
	render.JSON(w, r, render.M{
		"removed": len(allBindings),
		"message": fmt.Sprintf("Removed %d bindings", len(allBindings)),
	})
}
