// Package api exposes the runtime control plane for detour-linux as a
// small JSON-over-HTTP service. The handlers are intentionally backend-
// agnostic: they take NATBackend and HostsBackend interfaces (satisfied
// in production by *linuxnat.Manager and *hostsfile.Manager), which
// keeps every handler trivially unit-testable with fakes.
//
// Routing is done with the net/http ServeMux verb+path syntax (Go 1.22+
// /1.23 feature). No third-party HTTP libraries are introduced.
//
// Endpoint summary
//
//	GET    /healthz
//	GET    /rules
//	POST   /rules                 {from, to, proto?}
//	DELETE /rules/{id}
//	GET    /hosts
//	POST   /hosts                 {hostname, ip}
//	DELETE /hosts/{id}
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"detour/internal/hostsfile"
	"detour/internal/linuxnat"
)

// NATBackend is the slice of *linuxnat.Manager the API depends on. It's
// declared as an interface so tests can inject a fake without standing
// up real iptables.
type NATBackend interface {
	Add(from, to linuxnat.Endpoint, proto linuxnat.Protocol) (string, error)
	Remove(id string) error
	List() []linuxnat.Rule
}

// HostsBackend mirrors NATBackend for the /etc/hosts manager.
type HostsBackend interface {
	Add(hostname, ip string) (string, error)
	Remove(id string) error
	List() []hostsfile.Entry
}

// Server bundles the routes. Construct via New, mount via Handler().
type Server struct {
	nat   NATBackend
	hosts HostsBackend
}

// New builds a Server bound to the given backends. Either backend may
// be nil: the corresponding endpoints then return 503 so the operator
// can still introspect /healthz and the other resource.
func New(nat NATBackend, hosts HostsBackend) *Server {
	return &Server{nat: nat, hosts: hosts}
}

// Handler returns the http.Handler implementing the API surface.
// Includes the embedded browsable web UI:
//
//	GET /            -> web/index.html
//	GET /static/...  -> embedded JS/CSS
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /rules", s.handleListRules)
	mux.HandleFunc("POST /rules", s.handleAddRule)
	mux.HandleFunc("DELETE /rules/{id}", s.handleDeleteRule)
	mux.HandleFunc("GET /hosts", s.handleListHosts)
	mux.HandleFunc("POST /hosts", s.handleAddHost)
	mux.HandleFunc("DELETE /hosts/{id}", s.handleDeleteHost)
	// Web UI: explicit GET on "/" so the JSON API paths above keep
	// their semantics, plus an embedded asset directory.
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /static/{file...}", s.handleStatic)
	return mux
}

// --- JSON DTOs --------------------------------------------------------------

type ruleRequest struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Proto string `json:"proto"`
}

type ruleResponse struct {
	ID    string `json:"id"`
	From  string `json:"from"`
	To    string `json:"to"`
	Proto string `json:"proto"`
}

type hostRequest struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

type hostResponse struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// --- handlers ---------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListRules(w http.ResponseWriter, _ *http.Request) {
	if s.nat == nil {
		writeError(w, http.StatusServiceUnavailable, "NAT backend unavailable")
		return
	}
	out := []ruleResponse{}
	for _, r := range s.nat.List() {
		out = append(out, ruleToResp(r))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request) {
	if s.nat == nil {
		writeError(w, http.StatusServiceUnavailable, "NAT backend unavailable")
		return
	}
	var req ruleRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	from, err := linuxnat.ParseEndpoint(req.From)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("from: %v", err))
		return
	}
	to, err := linuxnat.ParseEndpoint(req.To)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("to: %v", err))
		return
	}
	proto := linuxnat.Protocol(strings.ToLower(req.Proto))
	if proto == "" {
		proto = linuxnat.ProtoBoth
	}
	if !proto.Valid() {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("proto: invalid %q (tcp|udp|both)", req.Proto))
		return
	}
	id, err := s.nat.Add(from, to, proto)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, ruleResponse{
		ID: id, From: from.String(), To: to.String(), Proto: string(proto),
	})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if s.nat == nil {
		writeError(w, http.StatusServiceUnavailable, "NAT backend unavailable")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	if err := s.nat.Remove(id); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListHosts(w http.ResponseWriter, _ *http.Request) {
	if s.hosts == nil {
		writeError(w, http.StatusServiceUnavailable, "hosts backend unavailable")
		return
	}
	out := []hostResponse{}
	for _, e := range s.hosts.List() {
		out = append(out, hostResponse{ID: e.ID, Hostname: e.Hostname, IP: e.IP.String()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAddHost(w http.ResponseWriter, r *http.Request) {
	if s.hosts == nil {
		writeError(w, http.StatusServiceUnavailable, "hosts backend unavailable")
		return
	}
	var req hostRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Hostname) == "" {
		writeError(w, http.StatusBadRequest, "hostname required")
		return
	}
	if net.ParseIP(strings.TrimSpace(req.IP)) == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid ip %q", req.IP))
		return
	}
	id, err := s.hosts.Add(req.Hostname, req.IP)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, hostResponse{
		ID: id, Hostname: strings.ToLower(strings.TrimSpace(req.Hostname)), IP: req.IP,
	})
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	if s.hosts == nil {
		writeError(w, http.StatusServiceUnavailable, "hosts backend unavailable")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	if err := s.hosts.Remove(id); err != nil {
		if errors.Is(err, hostsfile.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host entry not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ----------------------------------------------------------------

func ruleToResp(r linuxnat.Rule) ruleResponse {
	return ruleResponse{
		ID:    r.ID,
		From:  r.From.String(),
		To:    r.To.String(),
		Proto: string(r.Proto),
	}
}

func decodeJSON(body io.Reader, dst any) error {
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

// isNotFound covers both errors.Is(err, os.ErrNotExist) (linuxnat) and
// hostsfile.ErrNotFound, without forcing the API package to import the
// concrete error sentinels everywhere.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, hostsfile.ErrNotFound) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not exist") || strings.Contains(msg, "not found")
}
