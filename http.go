package cracker

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"fmt"

	"errors"
	"strings"
	"sync"

	g "github.com/golang/glog"

	"io"

	"github.com/pborman/uuid"
)

const (
	CONNECT = "/connect"
	PING    = "/ping"
	PULL    = "/pull"
	PUSH    = "/push"
)
const (
	DATA_TYP  = "data"
	QUIT_TYP  = "quit"
	HEART_TYP = "heart"
)

const (
	timeout  = 10
	signTTL  = 10
	heartTTL = 60
)

// Log level for glog
const (
	LFATAL = iota
	LERROR
	LWARNING
	LINFO
	LDEBUG
)

const (
	version = "20170803"
)

var bufPool = &sync.Pool{New: func() interface{} { return make([]byte, 1024*8) }}

type httpProxy struct {
	addr     string
	secret   string
	proxyMap map[string]*proxyConn
	sync.Mutex
	https bool
	rp    http.Handler
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func myNewSingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.Header.Set("Host", target.Host)
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	return &httputil.ReverseProxy{Director: director}
}

func NewHttpProxy(addr, secret string, https bool, rpAddr string) *httpProxy {
	server := &httpProxy{addr: addr,
		secret:   secret,
		proxyMap: make(map[string]*proxyConn),
		https:    https,
	}
	if strings.HasPrefix(rpAddr, "http") {
		u, err := url.Parse(rpAddr)
		if err != nil {
			g.Fatal(err)
			return nil
		}
		server.rp = myNewSingleHostReverseProxy(u)
	}
	return server
}

func (hp *httpProxy) handler() {
	http.HandleFunc("/", hp.reverseProxy)
	http.HandleFunc(CONNECT, hp.connect)
	http.HandleFunc(PULL, hp.pull)
	http.HandleFunc(PUSH, hp.push)
	http.HandleFunc(PING, hp.ping)
}

func (hp *httpProxy) ListenHTTPS(cert, key string) {
	hp.handler()
	g.Infof("listen at:[%s]", hp.addr)
	g.Fatal("ListenAndServe: ", http.ListenAndServeTLS(hp.addr, cert, key, nil))
}

func (hp *httpProxy) Listen() {
	hp.handler()
	g.Infof("listen at:[%s]", hp.addr)
	g.Fatal("ListenAndServe: ", http.ListenAndServe(hp.addr, nil))
}

func (hp *httpProxy) reverseProxy(w http.ResponseWriter, r *http.Request) {
	if hp.rp == nil {
		WriteNotFoundError(w, "404")
	} else {
		hp.rp.ServeHTTP(w, r)
	}
}

func (hp *httpProxy) verify(r *http.Request) error {
	ts := r.Header.Get("timestamp")
	sign := r.Header.Get("sign")
	tm, err := strconv.ParseInt(ts, 10, 0)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if now-tm > signTTL {
		return errors.New("timestamp expire")
	}
	if VerifyHMACSHA1(hp.secret, ts, sign) {
		return nil
	} else {
		return errors.New("sign invalid")
	}
}

func (hp *httpProxy) before(w http.ResponseWriter, r *http.Request) error {
	err := hp.verify(r)
	if err != nil {
		g.V(LDEBUG).Info(err)
		WriteNotFoundError(w, "404")
	}
	return err
}

func (hp *httpProxy) ping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Version", version)
	w.Write([]byte("pong"))
}

func (hp *httpProxy) pull(w http.ResponseWriter, r *http.Request) {
	if err := hp.before(w, r); err != nil {
		return
	}
	uuid := r.Header.Get("UUID")
	hp.Lock()
	pc, ok := hp.proxyMap[uuid]
	hp.Unlock()
	if !ok {
		WriteHTTPError(w, "uuid don't exist")
		return
	}
	if pc.IsClosed() {
		WriteHTTPError(w, "remote conn is closed")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	interval := r.Header.Get("Interval")
	if interval == "" {
		interval = "0"
	}
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	t, _ := strconv.ParseInt(interval, 10, 0)
	if t > 0 {
		pc.remote.SetReadDeadline(time.Now().Add(time.Duration(t)))
		n, err := pc.remote.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
		}
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
			} else {
				if err != io.EOF && !pc.IsClosed() {
					g.V(LERROR).Infof("read :%v", err)
				}
				pc.Close()
			}
		}

		return
	}
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Transfer-Encoding", "chunked")
	defer pc.Close()
	for {
		flusher.Flush()
		n, err := pc.remote.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
		}
		if err != nil {
			if err != io.EOF && !pc.IsClosed() {
				g.V(LERROR).Info(err)
			}
			return
		}
	}
}

func (hp *httpProxy) push(w http.ResponseWriter, r *http.Request) {
	if err := hp.before(w, r); err != nil {
		return
	}
	uuid := r.Header.Get("UUID")
	hp.Lock()
	pc, ok := hp.proxyMap[uuid]
	hp.Unlock()
	if !ok {
		WriteHTTPError(w, "uuid don't exist")
		return
	}
	if pc.IsClosed() {
		WriteHTTPError(w, "remote conn is closed")
		return
	}

	typ := r.Header.Get("TYP")
	switch typ {
	default:
	case HEART_TYP:
		pc.Heart()
	case QUIT_TYP:
		pc.Close()
	case DATA_TYP:
		_, err := io.Copy(pc.remote, r.Body)
		if err != nil && err != io.EOF {
			if !pc.IsClosed() {
				g.V(LERROR).Info(err)
			}
			pc.Close()
		}
	}

}

func (hp *httpProxy) connect(w http.ResponseWriter, r *http.Request) {

	if err := hp.before(w, r); err != nil {
		return
	}

	host := r.Header.Get("DSTHOST")
	port := r.Header.Get("DSTPORT")
	addr := fmt.Sprintf("%s:%s", host, port)
	remote, err := net.DialTimeout("tcp", addr, time.Second*timeout)
	if err != nil {
		WriteHTTPError(w, fmt.Sprintf("connect %s %v", addr, err))
		return
	}
	g.V(LINFO).Infof("connect %s success", addr)
	proxyID := uuid.New()
	pc := newProxyConn(remote, proxyID)
	hp.Lock()
	hp.proxyMap[proxyID] = pc
	hp.Unlock()

	go func() {
		pc.Do()
		hp.Lock()
		delete(hp.proxyMap, proxyID)
		hp.Unlock()
		g.V(LINFO).Infof("disconnect %s", addr)
	}()
	WriteHTTPOK(w, proxyID)
}
