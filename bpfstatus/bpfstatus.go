package bpfstatus

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

var bpfPacketMap *ebpf.Map
var bpfStartTime string

func init() {
	caddy.RegisterModule(UdpQuiz{})
	httpcaddyfile.RegisterGlobalOption("udpquiz", parseUdpQuizOption)
	caddy.RegisterModule(BpfStatus{})
	httpcaddyfile.RegisterHandlerDirective("bpfstatus", parseBpfStatusDirective)
	httpcaddyfile.RegisterDirectiveOrder("bpfstatus", httpcaddyfile.Before, "templates")
}

type UdpQuiz struct {
	Interface string `json:"interface,omitempty"`

	logger *zap.Logger

	objs    udpquizBpfObjects
	tcxLink link.Link
}

func (UdpQuiz) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "radiantly.udpquiz",
		New: func() caddy.Module { return new(UdpQuiz) },
	}
}

func (u *UdpQuiz) Provision(ctx caddy.Context) error {
	u.logger = ctx.Logger()

	// if network interface is not supplied by user, choose first one
	if u.Interface == "" {
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}

		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}
			u.Interface = iface.Name
		}

		if u.Interface == "" {
			return fmt.Errorf("no suitable network interface found")
		}
	}
	return nil
}

func (u *UdpQuiz) Start() error {
	if err := loadUdpquizBpfObjects(&u.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}

	iface, err := net.InterfaceByName(u.Interface)
	if err != nil {
		u.objs.Close()
		return fmt.Errorf("getting interface %q: %w", u.Interface, err)
	}

	u.tcxLink, err = link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   u.objs.ClsMain,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		u.objs.Close()
		return fmt.Errorf("attaching TC program to %q: %w", u.Interface, err)
	}

	u.logger.Info("BPF program attached", zap.String("interface", u.Interface))
	bpfPacketMap = u.objs.PacketCount
	bpfStartTime = time.Now().Format("January 2, 2006")
	return nil
}

func (u *UdpQuiz) Stop() error {
	bpfPacketMap = nil
	if u.tcxLink != nil {
		u.tcxLink.Close()
	}
	return u.objs.Close()
}

func (u *UdpQuiz) Validate() error {
	if _, err := net.InterfaceByName(u.Interface); err != nil {
		return fmt.Errorf("interface %q not found: %w", u.Interface, err)
	}
	return nil
}

func (u *UdpQuiz) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	//	udpquiz {
	//	    interface <name>   # optional
	//	}

	d.Next() // consume directive name
	for d.NextBlock(0) {
		switch d.Val() {
		case "interface":
			if !d.NextArg() {
				return d.ArgErr()
			}
			u.Interface = d.Val()
		default:
			return d.Errf("unknown subdirective: %s", d.Val())
		}
	}
	return nil
}

func parseUdpQuizOption(d *caddyfile.Dispenser, _ any) (any, error) {
	app := &UdpQuiz{}

	if err := app.UnmarshalCaddyfile(d); err != nil {
		return nil, err
	}

	return httpcaddyfile.App{
		Name:  "radiantly.udpquiz",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

// BpfStatus sets the udpquiz.bpf_packets replacer variable from the BPF packet counter.
type BpfStatus struct{}

func (BpfStatus) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.bpfstatus",
		New: func() caddy.Module { return new(BpfStatus) },
	}
}

func (b *BpfStatus) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}

	if bpfPacketMap != nil {
		repl.Set("udpquiz.start", bpfStartTime)
		if nCPU, err := ebpf.PossibleCPU(); err == nil {
			perCPU := make([]uint64, nCPU)
			if err := bpfPacketMap.Lookup(uint32(0), perCPU); err == nil {
				var total uint64
				for _, v := range perCPU {
					total += v
				}
				repl.Set("udpquiz.bpf_packets", strconv.FormatUint(total, 10))
			}
		}
	}

	return next.ServeHTTP(w, r)
}

func (b *BpfStatus) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	return nil
}

func parseBpfStatusDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	b := new(BpfStatus)
	return b, b.UnmarshalCaddyfile(h.Dispenser)
}

// Interface guards
var (
	_ caddy.Module          = (*UdpQuiz)(nil)
	_ caddy.Provisioner     = (*UdpQuiz)(nil)
	_ caddy.Validator       = (*UdpQuiz)(nil)
	_ caddy.App             = (*UdpQuiz)(nil)
	_ caddyfile.Unmarshaler = (*UdpQuiz)(nil)

	_ caddy.Module                = (*BpfStatus)(nil)
	_ caddyfile.Unmarshaler       = (*BpfStatus)(nil)
	_ caddyhttp.MiddlewareHandler = (*BpfStatus)(nil)
)
