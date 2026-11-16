package nfqueue

import (
	"testing"

	"github.com/mdlayher/netlink"
)

func TestCheckHeader(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"inet", []byte{2, 0, 0, 1}, false},
		{"inet6", []byte{10, 0, 0, 1}, false},
		{"bridge", []byte{7, 0, 0, 1}, false},
		{"bridge longer", []byte{7, 0, 0, 1, 9, 9, 9, 9}, false},
		{"unspec", []byte{0, 0, 0, 1}, true},
		{"unsupported family", []byte{3, 0, 0, 1}, true},
		{"bridge bad version", []byte{7, 1, 0, 1}, true},
		{"inet bad version", []byte{2, 1, 0, 1}, true},
		{"empty", []byte{}, true},
		{"one byte", []byte{7}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			off, err := checkHeader(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got offset %d", off)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if off != 4 {
				t.Fatalf("offset = %d, want 4", off)
			}
		})
	}
}

func TestExtractAttributesBridge(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x08, 0x00, 0x00}
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: nfQaPacketHdr, Data: data}})
	if err != nil {
		t.Fatal(err)
	}
	msg := append([]byte{7, 0, 0x00, 0x35}, attrs...)

	got, err := extractAttributes(new(devNull), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.PacketID == nil || *got.PacketID != 0x01020304 {
		t.Fatalf("PacketID = %v, want 0x01020304", got.PacketID)
	}
	if got.HwProtocol == nil || *got.HwProtocol != 0x0800 {
		t.Fatalf("HwProtocol = %v, want 0x0800", got.HwProtocol)
	}
}
