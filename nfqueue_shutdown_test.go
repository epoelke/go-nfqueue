package nfqueue

import (
	"context"
	"fmt"
	"iter"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

type recordingLogger struct {
	mu     sync.Mutex
	errors []string
}

func (l *recordingLogger) Debugf(format string, args ...any) {}

func (l *recordingLogger) Errorf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, fmt.Sprintf(format, args...))
}

func (l *recordingLogger) recorded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.errors...)
}

// deadlineSocket is a netlink.Socket that honours read deadlines like a real socket.
type deadlineSocket struct {
	mu       sync.Mutex
	deadline time.Time
	queue    []netlink.Message
	sent     []netlink.Message
	wake     chan struct{}
	entered  chan struct{}
	once     sync.Once

	// unbindAckWait delays the unbind's ack until a past read deadline is
	// set or the wait elapses, so a late deadline write deterministically
	// lands before the ack is read.
	unbindAckWait time.Duration
	past          chan struct{}
	pastOnce      sync.Once
}

func newDeadlineSocket() *deadlineSocket {
	return &deadlineSocket{
		wake:    make(chan struct{}),
		entered: make(chan struct{}),
		past:    make(chan struct{}),
	}
}

func isUnbind(m netlink.Message) bool {
	return m.Header.Type == netlink.HeaderType((nfnlSubSysQueue<<8)|nfQnlMsgConfig) &&
		len(m.Data) > 8 && m.Data[8] == nfUlnlCfgCmdUnbind
}

func (s *deadlineSocket) notify() {
	close(s.wake)
	s.wake = make(chan struct{})
}

func (s *deadlineSocket) Close() error { return nil }

func (s *deadlineSocket) Send(m netlink.Message) error {
	if s.unbindAckWait > 0 && isUnbind(m) {
		select {
		case <-s.past:
		case <-time.After(s.unbindAckWait):
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, m)
	if m.Header.Type == netlink.HeaderType((nfnlSubSysQueue<<8)|nfQnlMsgConfig) {
		s.queue = append(s.queue, netlink.Message{
			Header: netlink.Header{
				Length:   20,
				Type:     netlink.Error,
				Sequence: m.Header.Sequence,
				PID:      m.Header.PID,
			},
			Data: make([]byte, 4),
		})
		s.notify()
	}
	return nil
}

func (s *deadlineSocket) SendMessages(m []netlink.Message) error {
	for _, msg := range m {
		if err := s.Send(msg); err != nil {
			return err
		}
	}
	return nil
}

func (s *deadlineSocket) Receive() ([]netlink.Message, error) {
	s.once.Do(func() { close(s.entered) })
	for {
		s.mu.Lock()
		if !s.deadline.IsZero() && !s.deadline.After(time.Now()) {
			s.mu.Unlock()
			return nil, os.ErrDeadlineExceeded
		}
		if len(s.queue) > 0 {
			msgs := s.queue
			s.queue = nil
			s.mu.Unlock()
			return msgs, nil
		}
		wake := s.wake
		var timer <-chan time.Time
		if !s.deadline.IsZero() {
			timer = time.After(time.Until(s.deadline))
		}
		s.mu.Unlock()

		select {
		case <-wake:
		case <-timer:
		}
	}
}

func (s *deadlineSocket) ReceiveIter() iter.Seq2[netlink.Message, error] {
	return func(yield func(netlink.Message, error) bool) {
		msgs, err := s.Receive()
		if err != nil {
			yield(netlink.Message{}, err)
			return
		}
		for _, m := range msgs {
			if !yield(m, nil) {
				return
			}
		}
	}
}

func (s *deadlineSocket) SetDeadline(t time.Time) error {
	return s.SetReadDeadline(t)
}

func (s *deadlineSocket) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = t
	s.notify()
	if !t.IsZero() && !t.After(time.Now()) {
		s.pastOnce.Do(func() { close(s.past) })
	}
	return nil
}

func (s *deadlineSocket) SetWriteDeadline(t time.Time) error { return nil }

func (s *deadlineSocket) unbindCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, m := range s.sent {
		if isUnbind(m) {
			n++
		}
	}
	return n
}

func newTestNfqueue(sock *deadlineSocket, log Logger) *Nfqueue {
	return &Nfqueue{
		Con:             netlink.NewConn(sock, 0),
		logger:          log,
		setWriteTimeout: func() error { return nil },
		queue:           53,
		family:          7,
	}
}

// runSocketCallback runs socketCallback until it returns and checks that
// exactly one unbind was sent and acked without error.
func runSocketCallback(t *testing.T, sock *deadlineSocket, ctx context.Context, fn HookFunc, afterStart func()) {
	t.Helper()
	log := &recordingLogger{}
	nf := newTestNfqueue(sock, log)

	nf.wg.Add(1)
	go func() {
		defer nf.wg.Done()
		nf.socketCallback(ctx, fn, func(error) int { return 1 }, 0)
	}()

	afterStart()

	done := make(chan struct{})
	go func() {
		nf.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("socketCallback did not stop within 2s")
	}

	if got := sock.unbindCount(); got != 1 {
		t.Errorf("unbind messages sent = %d, want 1", got)
	}
	for _, e := range log.recorded() {
		if strings.Contains(e, "Could not unbind") {
			t.Errorf("unexpected log: %s", e)
		}
	}
}

func TestUnbindAfterCancelSucceeds(t *testing.T) {
	sock := newDeadlineSocket()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runSocketCallback(t, sock, ctx,
		func(Attribute) int { return 0 },
		func() {
			// Cancel only once the loop is blocked in Receive, as in normal operation.
			<-sock.entered
			cancel()
		})
}

// The loop can see the cancelled context before the cancel goroutine has
// set its past read deadline; that late write must not hit the unbind.
func TestUnbindAfterCancelInCallbackSucceeds(t *testing.T) {
	sock := newDeadlineSocket()
	sock.unbindAckWait = 100 * time.Millisecond
	sock.queue = []netlink.Message{{
		Header: netlink.Header{
			Length: 16,
			Type:   netlink.HeaderType((nfnlSubSysQueue << 8) | nfQnlMsgPacket),
		},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runSocketCallback(t, sock, ctx,
		func(Attribute) int {
			cancel()
			return 0
		},
		func() {})
}
