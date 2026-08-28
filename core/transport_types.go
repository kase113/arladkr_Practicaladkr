package core

type agreementTransport interface {
	RecvChan(id int) (<-chan Message, error)
	Send(msg Message) error
	Broadcast(from int, to []int, tag string, body []byte)
	Close() error
}

type Message struct {
	From      int
	To        int
	Tag       string
	Body      []byte
	WireBytes int
}
