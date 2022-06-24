package topic

import (
	"strings"
	"sync"
)

type Topic struct {
	rwmutex sync.RWMutex
	node    *node
}

type node struct {
	value string
	leaf  bool

	next []*node
}

func New() *Topic {
	return &Topic{
		node: &node{
			value: "root",
		},
	}
}

func (t *Topic) Add(topicName, udid string) {
	t.rwmutex.Lock()
	defer t.rwmutex.Unlock()
	strs := strings.Split(topicName, "/")

	if len(t.node.next) == 0 {
		t.node.next = append(t.node.next, &node{
			value: strs[0],
			leaf:  false,
			next:  nil,
		})
	}

	if !t.node.leaf {
		t.node.leaf = true
	}
}

func (t *Topic) find(value string) {
}
