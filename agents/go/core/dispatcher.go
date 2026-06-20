package core

import (
	"fmt"
	"sync"
)

// Handler processes a command and returns structured output.
type Handler func(args map[string]interface{}) map[string]interface{}

// Dispatcher routes incoming commands to registered module handlers.
type Dispatcher struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		handlers: make(map[string]Handler),
	}
}

// Register adds a named command handler.
func (d *Dispatcher) Register(name string, h Handler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[name] = h
}

// RegisterAll adds multiple handlers at once.
func (d *Dispatcher) RegisterAll(handlers map[string]Handler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for name, h := range handlers {
		d.handlers[name] = h
	}
}

// Dispatch routes a command to its handler and returns the result.
func (d *Dispatcher) Dispatch(command string, args map[string]interface{}) map[string]interface{} {
	d.mu.RLock()
	h, ok := d.handlers[command]
	d.mu.RUnlock()

	if !ok {
		return map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("unknown command: %s", command),
		}
	}

	defer func() {
		if r := recover(); r != nil {
			// Swallow panics from handlers to keep the agent alive
		}
	}()

	result := h(args)
	if result == nil {
		result = make(map[string]interface{})
	}
	if _, ok := result["status"]; !ok {
		result["status"] = "success"
	}
	return result
}

// Commands returns a list of registered command names.
func (d *Dispatcher) Commands() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	names := make([]string, 0, len(d.handlers))
	for name := range d.handlers {
		names = append(names, name)
	}
	return names
}

// HasCommand checks if a command is registered.
func (d *Dispatcher) HasCommand(name string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.handlers[name]
	return ok
}
