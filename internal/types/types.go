package types

// StreamState holds the state across the processing stream.
type StreamState struct {
	Headers map[string]string
	Path    string
	Method  string
}
