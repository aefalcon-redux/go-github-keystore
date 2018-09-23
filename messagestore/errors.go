package messagestore

import (
	"fmt"
)

type NoSuchResource string

func (e NoSuchResource) Error() string {
	return fmt.Sprintf("resource %s does not exist", string(e))
}

type GetResourceError struct {
	Name  string
	Cause error
}

func (e *GetResourceError) Error() string {
	return fmt.Sprintf("failed to get resource %s: %s", e.Name, e.Cause)
}

type PutResourceError struct {
	Name  string
	Cause error
}

func (e *PutResourceError) Error() string {
	return fmt.Sprintf("failed to put resource %s: %s", e.Name, e.Cause)
}

type DeleteResourceError struct {
	Name  string
	Cause error
}

func (e *DeleteResourceError) Error() string {
	return fmt.Sprintf("failed to delete resource %s: %s", e.Name, e.Cause)
}

type DecodeResourceError struct {
	Name  string
	Cause error
}

func (e *DecodeResourceError) Error() string {
	return fmt.Sprintf("failed to decode resource %s: %s", e.Name, e.Cause)
}

type EncodeResourceError struct {
	Name  string
	Cause error
}

func (e *EncodeResourceError) Error() string {
	return fmt.Sprintf("failed to encode resource %s: %s", e.Name, e.Cause)
}

type ReadResourceError struct {
	Name  string
	Cause error
}

func (e *ReadResourceError) Error() string {
	return fmt.Sprintf("failed to decode resource %s: %s", e.Name, e.Cause)
}
