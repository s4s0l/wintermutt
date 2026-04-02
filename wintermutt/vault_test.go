package main

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func TestClientCloseWithoutWatcher(t *testing.T) {
	c := &Client{}

	assert.NotPanics(t, func() {
		c.Close()
		c.Close()
	})
}

func TestClientCloseWaitsForRenewalGoroutine(t *testing.T) {
	c := &Client{}
	ctx, cancel := context.WithCancel(context.Background())
	c.renewCancel = cancel
	c.renewDone = make(chan struct{})

	go func() {
		<-ctx.Done()
		close(c.renewDone)
	}()

	finished := make(chan struct{})
	go func() {
		c.Close()
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return in time")
	}
}

func TestSleepWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.False(t, sleepWithContext(ctx, 100*time.Millisecond))

	assert.True(t, sleepWithContext(context.Background(), 10*time.Millisecond))
}

func TestLoginWithAppRoleInvalidRoleIDFails(t *testing.T) {
	_, err := loginWithAppRole(context.Background(), &api.Client{}, "", "x")
	assert.Error(t, err)
}
