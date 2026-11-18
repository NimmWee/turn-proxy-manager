package main

import "testing"

func TestRemovedNetworkLockOperationsCannotMutate(t *testing.T) {
	b := &broker{}
	for _, op := range []string{"network-lock-enable", "network-lock-disable"} {
		r := b.dispatch(request{V: 1, Op: op})
		if r.OK || r.Error != "UNKNOWN_OPERATION" {
			t.Fatal("removed lock command accepted")
		}
	}
}
