package main

/*
 * tlsconn_test.go
 * Tests for tlsconn.go
 * By J. Stuart McMurray
 * Created 20221217
 * Last Modified 20221217
 */

import "testing"

func TestGetClientHelloInfo(t *testing.T) {
	chi, err := GetClientHelloInfo()
	if nil != err {
		t.Fatalf("GetClientHelloInfo: err:%s", err)
	}
	if nil == chi {
		t.Fatalf("GetClientHelloInfo: nil")
	}
}
