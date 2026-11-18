package main

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

func unsafeProcessEntrySize() uintptr { return unsafe.Sizeof(windows.ProcessEntry32{}) }
