package main

import (
	"encoding/binary"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
)

func setUint16SharedData(key string, value uint16, cas uint32) error {
	byteBuffer := make([]byte, 2)
	binary.LittleEndian.PutUint16(byteBuffer, value)
	return proxywasm.SetSharedData(key, byteBuffer, cas)
}

func setUint64SharedData(key string, value uint64, cas uint32) error {
	byteBuffer := make([]byte, 8)
	binary.LittleEndian.PutUint64(byteBuffer, value)
	return proxywasm.SetSharedData(key, byteBuffer, cas)
}

func getUint16SharedData(key string) (uint16, uint32, error) {
	val, cas, err := proxywasm.GetSharedData(key)
	if err != nil {
		return 0, 0, err
	}
	intValue := binary.LittleEndian.Uint16(val)
	proxywasm.LogTracef("Retrieved shared data %s: %d (cas: %d)", key, intValue, cas)
	return intValue, cas, nil
}

func getUint64SharedData(key string) (uint64, uint32, error) {
	val, cas, err := proxywasm.GetSharedData(key)
	if err != nil {
		return 0, 0, err
	}
	proxywasm.LogInfof("Retrieved shared data %s: %d (cas: %d)", key, val, cas)
	intValue := binary.LittleEndian.Uint64(val)
	proxywasm.LogTracef("Retrieved shared data %s: %d (cas: %d)", key, intValue, cas)
	return intValue, cas, nil
}
