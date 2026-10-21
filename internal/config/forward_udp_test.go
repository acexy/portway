package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func TestForwardUDPLimitsPreserveEveryWireField(t *testing.T) {
	// Distinct nonzero values expose dropped or swapped fields, including new limits.
	var wire protocol.ForwardUDPConfig
	fields := reflect.ValueOf(&wire).Elem()
	for index := range fields.NumField() {
		fields.Field(index).SetInt(int64(index + 1))
	}
	runtime := ForwardUDPConfigFromProtocol(wire)
	runtimeFields := reflect.ValueOf(runtime)
	if runtimeFields.NumField() != fields.NumField() {
		t.Fatal("runtime and wire UDP limits differ; review the field mapping")
	}
	for index := range fields.NumField() {
		name := fields.Type().Field(index).Name
		runtimeName := strings.ReplaceAll(name, "PerForward", "PerProxy")
		field := runtimeFields.FieldByName(runtimeName)
		if !field.IsValid() || field.Int() != fields.Field(index).Int() {
			t.Errorf("wire field %s was not preserved as %s", name, runtimeName)
		}
	}
	if restored := ForwardUDPProtocolConfig(runtime); *restored != wire {
		t.Fatalf("UDP limits changed after round trip: got %+v, want %+v", *restored, wire)
	}
}
