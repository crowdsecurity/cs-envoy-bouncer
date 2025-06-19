package main

import (
	"fmt"

	"github.com/gofrs/uuid"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/properties"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

type vmContext struct {
	types.DefaultVMContext
}

type pluginContext struct {
	types.DefaultPluginContext
	contextID      uint32
	pluginUUID     string
	vmID           string
	queueID        uint32
	queueName      string
	queueReadCount int
}

type httpContext struct {
	types.DefaultHttpContext
	contextID uint32
}

const tickInterval = 2000 // In milliseconds

var hasSentName = false

type remediationType int

func (r remediationType) String() string {
	switch r {
	case RemediationTypeBan:
		return "ban"
	case RemediationTypeCaptcha:
		return "captcha"
	default:
		return "unknown"
	}
}

func newRemediationType(s string) remediationType {
	switch s {
	case "ban":
		return RemediationTypeBan
	case "captcha":
		return RemediationTypeCaptcha
	default:
		return -1 // Invalid remediation type
	}
}

const (
	RemediationTypeBan remediationType = iota
	RemediationTypeCaptcha
)

func main() {}

// Is intialization mandatory in init or can we do things in main?
func init() {
	// Probably not ideal for us given that:
	// We have a global state (the decisions or even captcha validation)
	// We probably need to access the plugin configuration (remediation type)
	// I don't know if the initial stream query is considered expansive or not
	// proxywasm.SetHttpContext()

	// We probably do no need to manage the full VM context, only handling the plugin context should be enough ?
	// This will give us access to the plugin configuration
	proxywasm.SetVMContext(&vmContext{})

	/*proxywasm.SetPluginContext(func(contextID uint32) types.PluginContext {
		return &pluginContext{}
	})*/
}

func (v *vmContext) OnVMStart(vmConfigurationSize int) types.OnVMStartStatus {
	// Set the initial value for the refreshing shared data
	//proxywasm.RegisterSharedQueue()

	return types.OnVMStartStatusOK
}

func (v *vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	// This is where we can create a new plugin context
	// and return it to the proxy
	// We can use this context to handle plugin-specific logic
	proxywasm.LogInfof("Creating new plugin context with ID %d", contextID)
	id, err := properties.GetPluginVmId()
	if err != nil {
		proxywasm.LogCriticalf("failed to get plugin VM ID: %v", err)
		return nil
	}
	proxywasm.LogInfof("Plugin VM ID: %s", id)

	uuid, err := uuid.NewV4()
	if err != nil {
		proxywasm.LogCriticalf("failed to generate UUID: %v", err)
		return nil
	}

	return &pluginContext{contextID: contextID, vmID: id, pluginUUID: uuid.String()}
}

func (p *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	// This is where we can read the plugin configuration

	proxywasm.LogInfo("loading plugin config")
	data, err := proxywasm.GetPluginConfiguration()

	if err != nil {
		proxywasm.LogCriticalf("failed to get plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	if data == nil {
		proxywasm.LogDebug("no configuration provided")
		//return types.OnPluginStartStatusOK
	}

	err = proxywasm.SetTickPeriodMilliSeconds(tickInterval)
	if err != nil {
		proxywasm.LogCriticalf("failed to set tick period: %v", err)
		return types.OnPluginStartStatusFailed
	}

	return types.OnPluginStartStatusOK
}

func (p *pluginContext) OnTick() {
	proxywasm.LogInfof("queue read count: %d", p.queueReadCount)
	if hasSentName {
		return
	}
	// Get the singleton queue to send the worker queue name
	queueID, err := proxywasm.ResolveSharedQueue("crowdsec_singleton", "crowdsec_worker_names")
	if err != nil {
		proxywasm.LogCriticalf("failed to resolve shared queue: %v", err)
		return
	}
	proxywasm.LogInfof("Resolved shared queue ID for worker names: %d", queueID)

	workerQueueName := fmt.Sprintf("crowdsec_decisions_queue_%s", p.pluginUUID)

	_, err = proxywasm.RegisterSharedQueue(workerQueueName)
	if err != nil {
		proxywasm.LogCriticalf("failed to register shared queue: %v", err)
		return
	}

	// Send our worker queue name to the singleton
	err = proxywasm.EnqueueSharedQueue(queueID, []byte(workerQueueName))
	if err != nil {
		proxywasm.LogCriticalf("failed to enqueue shared queue: %v", err)
		return
	}

	hasSentName = true
}

func (p *pluginContext) OnQueueReady(queueID uint32) {
	/*proxywasm.LogInfof("Shared queue %d is ready", p.queueID)
	proxywasm.LogInfof("received queueID: %d, expected queueID: %d", queueID, p.queueID)*/

	_, err := proxywasm.DequeueSharedQueue(queueID)
	if err != nil {
		proxywasm.LogCriticalf("failed to dequeue shared queue: %v", err)
		return
	}
	p.queueReadCount++

	//proxywasm.ResolveSharedQueue()
}

func (p *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	// This is where we can create a new HTTP context
	// and return it to the proxy
	// We can use this context to handle HTTP requests and responses

	// For example, we can create a new HTTP context that handles the request
	proxywasm.LogInfof("Creating new HTTP context with ID %d", contextID)
	return &httpContext{contextID: contextID}
}

func (h *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// Earliest point we can be called for an HTTP request
	// This is where we will check if the IP is allowed or not
	// No need to access anything, just drop the request if needed

	// Endofstream seems to indicate if the request was fully received or not ?
	// If so, we need to call the WAF when it is true, no matter the handler
	proxywasm.LogInfof("Received %d HTTP request headers | endOfStream: %v", numHeaders, endOfStream)

	// Return Continue to indicate that we want to continue processing the request
	return types.ActionContinue
}

func (h *httpContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	// This is where we can handle the HTTP request body
	// We can use this to perform additional checks or processing on the request body
	proxywasm.LogInfof("Received HTTP request body of size %d | endOfStream: %v", bodySize, endOfStream)
	return types.ActionContinue
}

func (h *httpContext) OnHttpStreamDone() {
	// This is called when the HTTP stream is done
	// We can use this to perform any cleanup or final processing
	proxywasm.LogInfof("HTTP stream with ID %d is done", h.contextID)
}
