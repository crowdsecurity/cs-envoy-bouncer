package main

import (
	"fmt"
	"net/netip"
	"os"
	"runtime/pprof"
	"time"

	"github.com/gofrs/uuid"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/properties"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

type vmContext struct {
	types.DefaultVMContext
}

type decisionDetails struct {
	remediation remediationType
	expiration  time.Time
}

type pluginContext struct {
	types.DefaultPluginContext
	pluginUUID       string
	vmID             string
	queueID          uint32
	queueName        string
	workerQueueNames []string
	workerQueueIDs   []uint32
	decisionsMap     map[netip.Addr]decisionDetails
}

type httpContext struct {
	types.DefaultHttpContext
	contextID uint32
}

const lastRefreshIntervalKey = "crowdsecLastRefreshInterval" // Last time interval at which the decisions stream was refreshed
const initialPullDoneKey = "crowdsecInitialPullDone"         // Was the initial pull done or not
const decisionsKey = "crowdsecDecisions"                     // Key under which the decisions are stored in shared data
const workerNamesQueue = "crowdsec_worker_names"             // Used by the worker to communicate the name of the decision queue they create

const refreshInterval = 10 * time.Second // FIXME: get this from the plugin configuration

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

	proxywasm.LogInfo("Starting WASM VM for crowdsec updater")

	// Set the initial value for the refreshing shared data
	proxywasm.LogTrace("Setting initial shared data for lastRefreshInterval")
	err := setUint64SharedData(lastRefreshIntervalKey, 0, 0)
	if err != nil {
		proxywasm.LogCriticalf("failed to set initial shared data: %v", err)
		return types.OnVMStartStatusFailed
	}

	err = setUint16SharedData(initialPullDoneKey, 0, 0)
	if err != nil {
		proxywasm.LogCriticalf("failed to set initial pull done shared data: %v", err)
		return types.OnVMStartStatusFailed
	}
	proxywasm.LogTrace("Initial shared data set successfully")

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
		return nil // Returning nil indicates that the plugin context could not be created
	}
	proxywasm.LogInfof("Plugin VM ID: %s", id)

	uuid, err := uuid.NewV4()
	if err != nil {
		proxywasm.LogCriticalf("failed to generate UUID: %v", err)
		return nil // Returning nil indicates that the plugin context could not be created
	}

	err = proxywasm.SetTickPeriodMilliSeconds(uint32(refreshInterval.Milliseconds())) // This can overflow for stupid high values
	if err != nil {
		proxywasm.LogCriticalf("failed to set tick period: %v", err)
		return nil // Returning nil indicates that the plugin context could not be created
	}
	return &pluginContext{pluginUUID: uuid.String(),
		vmID:             id,
		workerQueueNames: make([]string, 0),
		workerQueueIDs:   make([]uint32, 0),
		decisionsMap:     make(map[netip.Addr]decisionDetails),
	}
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
		proxywasm.LogInfo("no configuration provided")
		//return types.OnPluginStartStatusOK
	}

	_, err = proxywasm.RegisterSharedQueue(workerNamesQueue)
	if err != nil {
		proxywasm.LogCriticalf("failed to register shared queue: %v", err)
		return types.OnPluginStartStatusFailed
	}
	return types.OnPluginStartStatusOK
}

func (p *pluginContext) OnQueueReady(queueID uint32) {
	data, err := proxywasm.DequeueSharedQueue(queueID)
	if err != nil {
		proxywasm.LogCriticalf("failed to dequeue shared queue: %v", err)
		return
	}
	proxywasm.LogInfof("Received data from shared queue %d: %s", queueID, string(data))

	p.workerQueueNames = append(p.workerQueueNames, string(data))

	workerQueueID, err := proxywasm.ResolveSharedQueue("crowdsec_filter", string(data))
	if err != nil {
		proxywasm.LogCriticalf("failed to resolve shared queue for worker decisions: %v", err)
		return
	}
	p.workerQueueIDs = append(p.workerQueueIDs, workerQueueID)
	proxywasm.LogInfof("Adding worker queue %s to the list of worker queues", string(data))
}

func (p *pluginContext) broadcastDecision(ip netip.Addr, remediation remediationType, expiration time.Time) {
	// Here we can broadcast the decision to the worker queues
	for _, workerQueueID := range p.workerQueueIDs {
		// Create the decision message
		message := fmt.Sprintf(`{"ip": "%s", "remediation": "%s", "expiration": "%s"}`, ip.String(), remediation.String(), expiration.Format(time.RFC3339))
		err := proxywasm.EnqueueSharedQueue(workerQueueID, []byte(message))
		if err != nil {
			proxywasm.LogCriticalf("failed to enqueue shared queue %d: %v", workerQueueID, err)
			continue
		}
		proxywasm.LogTracef("Broadcasted decision to worker queue %d: %s", workerQueueID, message)
	}
}

func (p *pluginContext) dispatchCallback(numHeaders int, bodySize int, numTrailers int) {
	body, err := proxywasm.GetHttpCallResponseBody(0, bodySize)
	if err != nil {
		proxywasm.LogCriticalf("failed to get HTTP call response body: %s", err)
		return
	}
	proxywasm.LogInfof("Received HTTP call response with %d headers, body size %d, and %d trailers", numHeaders, bodySize, numTrailers)
	// Here we can process the response body and headers
	//proxywasm.LogInfof("HTTP call response body: %s", body)

	res := gjson.ParseBytes(body)

	newDecisions := res.Get("new")
	deletedDecisions := res.Get("deleted")

	/*queueId, err := proxywasm.ResolveSharedQueue(p.vmID, "crowdsec_decisions_queue")
	if err != nil {
		proxywasm.LogCriticalf("failed to resolve shared queue: %v", err)
		return
	}*/

	deletedCount := 0
	newCount := 0

	deletedDecisions.ForEach(func(_, decision gjson.Result) bool {
		/*err := proxywasm.EnqueueSharedQueue(queueId, []byte(decision.Raw))
		if err != nil {
			proxywasm.LogCriticalf("failed to enqueue shared queue: %v", err)
		}*/
		strIP := decision.Get("value")
		if !strIP.Exists() {
			return true
		}
		netipAddr, err := netip.ParseAddr(strIP.String())
		if err != nil {
			proxywasm.LogCriticalf("failed to parse IP address %s: %v", strIP.String(), err)
			return true // Continue processing other decisions
		}
		if _, exists := p.decisionsMap[netipAddr]; !exists {
			proxywasm.LogTracef("Decision for %s not found in map, skipping", netipAddr)
			return true // Continue processing other decisions
		}
		delete(p.decisionsMap, netipAddr)
		deletedCount++
		return true
	})

	newDecisions.ForEach(func(_, decision gjson.Result) bool {
		strIP := decision.Get("value")
		if !strIP.Exists() {
			return true
		}
		netipAddr, err := netip.ParseAddr(strIP.String())
		if err != nil {
			proxywasm.LogCriticalf("failed to parse IP address %s: %v", strIP.String(), err)
			return true // Continue processing other decisions
		}
		remediation := newRemediationType(decision.Get("remediation").String())
		expiration := decision.Get("expiration").Time()
		p.broadcastDecision(netipAddr, remediation, expiration)
		/*p.decisionsMap[netipAddr] = decisionDetails{
			remediation: remediation,
			expiration:  expiration,
		}*/
		newCount++
		return true
	})

	proxywasm.LogInfof("Received decisions stream response: %d deleted decisions", deletedCount)
	proxywasm.LogInfof("Received decisions stream response: %d new decisions", newCount)

	if newCount != 0 {
		dumpFile, err := os.Create("heap_profile.dump")

		if err != nil {
			proxywasm.LogCriticalf("failed to create heap profile dump file: %v", err)
			return
		}
		defer dumpFile.Close()

		err = pprof.WriteHeapProfile(dumpFile)

		if err != nil {
			proxywasm.LogCriticalf("failed to write heap profile: %v", err)
			return
		}
	}

	return
}

func (p *pluginContext) OnTick() {
	initialPullDone, casPullDone, err := getUint16SharedData(initialPullDoneKey)
	if err != nil {
		proxywasm.LogCriticalf("failed to get initial pull done shared data: %v", err)
		return
	}

	proxywasm.LogInfo("Refreshing stream")

	path := "/v1/decisions/stream"
	if initialPullDone == 0 {
		path = "/v1/decisions/stream?startup=true"
	}
	headers := [][2]string{
		{":method", "GET"},
		{":path", path},
		{"User-Agent", "cs-envoy-bouncer/0.1"},
		// FIXME: add configuration support for authority
		{":authority", "crowdsec:8080"}, // This *needs* to match the cluster definition in the Envoy config
		{"x-api-key", "thisisabouncerkey"},
	}
	_, err = proxywasm.DispatchHttpCall("crowdsec_cluster", headers, nil, nil, 6000, p.dispatchCallback)

	if err != nil {
		proxywasm.LogCriticalf("failed to dispatch HTTP call: %v", err)
	}

	if initialPullDone == 0 {
		// This is the first time we are pulling the stream, we need to set the initial pull done shared data
		err = setUint16SharedData(initialPullDoneKey, 1, casPullDone)
		if err != nil {
			proxywasm.LogCriticalf("failed to set initial pull done shared data: %v", err)
			return // We probably want to disable the plugin if we cannot write the shared data ?
		}
		proxywasm.LogTracef("Set shared data %s to 1", initialPullDoneKey)
	}
}
