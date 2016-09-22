package manager

import (
	"testing"
	"flag"
	"fmt"
	"strings"
	"github.com/google/cadvisor/storage"
	"github.com/google/cadvisor/cache/memory"
	"github.com/golang/glog"
	"time"
	"github.com/google/cadvisor/utils/sysfs"
	"github.com/google/cadvisor/container"
	"crypto/tls"
	"net/http"
	"github.com/Sirupsen/logrus"
)

type metricSetValue struct {
	container.MetricSet
}

var (
	// Metrics to be ignored.
	// Tcp metrics are ignored by default.
	ignoreMetrics metricSetValue = metricSetValue{container.MetricSet{container.NetworkTcpUsageMetrics: struct{}{}}}

	// List of metrics that can be ignored.
	ignoreWhitelist = container.MetricSet{
		container.DiskUsageMetrics:       struct{}{},
		container.NetworkUsageMetrics:    struct{}{},
		container.NetworkTcpUsageMetrics: struct{}{},
	}
)

func TestGetContainerData(t *testing.T) {
	memoryStorage, err := NewMemoryStorage()
	if err != nil {
		t.Fatal(err)
	}
	sysFs, err := sysfs.NewRealSysFs()
	if err != nil {
		t.Fatal(err)
	}
	collectorHttpClient := createCollectorHttpClient("", "")
	containerManager, err := New(memoryStorage, sysFs, 60*time.Second, true, ignoreMetrics.MetricSet, &collectorHttpClient)
	minfo, err := containerManager.GetMachineInfo()
	if err != nil {
		t.Fatal(err)
	}
	logrus.Infof("%+v", minfo)
}

var (
	storageDriver   = flag.String("storage_driver", "", fmt.Sprintf("Storage `driver` to use. Data is always cached shortly in memory, this controls where data is pushed besides the local cache. Empty means none. Options are: <empty>, %s", strings.Join(storage.ListDrivers(), ", ")))
	storageDuration = flag.Duration("storage_duration", 2*time.Minute, "How long to keep data stored (Default: 2min).")
)

// NewMemoryStorage creates a memory storage with an optional backend storage option.
func NewMemoryStorage() (*memory.InMemoryCache, error) {
	backendStorage, err := storage.New(*storageDriver)
	if err != nil {
		return nil, err
	}
	if *storageDriver != "" {
		glog.Infof("Using backend storage type %q", *storageDriver)
	}
	glog.Infof("Caching stats in memory for %v", *storageDuration)
	return memory.New(*storageDuration, backendStorage), nil
}

func createCollectorHttpClient(collectorCert, collectorKey string) http.Client {
	//Enable accessing insecure endpoints. We should be able to access metrics from any endpoint
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	if collectorCert != "" {
		if collectorKey == "" {
			glog.Fatal("The collector_key value must be specified if the collector_cert value is set.")
		}
		cert, err := tls.LoadX509KeyPair(collectorCert, collectorKey)
		if err != nil {
			glog.Fatalf("Failed to use the collector certificate and key: %s", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.BuildNameToCertificate()
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return http.Client{Transport: transport}
}

