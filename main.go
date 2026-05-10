package main

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	_ "modernc.org/sqlite"
)

const (
	isoFormatStandard        = "2006-01-02T15:04:05+00:00"
	maxBodySize              = 10 << 20
	defaultAPITimeout        = 10
	defaultWorkerTaskTimeout = 60
	defaultPort              = 10199
	defaultMaxLinks          = 20
	defaultWorkers           = 50
	maxAPITimeout            = 60
	maxWorkerTaskTimeout     = 300
	maxLinksLimit            = 100
	maxWorkersLimit          = 100
	defaultPansouAPIURL      = "https://so.252035.xyz"
	defaultPGCloudTypes      = "aliyun,quark,tianyi,uc,mobile,115,pikpak,xunlei,123,magnet"
	defaultZXCloudTypes      = "baidu,aliyun,quark,tianyi,uc,mobile,115,123"
	defaultPGImageProxy      = "direct"
	defaultZXImageProxy      = "proxy"
	defaultCheckWorkers      = 200
	maxCheckWorkers          = 500
	maxReadSize              = 500 * 1024
	RecentRequestCapacity    = 100000
	defaultCacheCapacity     = 1000
	linkCacheTTL             = 24 * time.Hour
	linkCacheCleanupInterval = 1 * time.Hour
	maxDBConnections         = 25
	maxDBIdleConnections     = 10
)

var (
	geoIPSingleFlight     singleflight.Group
	linkCheckSingleFlight singleflight.Group

	spaceCleanupRegexp = regexp.MustCompile(`\s+`)
	titleRegex         = regexp.MustCompile(`<title[^>]*>(.*?)</title>`)
	aliyunPatterns     = regexp.MustCompile(`(?:aliyundrive|alipan)\.com/s/([A-Za-z0-9]+)`)
	quarkPatterns      = regexp.MustCompile(`(?:quark\.cn|quark\.com|pan\.quark\.cn)/s/([A-Za-z0-9]+)`)
	ucPattern          = regexp.MustCompile(`drive\.uc\.cn/s/([A-Za-z0-9]+)`)

	fileSizeRegexes = map[string]*regexp.Regexp{
		"baidu":   regexp.MustCompile(`文件大小.*?([\d.]+)\s*([KMGTP]B)`),
		"aliyun":  regexp.MustCompile(`大小.*?([\d.]+)\s*([KMGTP]?B)`),
		"quark":   regexp.MustCompile(`大小.*?([\d.]+)\s*([KMGTP]?B)`),
		"115":     regexp.MustCompile(`大小.*?([\d.]+)\s*([KMGTP]?B)`),
		"default": regexp.MustCompile(`([\d.]+)\s*([KMGTP]?B)`),
	}

	timeFormats = []string{
		time.RFC3339,
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05+00:00",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	domains123Pan = []string{
		"123684.com", "123685.com", "123912.com",
		"123pan.com", "123pan.cn", "123592.com",
	}

	validCloudTypes = map[string]bool{
		"aliyun": true, "quark": true, "tianyi": true, "uc": true,
		"mobile": true, "115": true, "pikpak": true, "xunlei": true,
		"123": true, "magnet": true, "baidu": true,
	}

	validProxyModes = map[string]bool{
		"proxy":  true,
		"direct": true,
		"none":   true,
	}

	titleReplacer = strings.NewReplacer(
		"#", "【#】",
		"\\( ", "【 \\)】",
		"@", "【@】",
	)

	exactWhitelist = map[string]struct{}{
		"/":                                 {},
		"/api/search":                       {},
		"/config":                           {},
		"/s":                                {},
		"/stats":                            {},
		"/health":                           {},
		"/robots.txt":                       {},
		"/favicon.ico":                      {},
		"/apple-touch-icon.png":             {},
		"/apple-touch-icon-precomposed.png": {},
		"/apple-touch-icon-120x120.png":     {},
		"/apple-touch-icon-120x120-precomposed.png": {},
	}

	prefixWhitelist = []string{
		"/i/",
		"/api/proxy/",
		"/api/config/",
		"/api/stats/",
		"/api/geoip/",
		"/api/blacklist/",
		"/api/loadbalancer/",
		"/assets/",
	}

	StandardTimeRanges = map[string]time.Duration{
		"all": 0,
		"1h":  time.Hour,
		"6h":  6 * time.Hour,
		"12h": 12 * time.Hour,
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"30d": 30 * 24 * time.Hour,
	}

	cloudTypeMapping = map[string]string{
		"baidu":  "baidu",
		"aliyun": "aliyun",
		"quark":  "quark",
		"tianyi": "tianyi",
		"uc":     "uc",
		"mobile": "mobile",
		"115":    "115",
		"pikpak": "pikpak",
		"xunlei": "xunlei",
		"123":    "123",
		"magnet": "magnet",
	}

	cloudCheckConfigs = map[string]*CloudCheckConfig{
		"aliyun": {
			Name:   "阿里云盘",
			APIURL: "https://api.aliyundrive.com/adrive/v3/share_link/get_share_by_anonymous",
			Method: "POST",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			CheckFunc: func(response string) (bool, string, string) {
				var data map[string]interface{}
				if err := json.Unmarshal([]byte(response), &data); err != nil {
					return false, "API响应解析失败", ""
				}
				if code, exists := data["code"]; exists {
					if codeStr, ok := code.(string); ok && strings.Contains(codeStr, "ShareLink") {
						return false, "分享链接异常", ""
					}
				}
				if fileCount, exists := data["file_count"]; exists {
					if count, ok := fileCount.(float64); ok && count == 0 {
						return false, "文件数量为0", ""
					}
				}
				return true, "阿里云盘分享", ""
			},
		},
		"quark": {
			Name:   "夸克网盘",
			APIURL: "https://drive-h.quark.cn/1/clouddrive/share/sharepage/token?pr=ucpro&fr=pc",
			Method: "POST",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			CheckFunc: func(response string) (bool, string, string) {
				var data map[string]interface{}
				if err := json.Unmarshal([]byte(response), &data); err != nil {
					return false, "API响应解析失败", ""
				}
				if message, exists := data["message"]; exists {
					if msg, ok := message.(string); ok {
						if strings.Contains(msg, "需要提取码") {
							return false, "需要提取码", ""
						}
						if strings.Contains(msg, "ok") {
							return true, "夸克网盘分享", ""
						}
					}
				}
				return false, "分享不存在", ""
			},
		},
		"uc": {
			Name: "UC网盘",
			CheckFunc: func(response string) (bool, string, string) {
				if strings.Contains(response, "文件不存在") || strings.Contains(response, "文件已删除") ||
					strings.Contains(response, "分享不存在") {
					return false, "文件不存在", ""
				}
				if strings.Contains(response, "需要密码") || strings.Contains(response, "输入密码") {
					return false, "需要密码", ""
				}
				return true, "UC网盘分享", ""
			},
		},
	}

	globalTransport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		MaxConnsPerHost:     100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	bufferPool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, 4096))
		},
	}

	byteBufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, maxReadSize)
			return &b
		},
	}

	platformMapping = map[string]string{
		"aliyun": "aliyun",
		"quark":  "quark",
		"uc":     "uc",
		"115":    "pan115",
		"baidu":  "baidu",
		"tianyi": "tianyi",
		"123":    "pan123",
		"xunlei": "xunlei",
		"mobile": "cmcc",
	}

	newAPISupportedTypes = map[string]bool{
		"aliyun": true,
		"quark":  true,
		"uc":     true,
		"115":    true,
		"baidu":  true,
		"tianyi": true,
		"123":    true,
		"xunlei": true,
		"mobile": true,
	}

	legacyCheckTypes = map[string]bool{
		"aliyun": true,
		"quark":  true,
		"uc":     true,
	}

	newAPIClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	globalLinkCheckPool *LinkCheckWorkerPool
)

//go:embed templates/*
var templateFS embed.FS

type PasswordProtectionManager struct {
	mu              sync.RWMutex
	attempts        map[string]int
	lastSeen        map[string]time.Time
	permanentBlocks map[string]bool
	logger          *Logger
}

func NewPasswordProtectionManager(logger *Logger) *PasswordProtectionManager {
	ppm := &PasswordProtectionManager{
		attempts:        make(map[string]int),
		lastSeen:        make(map[string]time.Time),
		permanentBlocks: make(map[string]bool),
		logger:          logger,
	}
	go ppm.cleanupRoutine()
	return ppm
}

func (ppm *PasswordProtectionManager) RecordAttempt(ip string) bool {
	ppm.mu.Lock()
	defer ppm.mu.Unlock()

	ppm.attempts[ip]++
	ppm.lastSeen[ip] = time.Now()
	attempts := ppm.attempts[ip]

	if attempts >= 10 {
		ppm.permanentBlocks[ip] = true
		ppm.logger.Warn("IP %s 因密码尝试次数过多被永久封禁", ip)
		return true
	}
	return false
}

func (ppm *PasswordProtectionManager) IsPermanentlyBlocked(ip string) bool {
	ppm.mu.RLock()
	defer ppm.mu.RUnlock()
	return ppm.permanentBlocks[ip]
}

func (ppm *PasswordProtectionManager) GetAttempts(ip string) int {
	ppm.mu.RLock()
	defer ppm.mu.RUnlock()
	return ppm.attempts[ip]
}

func (ppm *PasswordProtectionManager) ResetAttempts(ip string) {
	ppm.mu.Lock()
	defer ppm.mu.Unlock()
	delete(ppm.attempts, ip)
	delete(ppm.lastSeen, ip)
	delete(ppm.permanentBlocks, ip)
}

func (ppm *PasswordProtectionManager) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		ppm.mu.Lock()
		now := time.Now()
		for ip, t := range ppm.lastSeen {
			if now.Sub(t) > 24*time.Hour {
				delete(ppm.attempts, ip)
				delete(ppm.lastSeen, ip)
			}
		}
		ppm.mu.Unlock()
	}
}

type RequestLogEntry struct {
	Timestamp  time.Time     `json:"timestamp"`
	Method     string        `json:"method"`
	Path       string        `json:"path"`
	StatusCode int           `json:"statusCode"`
	Latency    time.Duration `json:"latency"`
	IP         string        `json:"ip"`
	Region     string        `json:"region"`
	City       string        `json:"city"`
	UserAgent  string        `json:"userAgent"`
	SearchTerm string        `json:"searchTerm"`
}

type SafeRingBuffer[T any] struct {
	buffer []T
	head   int
	tail   int
	size   int
	mutex  sync.RWMutex
}

func NewSafeRingBuffer[T any](capacity int) *SafeRingBuffer[T] {
	return &SafeRingBuffer[T]{
		buffer: make([]T, capacity),
		size:   capacity,
	}
}

func (rb *SafeRingBuffer[T]) Push(item T) {
	rb.mutex.Lock()
	defer rb.mutex.Unlock()
	rb.buffer[rb.head] = item
	rb.head = (rb.head + 1) % rb.size
	if rb.head == rb.tail {
		rb.tail = (rb.tail + 1) % rb.size
	}
}

func (rb *SafeRingBuffer[T]) GetAll() []T {
	rb.mutex.RLock()
	defer rb.mutex.RUnlock()
	if rb.head == rb.tail {
		return []T{}
	}
	result := make([]T, 0, rb.Len())
	for i := rb.tail; i != rb.head; i = (i + 1) % rb.size {
		result = append(result, rb.buffer[i])
	}
	return result
}

func (rb *SafeRingBuffer[T]) Len() int {
	rb.mutex.RLock()
	defer rb.mutex.RUnlock()
	if rb.head == rb.tail {
		return 0
	}
	if rb.head > rb.tail {
		return rb.head - rb.tail
	}
	return rb.size - rb.tail + rb.head
}

type AtomicCounter struct {
	value atomic.Int64
}

func (c *AtomicCounter) Increment() int64 {
	return c.value.Add(1)
}

func (c *AtomicCounter) Get() int64 {
	return c.value.Load()
}

func (c *AtomicCounter) Set(value int64) {
	c.value.Store(value)
}

type MetricBucket struct {
	TotalRequests atomic.Uint64
	TotalLatency  atomic.Int64
	StatusCodes   sync.Map
}

func (b *MetricBucket) Reset() {
	b.TotalRequests.Store(0)
	b.TotalLatency.Store(0)
	b.StatusCodes.Range(func(key, value interface{}) bool {
		b.StatusCodes.Delete(key)
		return true
	})
}

func NewMetricBucket() *MetricBucket {
	return &MetricBucket{}
}

func (b *MetricBucket) Record(statusCode int, latency time.Duration) {
	b.TotalRequests.Add(1)
	b.TotalLatency.Add(int64(latency))

	counter, _ := b.StatusCodes.LoadOrStore(statusCode, new(atomic.Int32))
	counter.(*atomic.Int32).Add(1)
}

func (b *MetricBucket) Merge(other *MetricBucket) {
	if other == nil {
		return
	}

	b.TotalRequests.Add(other.TotalRequests.Load())
	b.TotalLatency.Add(other.TotalLatency.Load())

	other.StatusCodes.Range(func(key, value interface{}) bool {
		code := key.(int)
		count := value.(*atomic.Int32).Load()
		if count > 0 {
			counter, _ := b.StatusCodes.LoadOrStore(code, new(atomic.Int32))
			counter.(*atomic.Int32).Add(count)
		}
		return true
	})
}

type ConcurrentCounter struct {
	counters sync.Map
}

func NewConcurrentCounter() *ConcurrentCounter {
	return &ConcurrentCounter{}
}

func (cc *ConcurrentCounter) Increment(key string) int64 {
	counter, _ := cc.counters.LoadOrStore(key, new(atomic.Int64))
	return counter.(*atomic.Int64).Add(1)
}

func (cc *ConcurrentCounter) Get(key string) int64 {
	if counter, ok := cc.counters.Load(key); ok {
		return counter.(*atomic.Int64).Load()
	}
	return 0
}

type kvItem struct {
	Key   string
	Count int64
}

func (cc *ConcurrentCounter) GetTopN(n int) []map[string]interface{} {
	var items []kvItem
	cc.counters.Range(func(key, value interface{}) bool {
		items = append(items, kvItem{key.(string), value.(*atomic.Int64).Load()})
		return true
	})

	if len(items) > n {
		quickSelectGeneric(items, 0, len(items)-1, n, func(a, b kvItem) bool {
			return a.Count >= b.Count
		})
		items = items[:n]
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})

	result := make([]map[string]interface{}, len(items))
	for i, item := range items {
		result[i] = map[string]interface{}{
			"name":  item.Key,
			"count": item.Count,
		}
	}
	return result
}

func quickSelectGeneric[T any](items []T, left, right, k int, less func(a, b T) bool) {
	if left >= right {
		return
	}
	pivotIndex := partitionGeneric(items, left, right, less)
	if pivotIndex == k {
		return
	} else if pivotIndex < k {
		quickSelectGeneric(items, pivotIndex+1, right, k, less)
	} else {
		quickSelectGeneric(items, left, pivotIndex-1, k, less)
	}
}

func partitionGeneric[T any](items []T, left, right int, less func(a, b T) bool) int {
	pivot := right
	i := left - 1
	for j := left; j < right; j++ {
		if less(items[j], items[pivot]) {
			i++
			items[i], items[j] = items[j], items[i]
		}
	}
	items[i+1], items[right] = items[right], items[i+1]
	return i + 1
}

type MetricsManager struct {
	recentRequests   *SafeRingBuffer[RequestLogEntry]
	startTime        time.Time
	minuteBuckets    [1440]*MetricBucket
	hourlyBuckets    [720]*MetricBucket
	dailyBuckets     [365]*MetricBucket
	currentMinuteIdx int32
	currentHourIdx   int32
	currentDayIdx    int32
	currentBucket    atomic.Value
	pathStats        *ConcurrentCounter
	regionStats      *ConcurrentCounter
	cityStats        *ConcurrentCounter
	userAgentStats   *ConcurrentCounter
	searchTermStats  *ConcurrentCounter
	requestLogChan   chan RequestLogEntry
	closeChan        chan struct{}
	mu               sync.RWMutex
}

func NewMetricsManager() *MetricsManager {
	mm := &MetricsManager{
		recentRequests:  NewSafeRingBuffer[RequestLogEntry](RecentRequestCapacity),
		startTime:       time.Now(),
		pathStats:       NewConcurrentCounter(),
		regionStats:     NewConcurrentCounter(),
		cityStats:       NewConcurrentCounter(),
		userAgentStats:  NewConcurrentCounter(),
		searchTermStats: NewConcurrentCounter(),
		requestLogChan:  make(chan RequestLogEntry, 10000),
		closeChan:       make(chan struct{}),
	}
	for i := range mm.minuteBuckets {
		mm.minuteBuckets[i] = NewMetricBucket()
	}
	for i := range mm.hourlyBuckets {
		mm.hourlyBuckets[i] = NewMetricBucket()
	}
	for i := range mm.dailyBuckets {
		mm.dailyBuckets[i] = NewMetricBucket()
	}
	mm.currentBucket.Store(mm.minuteBuckets[0])
	mm.currentMinuteIdx = 0
	mm.currentHourIdx = 0
	mm.currentDayIdx = 0
	go mm.processMetricsWorker()
	return mm
}

func (mm *MetricsManager) Close() {
	close(mm.closeChan)
}

func (mm *MetricsManager) RecordRequest(entry RequestLogEntry) {
	select {
	case mm.requestLogChan <- entry:
	default:
	}
}

func getStartTime(rangeKey string, startTime time.Time) time.Time {
	now := time.Now()
	switch rangeKey {
	case "all":
		return startTime
	case "1h":
		return now.Add(-1 * time.Hour)
	case "6h":
		return now.Add(-6 * time.Hour)
	case "12h":
		return now.Add(-12 * time.Hour)
	case "24h":
		return now.Add(-24 * time.Hour)
	case "7d":
		return now.Add(-7 * 24 * time.Hour)
	case "30d":
		return now.Add(-30 * 24 * time.Hour)
	default:
		return now.Add(-1 * time.Hour)
	}
}

func getDurationSeconds(rangeKey string) float64 {
	switch rangeKey {
	case "all":
		return time.Since(time.Now().Add(-365 * 24 * time.Hour)).Seconds()
	case "1h":
		return 3600
	case "6h":
		return 6 * 3600
	case "12h":
		return 12 * 3600
	case "24h":
		return 24 * 3600
	case "7d":
		return 7 * 24 * 3600
	case "30d":
		return 30 * 24 * 3600
	default:
		return 3600
	}
}

type TimeRangeStatsResult struct {
	TotalRequests    uint64                   `json:"totalRequests"`
	QPS              float64                  `json:"qps"`
	AvgResponseTime  float64                  `json:"avgResponseTime"`
	Uptime           string                   `json:"uptime"`
	StatusCodeCounts map[string]int           `json:"statusCodeCounts"`
	SuccessRate      float64                  `json:"successRate"`
	SearchTermTopN   []map[string]interface{} `json:"searchTermTopN"`
	RegionTopN       []map[string]interface{} `json:"regionTopN"`
	CityTopN         []map[string]interface{} `json:"cityTopN"`
	UserAgentTopN    []map[string]interface{} `json:"userAgentTopN"`
	RecentRequests   []RequestLogEntry        `json:"recentRequests"`
}

func (mm *MetricsManager) aggregateBucketsFromList(buckets []*MetricBucket, rangeKey string) *TimeRangeStatsResult {
	result := &TimeRangeStatsResult{
		StatusCodeCounts: make(map[string]int),
	}
	var totalLatencyNs int64
	var totalRequests uint64
	for _, bucket := range buckets {
		if bucket == nil {
			continue
		}
		totalRequests += bucket.TotalRequests.Load()
		totalLatencyNs += bucket.TotalLatency.Load()
		bucket.StatusCodes.Range(func(key, value interface{}) bool {
			code := key.(int)
			count := value.(*atomic.Int32).Load()
			if count > 0 {
				result.StatusCodeCounts[strconv.Itoa(code)] += int(count)
			}
			return true
		})
	}
	result.TotalRequests = totalRequests
	if totalRequests > 0 {
		result.AvgResponseTime = float64(totalLatencyNs) / float64(totalRequests) / 1e6
	}
	uptime := time.Since(mm.startTime)
	baseDuration := getDurationSeconds(rangeKey)
	actualDuration := uptime.Seconds()
	if rangeKey == "all" || uptime.Seconds() < baseDuration {
		result.QPS = float64(totalRequests) / math.Max(actualDuration, 1.0)
	} else {
		result.QPS = float64(totalRequests) / math.Max(baseDuration, 1.0)
	}
	successfulRequests := 0
	for code, count := range result.StatusCodeCounts {
		if c, _ := strconv.Atoi(code); c >= 200 && c < 300 {
			successfulRequests += count
		}
	}
	if totalRequests > 0 {
		result.SuccessRate = float64(successfulRequests) / float64(totalRequests) * 100
	}
	recentLogs := mm.recentRequests.GetAll()
	var filteredLogs []RequestLogEntry
	tempSearchTermStats := make(map[string]int)
	tempRegionStats := make(map[string]int)
	tempCityStats := make(map[string]int)
	tempUserAgentStats := make(map[string]int)
	startTime := getStartTime(rangeKey, mm.startTime)
	for _, entry := range recentLogs {
		if entry.Timestamp.After(startTime) {
			filteredLogs = append(filteredLogs, entry)
			if entry.Region != "" && entry.Region != "未知" {
				tempRegionStats[entry.Region]++
			}
			if entry.City != "" && entry.City != "未知" {
				tempCityStats[entry.City]++
			}
			if entry.UserAgent != "" {
				ua := entry.UserAgent
				if len(ua) > 100 {
					ua = ua[:100] + "..."
				}
				tempUserAgentStats[ua]++
			}
			if entry.SearchTerm != "" {
				tempSearchTermStats[entry.SearchTerm]++
			}
		}
	}
	result.SearchTermTopN = mm.getTopNFromMap(tempSearchTermStats, 10)
	result.RegionTopN = mm.getTopNFromMap(tempRegionStats, 10)
	result.CityTopN = mm.getTopNFromMap(tempCityStats, 10)
	result.UserAgentTopN = mm.getTopNFromMap(tempUserAgentStats, 10)
	result.RecentRequests = filteredLogs
	if len(result.RecentRequests) > 0 {
		sort.Slice(result.RecentRequests, func(i, j int) bool {
			return result.RecentRequests[i].Timestamp.After(result.RecentRequests[j].Timestamp)
		})
	}
	result.Uptime = formatDuration(uptime)
	return result
}

func (mm *MetricsManager) processMetricsWorker() {
	minuteTicker := time.NewTicker(time.Minute)
	hourTicker := time.NewTicker(time.Hour)
	dayTicker := time.NewTicker(24 * time.Hour)
	defer minuteTicker.Stop()
	defer hourTicker.Stop()
	defer dayTicker.Stop()
	for {
		select {
		case entry := <-mm.requestLogChan:
			mm.recentRequests.Push(entry)
			bucket := mm.currentBucket.Load().(*MetricBucket)
			bucket.Record(entry.StatusCode, entry.Latency)
			pathKey := entry.Method + " " + entry.Path
			mm.pathStats.Increment(pathKey)
			if entry.Region != "" && entry.Region != "未知" {
				mm.regionStats.Increment(entry.Region)
			}
			if entry.City != "" && entry.City != "未知" {
				mm.cityStats.Increment(entry.City)
			}
			if entry.UserAgent != "" {
				ua := entry.UserAgent
				if len(ua) > 100 {
					ua = ua[:100] + "..."
				}
				mm.userAgentStats.Increment(ua)
			}
			if entry.SearchTerm != "" {
				mm.searchTermStats.Increment(entry.SearchTerm)
			}
		case <-minuteTicker.C:
			mm.mu.Lock()
			newIdx := (mm.currentMinuteIdx + 1) % int32(len(mm.minuteBuckets))
			mm.currentMinuteIdx = newIdx
			mm.currentBucket.Store(mm.minuteBuckets[newIdx])
			mm.mu.Unlock()
		case <-hourTicker.C:
			mm.aggregateMinutesToHours()
		case <-dayTicker.C:
			mm.aggregateHoursToDays()
		case <-mm.closeChan:
			return
		}
	}
}

func (mm *MetricsManager) aggregateMinutesToHours() {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	newHourIdx := (mm.currentHourIdx + 1) % int32(len(mm.hourlyBuckets))
	mm.hourlyBuckets[newHourIdx].Reset()
	for i := 0; i < 60; i++ {
		minuteIdx := (mm.currentMinuteIdx - int32(i)) % int32(len(mm.minuteBuckets))
		if minuteIdx < 0 {
			minuteIdx += int32(len(mm.minuteBuckets))
		}
		mm.hourlyBuckets[newHourIdx].Merge(mm.minuteBuckets[minuteIdx])
	}
	mm.currentHourIdx = newHourIdx
}

func (mm *MetricsManager) aggregateHoursToDays() {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	newDayIdx := (mm.currentDayIdx + 1) % int32(len(mm.dailyBuckets))
	mm.dailyBuckets[newDayIdx].Reset()
	for i := 0; i < 24; i++ {
		hourIdx := (mm.currentHourIdx - int32(i)) % int32(len(mm.hourlyBuckets))
		if hourIdx < 0 {
			hourIdx += int32(len(mm.hourlyBuckets))
		}
		mm.dailyBuckets[newDayIdx].Merge(mm.hourlyBuckets[hourIdx])
	}
	mm.currentDayIdx = newDayIdx
}

func (mm *MetricsManager) getLastBuckets(buckets []*MetricBucket, currentIdx int32, n int) []*MetricBucket {
	length := len(buckets)
	if n > length {
		n = length
	}
	result := make([]*MetricBucket, n)
	for i := 0; i < n; i++ {
		idx := (int(currentIdx) - i + length) % length
		result[i] = buckets[idx]
	}
	return result
}

func (mm *MetricsManager) getLastMinuteBuckets(n int) []*MetricBucket {
	return mm.getLastBuckets(mm.minuteBuckets[:], mm.currentMinuteIdx, n)
}

func (mm *MetricsManager) getLastHourlyBuckets(n int) []*MetricBucket {
	return mm.getLastBuckets(mm.hourlyBuckets[:], mm.currentHourIdx, n)
}

func (mm *MetricsManager) getLastDailyBuckets(n int) []*MetricBucket {
	return mm.getLastBuckets(mm.dailyBuckets[:], mm.currentDayIdx, n)
}

func (mm *MetricsManager) GetAggregatedStats(rangeKey string) *TimeRangeStatsResult {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	var buckets []*MetricBucket
	switch rangeKey {
	case "all":
		buckets = mm.collectAllNonEmptyBuckets()
	case "1h":
		buckets = mm.getLastMinuteBuckets(60)
	case "6h":
		buckets = mm.getLastHourlyBuckets(6)
	case "12h":
		buckets = mm.getLastHourlyBuckets(12)
	case "24h":
		buckets = mm.getLastHourlyBuckets(24)
	case "7d":
		buckets = mm.getLastDailyBuckets(7)
	case "30d":
		buckets = mm.getLastDailyBuckets(30)
	default:
		buckets = mm.getLastMinuteBuckets(60)
	}
	return mm.aggregateBucketsFromList(buckets, rangeKey)
}

func (mm *MetricsManager) collectAllNonEmptyBuckets() []*MetricBucket {
	var all []*MetricBucket
	for _, b := range mm.dailyBuckets {
		if b != nil && b.TotalRequests.Load() > 0 {
			all = append(all, b)
		}
	}
	for _, b := range mm.hourlyBuckets {
		if b != nil && b.TotalRequests.Load() > 0 {
			all = append(all, b)
		}
	}
	for _, b := range mm.minuteBuckets {
		if b != nil && b.TotalRequests.Load() > 0 {
			all = append(all, b)
		}
	}
	return all
}

func (mm *MetricsManager) GetMultipleTimeRangeStats(timeRanges map[string]time.Duration) map[string]*TimeRangeStatsResult {
	results := make(map[string]*TimeRangeStatsResult)
	for name, duration := range timeRanges {
		rangeKey := durationToRangeKey(duration)
		results[name] = mm.GetAggregatedStats(rangeKey)
	}
	return results
}

func durationToRangeKey(duration time.Duration) string {
	switch duration {
	case 0:
		return "all"
	case time.Hour:
		return "1h"
	case 6 * time.Hour:
		return "6h"
	case 12 * time.Hour:
		return "12h"
	case 24 * time.Hour:
		return "24h"
	case 7 * 24 * time.Hour:
		return "7d"
	case 30 * 24 * time.Hour:
		return "30d"
	default:
		return "1h"
	}
}

type kv struct {
	Key   string
	Value int
}

func (mm *MetricsManager) getTopNFromMap(m map[string]int, n int) []map[string]interface{} {
	if len(m) == 0 {
		return []map[string]interface{}{}
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	if len(items) > n {
		quickSelectGeneric(items, 0, len(items)-1, n, func(a, b kv) bool {
			return a.Value >= b.Value
		})
		items = items[:n]
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Value > items[j].Value
	})
	result := make([]map[string]interface{}, len(items))
	for i, item := range items {
		result[i] = map[string]interface{}{
			"name":  item.Key,
			"count": item.Value,
		}
	}
	return result
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	days := d / (24 * time.Hour)
	d %= (24 * time.Hour)
	hours := d / time.Hour
	d %= time.Hour
	minutes := d / time.Minute
	if days > 0 {
		return fmt.Sprintf("%d天 %d时 %d分", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%d时 %d分", hours, minutes)
	}
	return fmt.Sprintf("%d分", minutes)
}

type geoIPCacheEntry struct {
	region    string
	city      string
	timestamp time.Time
}

type OnlineIPInfo struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	RegionName  string  `json:"region_name"`
	City        string  `json:"city"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Latitude    float64 `json:"lat"`
	Longitude   float64 `json:"lon"`
	CountryName string  `json:"country_name"`
}

type ServiceStats struct {
	TotalRequests int
	SuccessCount  int
	ErrorCount    int
	LastSuccess   time.Time
	LastError     time.Time
	AvgResponse   time.Duration
}

type GeoIPService struct {
	logger           *Logger
	cache            sync.Map
	httpClient       *http.Client
	countryCodeMap   map[string]string
	chineseProvinces map[string]bool
	serviceStats     sync.Map
	maxmindDB        *geoip2.Reader
	maxmindMutex     sync.RWMutex
	dbPath           string
}

func (g *GeoIPService) getServicePriority() []struct {
	name    string
	handler func(context.Context, string) (string, string, string)
	timeout time.Duration
} {
	return []struct {
		name    string
		handler func(context.Context, string) (string, string, string)
		timeout time.Duration
	}{
		{"ip-api.com", g.queryIPAPICom, 4 * time.Second},
		{"db-ip.com", g.queryDBIP, 4 * time.Second},
	}
}

func (g *GeoIPService) recordServiceStats(serviceName string, success bool, duration time.Duration) {
	statsInterface, _ := g.serviceStats.LoadOrStore(serviceName, &ServiceStats{})
	stats := statsInterface.(*ServiceStats)
	stats.TotalRequests++
	if success {
		stats.SuccessCount++
		stats.LastSuccess = time.Now()
		if stats.AvgResponse == 0 {
			stats.AvgResponse = duration
		} else {
			stats.AvgResponse = (stats.AvgResponse + duration) / 2
		}
	} else {
		stats.ErrorCount++
		stats.LastError = time.Now()
	}
}

func (g *GeoIPService) initCountryCodeMap() {
	g.countryCodeMap = map[string]string{
		"CN": "中国", "HK": "香港", "MO": "澳门", "TW": "台湾",
		"US": "美国", "JP": "日本", "KR": "韩国", "SG": "新加坡",
		"GB": "英国", "DE": "德国", "FR": "法国", "CA": "加拿大",
		"AU": "澳大利亚", "RU": "俄罗斯", "IN": "印度", "BR": "巴西",
		"ID": "印度尼西亚", "MY": "马来西亚", "TH": "泰国", "VN": "越南",
		"PH": "菲律宾", "MM": "缅甸", "KH": "柬埔寨", "LA": "老挝",
		"BD": "孟加拉国", "NP": "尼泊尔", "LK": "斯里兰卡", "PK": "巴基斯坦",
		"TR": "土耳其", "IR": "伊朗", "IQ": "伊拉克", "SA": "沙特阿拉伯",
		"IL": "以色列", "AE": "阿联酋", "QA": "卡塔尔", "KW": "科威特",
		"EG": "埃及", "ZA": "南非", "NG": "尼日利亚", "KE": "肯尼亚",
		"MA": "摩洛哥", "DZ": "阿尔及利亚", "TN": "突尼斯", "LY": "利比亚",
		"IT": "意大利", "ES": "西班牙", "PT": "葡萄牙", "NL": "荷兰",
		"BE": "比利时", "CH": "瑞士", "SE": "瑞典", "NO": "挪威",
		"DK": "丹麦", "FI": "芬兰", "IE": "爱尔兰", "AT": "奥地利",
		"PL": "波兰", "CZ": "捷克", "HU": "匈牙利", "GR": "希腊",
		"UA": "乌克兰", "RO": "罗马尼亚", "BG": "保加利亚", "HR": "克罗地亚",
		"RS": "塞尔维亚", "SI": "斯洛文尼亚", "SK": "斯洛伐克", "BY": "白俄罗斯",
		"MD": "摩尔多瓦", "AZ": "阿塞拜疆", "GE": "格鲁吉亚", "AM": "亚美尼亚",
		"KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦", "TM": "土库曼斯坦", "KG": "吉尔吉斯斯坦",
		"TJ": "塔吉克斯坦", "MN": "蒙古", "KP": "朝鲜",
		"MX": "墨西哥", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
		"PE": "秘鲁", "VE": "委内瑞拉", "EC": "厄瓜多尔", "PA": "巴拿马",
		"CU": "古巴", "CR": "哥斯达黎加", "NZ": "新西兰", "FJ": "斐济",
		"PG": "巴布亚新几内亚", "MU": "毛里求斯", "SC": "塞舌尔",
	}
	g.chineseProvinces = map[string]bool{
		"北京": true, "天津": true, "上海": true, "重庆": true,
		"河北": true, "山西": true, "辽宁": true, "吉林": true,
		"黑龙江": true, "江苏": true, "浙江": true, "安徽": true,
		"福建": true, "江西": true, "山东": true, "河南": true,
		"湖北": true, "湖南": true, "广东": true, "海南": true,
		"四川": true, "贵州": true, "云南": true, "陕西": true,
		"甘肃": true, "青海": true, "台湾": true, "内蒙古": true,
		"广西": true, "西藏": true, "宁夏": true, "新疆": true,
		"香港": true, "澳门": true,
	}
}

func (g *GeoIPService) normalizeRegion(rawRegion, countryCode string) string {
	if countryCode == "CN" {
		m := map[string]string{
			"Beijing": "北京", "Tianjin": "天津", "Shanghai": "上海", "Chongqing": "重庆",
			"Hebei": "河北", "Shanxi": "山西", "Liaoning": "辽宁", "Jilin": "吉林",
			"Heilongjiang": "黑龙江", "Jiangsu": "江苏", "Zhejiang": "浙江", "Anhui": "安徽",
			"Fujian": "福建", "Jiangxi": "江西", "Shandong": "山东", "Henan": "河南",
			"Hubei": "湖北", "Hunan": "湖南", "Guangdong": "广东", "Hainan": "海南",
			"Sichuan": "四川", "Guizhou": "贵州", "Yunnan": "云南", "Shaanxi": "陕西",
			"Gansu": "甘肃", "Qinghai": "青海", "Taiwan": "台湾", "Inner Mongolia": "内蒙古",
			"Guangxi": "广西", "Tibet": "西藏", "Ningxia": "宁夏", "Xinjiang": "新疆",
			"Hong Kong": "香港", "Macau": "澳门", "Macao": "澳门",
			"Beijing Municipality": "北京", "Shanghai Municipality": "上海",
			"Tianjin Municipality": "天津", "Chongqing Municipality": "重庆",
		}
		if v, ok := m[rawRegion]; ok {
			return v
		}
		if rawRegion != "" {
			return rawRegion
		}
		return "中国"
	}
	if countryName, ok := g.countryCodeMap[countryCode]; ok {
		return countryName
	}
	return "未知国家"
}

func (g *GeoIPService) normalizeCity(rawCity, rawRegion, countryCode string) string {
	if countryCode == "CN" {
		if rawCity == "" || rawCity == "未知" {
			return "未知"
		}
		return rawCity
	}
	if rawCity != "" && rawCity != "未知" {
		return rawCity
	}
	if rawRegion != "" && rawRegion != "未知" {
		return rawRegion
	}
	return "未知"
}

func NewGeoIPService(logger *Logger) *GeoIPService {
	dbPath := os.Getenv("GEOIP_DB_PATH")
	if dbPath == "" {
		dbPath = "GeoLite2-City.mmdb"
	}
	service := &GeoIPService{
		logger: logger,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: globalTransport,
		},
		dbPath: dbPath,
	}
	service.initCountryCodeMap()
	if err := service.loadMaxMindDB(); err != nil {
		logger.Warn("MaxMind数据库加载失败，将使用在线查询: %v", err)
	} else {
		logger.Info("MaxMind数据库加载成功: %s", dbPath)
	}
	go service.cleanupCache()
	logger.Info("GeoIP 服务初始化完成（MaxMind本地数据库 + 在线查询兜底）")
	return service
}

func (g *GeoIPService) loadMaxMindDB() error {
	g.maxmindMutex.Lock()
	defer g.maxmindMutex.Unlock()
	if g.maxmindDB != nil {
		g.maxmindDB.Close()
		g.maxmindDB = nil
	}
	if _, err := os.Stat(g.dbPath); os.IsNotExist(err) {
		return fmt.Errorf("数据库文件不存在: %s", g.dbPath)
	}
	db, err := geoip2.Open(g.dbPath)
	if err != nil {
		return fmt.Errorf("打开数据库失败: %v", err)
	}
	g.maxmindDB = db
	return nil
}

func (g *GeoIPService) updateMaxMindDB() error {
	g.logger.Info("开始更新MaxMind GeoLite2数据库...")

	downloadSources := []string{
		"https://git.io/GeoLite2-City.mmdb",
		"https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
	}

	tmpPath := "GeoLite2-City.mmdb.tmp"
	var lastErr error

	for _, downloadURL := range downloadSources {
		g.logger.Info("尝试从 %s 下载数据库...", downloadURL)

		downloadClient := &http.Client{
			Timeout: 300 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   60 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          10,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   30 * time.Second,
				ExpectContinueTimeout: 5 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		}

		req, err := http.NewRequest("GET", downloadURL, nil)
		if err != nil {
			lastErr = fmt.Errorf("创建HTTP请求失败: %v", err)
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
		req.Header.Set("Connection", "keep-alive")

		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
		defer cancel()
		req = req.WithContext(ctx)

		resp, err := downloadClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("下载失败: %v", err)
			g.logger.Warn("从 %s 下载失败: %v", downloadURL, err)
			time.Sleep(2 * time.Second)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP状态码 %d", resp.StatusCode)
			g.logger.Warn("从 %s 下载失败，状态码: %d", downloadURL, resp.StatusCode)
			continue
		}

		contentLength := resp.Header.Get("Content-Length")
		if contentLength != "" {
			fileSize, _ := strconv.ParseInt(contentLength, 10, 64)
			if fileSize < 1024*1024 {
				lastErr = fmt.Errorf("文件大小异常: %d bytes", fileSize)
				g.logger.Warn("从 %s 下载的文件大小异常: %d bytes", downloadURL, fileSize)
				continue
			}
			g.logger.Info("下载文件大小: %d MB", fileSize/(1024*1024))
		}

		tmpFile, err := os.Create(tmpPath)
		if err != nil {
			lastErr = fmt.Errorf("创建临时文件失败: %v", err)
			continue
		}
		defer tmpFile.Close()

		buf := make([]byte, 32*1024)
		var downloaded int64
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		go func() {
			for range ticker.C {
				if downloaded > 0 {
					g.logger.Info("下载进度: %d KB", downloaded/1024)
				}
			}
		}()

		reader := io.LimitReader(resp.Body, 200*1024*1024)
		downloaded, err = io.CopyBuffer(tmpFile, reader, buf)
		if err != nil {
			lastErr = fmt.Errorf("保存数据库文件失败: %v", err)
			tmpFile.Close()
			os.Remove(tmpPath)
			continue
		}

		if err := tmpFile.Sync(); err != nil {
			lastErr = fmt.Errorf("同步文件失败: %v", err)
			continue
		}
		tmpFile.Close()

		if fi, err := os.Stat(tmpPath); err != nil || fi.Size() < 10*1024*1024 {
			lastErr = fmt.Errorf("下载的文件大小不足")
			os.Remove(tmpPath)
			continue
		}

		g.logger.Info("测试下载的数据库文件...")
		if err := g.testDatabaseFile(tmpPath); err != nil {
			lastErr = fmt.Errorf("数据库文件测试失败: %v", err)
			os.Remove(tmpPath)
			continue
		}

		g.logger.Info("数据库文件验证成功，大小: %d MB", downloaded/(1024*1024))

		if _, err := os.Stat(g.dbPath); err == nil {
			backupPath := g.dbPath + ".bak"
			if err := os.Rename(g.dbPath, backupPath); err != nil {
				g.logger.Warn("备份原数据库文件失败: %v", err)
			} else {
				g.logger.Info("已备份原数据库文件到 %s", backupPath)
			}
		}

		if err := os.Rename(tmpPath, g.dbPath); err != nil {
			if _, err := os.Stat(g.dbPath + ".bak"); err == nil {
				os.Rename(g.dbPath+".bak", g.dbPath)
			}
			lastErr = fmt.Errorf("替换数据库文件失败: %v", err)
			continue
		}

		if err := g.loadMaxMindDB(); err != nil {
			if _, err := os.Stat(g.dbPath + ".bak"); err == nil {
				os.Rename(g.dbPath+".bak", g.dbPath)
				g.loadMaxMindDB()
			}
			lastErr = fmt.Errorf("重新加载数据库失败: %v", err)
			continue
		}

		if _, err := os.Stat(g.dbPath + ".bak"); err == nil {
			os.Remove(g.dbPath + ".bak")
		}

		g.logger.Info("MaxMind GeoLite2数据库更新成功！")
		return nil
	}

	return fmt.Errorf("所有下载源都失败，最后一个错误: %v", lastErr)
}

func (g *GeoIPService) testDatabaseFile(filePath string) error {
	db, err := geoip2.Open(filePath)
	if err != nil {
		return err
	}
	defer db.Close()

	testIPs := []string{"8.8.8.8", "114.114.114.114", "1.1.1.1"}
	for _, ip := range testIPs {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}
		_, err := db.City(parsedIP)
		if err != nil {
			return fmt.Errorf("测试查询IP %s 失败: %v", ip, err)
		}
	}
	return nil
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 10 {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4[0] == 127 {
			return true
		}
	}
	if ip.To16() != nil && ip.To4() == nil {
		if ip.IsLoopback() {
			return true
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		if len(ip) >= 2 && (ip[0] == 0xfc || ip[0] == 0xfd) {
			return true
		}
		if len(ip) >= 2 && ip[0] == 0xfe && (ip[1]&0xc0) == 0xc0 {
			return true
		}
	}
	return false
}

func (g *GeoIPService) LookupGeoIP(ipStr string) (region, city string) {
	if ipStr == "" || ipStr == "127.0.0.1" || ipStr == "::1" || ipStr == "localhost" {
		return "本地", "本地"
	}
	if isPrivateIP(ipStr) {
		g.logger.Debug("检测到局域网IP: %s", ipStr)
		return "局域网", "内部网络"
	}
	if entry := g.getFromCache(ipStr); entry != nil {
		return entry.region, entry.city
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	v, _, _ := geoIPSingleFlight.Do(ipStr, func() (interface{}, error) {
		r, c, _ := g.lookupGeoIPOptimized(ctx, ipStr)
		if r != "未知" && c != "未知" {
			g.saveToCache(ipStr, r, c)
		}
		return struct{ R, C string }{r, c}, nil
	})
	ret := v.(struct{ R, C string })
	return ret.R, ret.C
}

func (g *GeoIPService) lookupGeoIPOptimized(ctx context.Context, ipStr string) (region, city, countryCode string) {
	localRegion, localCity, localCountryCode := g.queryMaxMindLocal(ipStr)
	onlineRegion, onlineCity, onlineCountryCode := g.lookupGeoIPOnlineConcurrent(ctx, ipStr)
	return g.mergeGeoIPResults(ipStr, localRegion, localCity, localCountryCode,
		onlineRegion, onlineCity, onlineCountryCode)
}

func (g *GeoIPService) mergeGeoIPResults(ipStr string,
	localRegion, localCity, localCountryCode string,
	onlineRegion, onlineCity, onlineCountryCode string) (region, city, countryCode string) {
	switch localCountryCode {
	case "HK":
		return "香港", "香港", "HK"
	case "MO":
		return "澳门", "澳门", "MO"
	case "TW":
		return "台湾", "台北", "TW"
	}
	switch onlineCountryCode {
	case "HK":
		return "香港", "香港", "HK"
	case "MO":
		return "澳门", "澳门", "MO"
	case "TW":
		return "台湾", "台北", "TW"
	}
	if localCountryCode != "" && localCountryCode != "未知" {
		countryCode = localCountryCode
		if (localRegion != "" && localRegion != "未知") || (localCity != "" && localCity != "未知") {
			region = localRegion
			city = localCity
			if countryCode == "CN" {
				region = g.normalizeChineseRegion(region)
				if city == "" || city == "未知" {
					city = region
				}
			} else {
				countryName := g.countryCodeMap[countryCode]
				if countryName == "" {
					countryName = "未知国家"
				}
				region = countryName
				if city == "" || city == "未知" {
					city = countryName
				}
			}
			g.logger.Debug("本地有有效地区/城市，直接使用本地数据: %s → %s/%s (%s)",
				ipStr, region, city, countryCode)
			return region, city, countryCode
		}
		if onlineCountryCode == localCountryCode {
			region = onlineRegion
			city = onlineCity
			if countryCode == "CN" {
				region = g.normalizeChineseRegion(region)
				if city == "" || city == "未知" {
					city = region
				}
			} else {
				countryName := g.countryCodeMap[countryCode]
				if countryName == "" {
					countryName = "未知国家"
				}
				region = countryName
				if city == "" || city == "未知" {
					city = countryName
				}
			}
			g.logger.Debug("本地缺城市，在线国家一致，补充在线数据: %s → %s/%s (%s)",
				ipStr, region, city, countryCode)
			return region, city, countryCode
		} else {
			if countryCode == "CN" {
				region = "中国"
				city = "未知"
			} else {
				countryName := g.countryCodeMap[countryCode]
				if countryName == "" {
					countryName = "未知国家"
				}
				region = countryName
				city = countryName
			}
			g.logger.Debug("本地缺城市，在线国家不一致，兜底显示: %s → %s/%s (%s)",
				ipStr, region, city, countryCode)
			return region, city, countryCode
		}
	}
	if onlineCountryCode != "" && onlineCountryCode != "未知" {
		countryCode = onlineCountryCode
		if countryCode == "CN" {
			region = g.normalizeChineseRegion(onlineRegion)
			city = onlineCity
			if city == "" || city == "未知" {
				city = region
			}
		} else {
			countryName := g.countryCodeMap[countryCode]
			if countryName == "" {
				countryName = "未知国家"
			}
			region = countryName
			city = onlineCity
			if city == "" || city == "未知" {
				city = countryName
			}
		}
		g.logger.Debug("本地无国家，使用在线兜底: %s → %s/%s (%s)",
			ipStr, region, city, countryCode)
		return region, city, countryCode
	}
	g.logger.Debug("本地与在线均无有效数据: %s", ipStr)
	return "未知", "未知", ""
}

func (g *GeoIPService) normalizeChineseRegion(region string) string {
	if region == "" {
		return "中国"
	}
	provinceMap := map[string]string{
		"北京": "北京", "北京市": "北京", "Beijing": "北京",
		"天津": "天津", "天津市": "天津", "Tianjin": "天津",
		"上海": "上海", "上海市": "上海", "Shanghai": "上海",
		"重庆": "重庆", "重庆市": "重庆", "Chongqing": "重庆",
		"河北": "河北", "河北省": "河北", "Hebei": "河北",
		"山西": "山西", "山西省": "山西", "Shanxi": "山西",
		"辽宁": "辽宁", "辽宁省": "辽宁", "Liaoning": "辽宁",
		"吉林": "吉林", "吉林省": "吉林", "Jilin": "吉林",
		"黑龙江": "黑龙江", "黑龙江省": "黑龙江", "Heilongjiang": "黑龙江",
		"江苏": "江苏", "江苏省": "江苏", "Jiangsu": "江苏",
		"浙江": "浙江", "浙江省": "浙江", "Zhejiang": "浙江",
		"安徽": "安徽", "安徽省": "安徽", "Anhui": "安徽",
		"福建": "福建", "福建省": "福建", "Fujian": "福建",
		"江西": "江西", "江西省": "江西", "Jiangxi": "江西",
		"山东": "山东", "山东省": "山东", "Shandong": "山东",
		"河南": "河南", "河南省": "河南", "Henan": "河南",
		"湖北": "湖北", "湖北省": "湖北", "Hubei": "湖北",
		"湖南": "湖南", "湖南省": "湖南", "Hunan": "湖南",
		"广东": "广东", "广东省": "广东", "Guangdong": "广东",
		"海南": "海南", "海南省": "海南", "Hainan": "海南",
		"四川": "四川", "四川省": "四川", "Sichuan": "四川",
		"贵州": "贵州", "贵州省": "贵州", "Guizhou": "贵州",
		"云南": "云南", "云南省": "云南", "Yunnan": "云南",
		"陕西": "陕西", "陕西省": "陕西", "Shaanxi": "陕西",
		"甘肃": "甘肃", "甘肃省": "甘肃", "Gansu": "甘肃",
		"青海": "青海", "青海省": "青海", "Qinghai": "青海",
		"台湾": "台湾", "台湾省": "台湾", "Taiwan": "台湾",
		"内蒙古": "内蒙古", "内蒙古自治区": "内蒙古", "Inner Mongolia": "内蒙古",
		"广西": "广西", "广西壮族自治区": "广西", "Guangxi": "广西",
		"西藏": "西藏", "西藏自治区": "西藏", "Tibet": "西藏",
		"宁夏": "宁夏", "宁夏回族自治区": "宁夏", "Ningxia": "宁夏",
		"新疆": "新疆", "新疆维吾尔自治区": "新疆", "Xinjiang": "新疆",
		"香港": "香港", "香港特别行政区": "香港", "Hong Kong": "香港",
		"澳门": "澳门", "澳门特别行政区": "澳门", "Macau": "澳门", "Macao": "澳门",
	}
	if normalized, exists := provinceMap[region]; exists {
		return normalized
	}
	return region
}

func (g *GeoIPService) queryMaxMindLocal(ipStr string) (region, city, countryCode string) {
	g.maxmindMutex.RLock()
	defer g.maxmindMutex.RUnlock()
	if g.maxmindDB == nil {
		g.logger.Debug("MaxMind数据库未加载")
		return "未知", "未知", ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		g.logger.Debug("无效的IP地址: %s", ipStr)
		return "未知", "未知", ""
	}
	record, err := g.maxmindDB.City(ip)
	if err != nil {
		g.logger.Debug("MaxMind本地查询失败: IP=%s, 错误=%v", ipStr, err)
		return "未知", "未知", ""
	}
	countryCode = record.Country.IsoCode
	if countryCode == "" {
		countryCode = "未知"
	}
	region = "未知"
	if len(record.Subdivisions) > 0 {
		region = record.Subdivisions[0].Names["zh-CN"]
		if region == "" {
			region = record.Subdivisions[0].Names["en"]
		}
		if region == "" {
			region = "未知"
		}
	}
	city = record.City.Names["zh-CN"]
	if city == "" {
		city = record.City.Names["en"]
	}
	if city == "" {
		city = "未知"
	}
	normalizedRegion := g.normalizeRegion(region, countryCode)
	normalizedCity := g.normalizeCity(city, region, countryCode)
	return normalizedRegion, normalizedCity, countryCode
}

func (g *GeoIPService) lookupGeoIPOnlineConcurrent(ctx context.Context, ipStr string) (region, city, countryCode string) {
	services := g.getServicePriority()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	resultChan := make(chan struct {
		region      string
		city        string
		countryCode string
		serviceName string
	}, len(services))
	for _, service := range services {
		go func(svc struct {
			name    string
			handler func(context.Context, string) (string, string, string)
			timeout time.Duration
		}) {
			svcCtx, cancel := context.WithTimeout(ctx, svc.timeout)
			r, c, cc := svc.handler(svcCtx, ipStr)
			cancel()
			select {
			case resultChan <- struct {
				region      string
				city        string
				countryCode string
				serviceName string
			}{r, c, cc, svc.name}:
			case <-ctx.Done():
				return
			}
		}(service)
	}
	for i := 0; i < len(services); i++ {
		select {
		case result := <-resultChan:
			if result.region != "未知" || result.city != "未知" {
				g.logger.Debug("在线GeoIP命中 (%s): %s → %s/%s",
					result.serviceName, ipStr, result.region, result.city)
				return result.region, result.city, result.countryCode
			}
		case <-ctx.Done():
			g.logger.Debug("在线GeoIP查询超时: %s", ipStr)
			return "未知", "未知", ""
		}
	}
	return "未知", "未知", ""
}

func (g *GeoIPService) queryIPAPICom(ctx context.Context, ipStr string) (region, city, countryCode string) {
	region = "未知"
	city = "未知"
	countryCode = ""
	req, err := http.NewRequestWithContext(ctx, "GET", "http://demo.ip-api.com/json/"+ipStr+"?fields=66842623&lang=zh-CN", nil)
	if err != nil {
		g.logger.Debug("ip-api.com 创建请求失败: %v", err)
		return
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		g.logger.Debug("ip-api.com 请求失败: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		g.logger.Debug("ip-api.com 返回非200状态码: %d", resp.StatusCode)
		return
	}
	var info struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		g.logger.Debug("ip-api.com 解析失败: %v", err)
		return
	}
	if info.Status != "success" {
		g.logger.Debug("ip-api.com 返回失败状态: %s", info.Status)
		return
	}
	countryCode = strings.ToUpper(info.CountryCode)
	region = info.RegionName
	city = info.City
	if region == "" {
		region = "未知"
	}
	if city == "" {
		city = "未知"
	}
	return
}

func (g *GeoIPService) queryDBIP(ctx context.Context, ipStr string) (region, city, countryCode string) {
	region = "未知"
	city = "未知"
	countryCode = ""
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.db-ip.com/v2/free/"+ipStr, nil)
	if err != nil {
		g.logger.Debug("db-ip.com 创建请求失败: %v", err)
		return
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		g.logger.Debug("db-ip.com 请求失败: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		g.logger.Debug("db-ip.com 返回非200状态码: %d", resp.StatusCode)
		return
	}
	var info struct {
		CountryCode string `json:"countryCode"`
		CountryName string `json:"countryName"`
		StateProv   string `json:"stateProv"`
		City        string `json:"city"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		g.logger.Debug("db-ip.com 解析失败: %v", err)
		return
	}
	countryCode = strings.ToUpper(info.CountryCode)
	region = info.StateProv
	city = info.City
	if region == "" {
		region = "未知"
	}
	if city == "" {
		city = "未知"
	}
	return
}

func (g *GeoIPService) getFromCache(ipStr string) *geoIPCacheEntry {
	if entry, exists := g.cache.Load(ipStr); exists {
		cacheEntry := entry.(*geoIPCacheEntry)
		if time.Since(cacheEntry.timestamp) > 30*time.Minute {
			g.cache.Delete(ipStr)
			return nil
		}
		return cacheEntry
	}
	return nil
}

func (g *GeoIPService) saveToCache(ipStr, region, city string) {
	g.cache.Store(ipStr, &geoIPCacheEntry{
		region:    region,
		city:      city,
		timestamp: time.Now(),
	})
}

func (g *GeoIPService) cleanupCache() {
	ticker := time.NewTicker(2 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		g.cache.Range(func(key, value interface{}) bool {
			entry := value.(*geoIPCacheEntry)
			if time.Since(entry.timestamp) > 2*time.Hour {
				g.cache.Delete(key)
			}
			return true
		})
	}
}

func (g *GeoIPService) Close() {
	if g.httpClient != nil {
		g.httpClient.CloseIdleConnections()
	}
	if g.maxmindDB != nil {
		g.maxmindDB.Close()
	}
}

type ResponseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func NewResponseWriterWrapper(w http.ResponseWriter) *ResponseWriterWrapper {
	return &ResponseWriterWrapper{w, http.StatusOK}
}

func (rw *ResponseWriterWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *ResponseWriterWrapper) StatusCode() int {
	return rw.statusCode
}

func normalizePath(requestPath string) string {
	cleanPath := path.Clean(requestPath)
	if cleanPath == "." || cleanPath == "/" {
		return "/"
	}
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	return cleanPath
}

type WhitelistDecision struct {
	Path          string
	Scene         string
	IsWhitelisted bool
	MatchType     string
	Rule          string
}

func detectRequestScene(pathLower string) string {
	switch {
	case pathLower == "/api/search" || strings.HasPrefix(pathLower, "/api/search/"):
		return "zx"
	case pathLower == "/s" || strings.HasPrefix(pathLower, "/s/"):
		return "pg"
	default:
		return "generic"
	}
}

func evaluateWhitelist(requestPath string) WhitelistDecision {
	normalizedPath := normalizePath(requestPath)
	pathLower := strings.ToLower(normalizedPath)
	decision := WhitelistDecision{
		Path:  normalizedPath,
		Scene: detectRequestScene(pathLower),
	}
	if _, ok := exactWhitelist[pathLower]; ok {
		decision.IsWhitelisted = true
		decision.MatchType = "exact"
		decision.Rule = pathLower
		return decision
	}
	for _, prefix := range prefixWhitelist {
		if strings.HasPrefix(pathLower, prefix) {
			decision.IsWhitelisted = true
			decision.MatchType = "prefix"
			decision.Rule = prefix
			return decision
		}
	}
	return decision
}

type Application struct {
	configManager             *ConfigManager
	workerPool                atomic.Value
	authMiddleware            *AuthMiddleware
	linkCheckManager          *LinkCheckTaskManager
	loadBalancer              *LoadBalancer
	logger                    *Logger
	metricsManager            *MetricsManager
	blacklistManager          *BlacklistManager
	geoipService              *GeoIPService
	passwordProtectionManager *PasswordProtectionManager
	pgMessageTmpl             *template.Template
	configTmpl                *template.Template
	statsTmpl                 *template.Template
	pansouClient              *http.Client
	db                        *sql.DB
}

func (app *Application) MonitoringMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		clientIP := getClientIP(r)
		whitelistDecision := evaluateWhitelist(r.URL.Path)
		requestPath := whitelistDecision.Path
		if app.blacklistManager.IsBlocked("ip", clientIP) && !strings.HasPrefix(requestPath, "/api/blacklist/unblock") {
			app.logger.Warn("拒绝黑名单IP访问: IP=%s, 路径=%s", clientIP, requestPath)
			http.Error(w, "拒绝访问", http.StatusForbidden)
			return
		}
		userAgent := r.Header.Get("User-Agent")
		if userAgent != "" && app.blacklistManager.IsBlocked("user_agent", userAgent) {
			app.logger.Warn("拒绝黑名单User-Agent访问: UA=%s, IP=%s", userAgent, clientIP)
			http.Error(w, "拒绝访问", http.StatusForbidden)
			return
		}
		region, city := app.geoipService.LookupGeoIP(clientIP)
		if region != "" && region != "未知" && app.blacklistManager.IsBlocked("region", region) {
			app.logger.Warn("拒绝黑名单地区访问: 地区=%s, IP=%s", region, clientIP)
			http.Error(w, "拒绝访问", http.StatusForbidden)
			return
		}
		if city != "" && city != "未知" && app.blacklistManager.IsBlocked("city", city) {
			app.logger.Warn("拒绝黑名单城市访问: 城市=%s, IP=%s", city, clientIP)
			http.Error(w, "拒绝访问", http.StatusForbidden)
			return
		}
		if requestPath == "/" && app.passwordProtectionManager.IsPermanentlyBlocked(clientIP) {
			app.logger.Warn("拒绝被密码保护永久封禁的IP访问: IP=%s", clientIP)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>访问被拒绝</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #d32f2f; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 访问被拒绝</h1>
        <p>您的IP地址 %s 因多次尝试错误密码已被永久封禁。</p>
        <p>如果您认为这是个错误，请联系网站管理员。</p>
    </div>
</body>
</html>`, clientIP)
			return
		}
		if whitelistDecision.IsWhitelisted {
			if app.logger.ShouldLog(DebugLevel) {
				app.logger.Debug("路径命中白名单: scene=%s, match=%s, rule=%s, path=%s",
					whitelistDecision.Scene, whitelistDecision.MatchType, whitelistDecision.Rule, requestPath)
			}
		} else {
			cfg := app.configManager.GetConfig()
			app.logger.Warn("检测到非白名单路径访问: scene=%s, auto_block=%v, ip=%s, 路径=%s",
				whitelistDecision.Scene, cfg.AutoBlockIP, clientIP, requestPath)
			if cfg.AutoBlockIP {
				app.blacklistManager.Block(clientIP, "ip", 0, "访问非白名单路径: "+requestPath)
				app.logger.Info("已自动封禁IP: scene=%s, ip=%s, 原因=访问非白名单路径 %s",
					whitelistDecision.Scene, clientIP, requestPath)
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			} else {
				app.logger.Warn("自动封禁IP功能已禁用，仅记录警告: scene=%s, ip=%s, 路径=%s",
					whitelistDecision.Scene, clientIP, requestPath)
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
		}
		lrw := NewResponseWriterWrapper(w)
		next.ServeHTTP(lrw, r)
		duration := time.Since(start)
		statusCode := lrw.StatusCode()
		searchTerm := r.Header.Get("X-Search-Term")
		logEntry := RequestLogEntry{
			Timestamp:  start,
			Method:     r.Method,
			Path:       requestPath,
			StatusCode: statusCode,
			Latency:    duration,
			IP:         clientIP,
			Region:     region,
			City:       city,
			UserAgent:  userAgent,
			SearchTerm: searchTerm,
		}
		app.metricsManager.RecordRequest(logEntry)
		if app.logger.ShouldLog(InfoLevel) {
			latencyMs := float64(duration.Microseconds()) / 1000.0
			app.logger.Info("请求完成: %s %s %d %.2fms %s %s/%s",
				r.Method, requestPath, statusCode, latencyMs, clientIP, region, city)
		}
	})
}

type BlacklistEntry struct {
	Value     string    `json:"value"`
	Type      string    `json:"type"`
	Expiry    time.Time `json:"expiry"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

type BlockRequest struct {
	Value    string `json:"value"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Reason   string `json:"reason,omitempty"`
}

type BlacklistManager struct {
	mu      sync.RWMutex
	entries sync.Map
	db      *sql.DB
	logger  *Logger
}

func NewBlacklistManager(db *sql.DB, logger *Logger) *BlacklistManager {
	bm := &BlacklistManager{
		db:     db,
		logger: logger,
	}
	bm.loadFromDB()
	go bm.cleanupExpiredRoutine()
	return bm
}

func (bm *BlacklistManager) loadFromDB() {
	rows, err := bm.db.Query(`
SELECT value, type, reason, expires_at, created_at
FROM blacklist
WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP
`)
	if err != nil {
		bm.logger.Error("加载黑名单失败", err)
		return
	}
	defer rows.Close()
	now := time.Now()
	count := 0
	batchSize := 1000
	batchCount := 0
	for rows.Next() {
		var entry BlacklistEntry
		var expiresAt sql.NullTime
		if err := rows.Scan(&entry.Value, &entry.Type, &entry.Reason, &expiresAt, &entry.CreatedAt); err != nil {
			bm.logger.Error("扫描黑名单行失败", err)
			continue
		}
		if expiresAt.Valid {
			entry.Expiry = expiresAt.Time
			if entry.Expiry.Before(now) {
				continue
			}
		}
		key := bm.generateKey(entry.Type, entry.Value)
		bm.entries.Store(key, &entry)
		count++
		batchCount++
		if batchCount >= batchSize {
			bm.logger.Debug("已批量加载 %d 条黑名单", batchCount)
			batchCount = 0
		}
	}
	bm.logger.Info("从DB加载 %d 条黑名单", count)
}

func (bm *BlacklistManager) generateKey(blType, value string) string {
	return fmt.Sprintf("%s:%s", blType, value)
}

func (bm *BlacklistManager) IsBlocked(checkType, value string) bool {
	key := bm.generateKey(checkType, value)
	entryInterface, exists := bm.entries.Load(key)
	if !exists {
		return false
	}
	entry := entryInterface.(*BlacklistEntry)
	if !entry.Expiry.IsZero() && time.Now().After(entry.Expiry) {
		return false
	}
	return true
}

func (bm *BlacklistManager) Block(value string, blType string, duration time.Duration, reason string) {
	var expiry time.Time
	if duration == 0 {
		expiry = time.Time{}
	} else {
		expiry = time.Now().Add(duration)
	}
	entry := &BlacklistEntry{
		Value:     value,
		Type:      blType,
		Expiry:    expiry,
		Reason:    reason,
		CreatedAt: time.Now(),
	}
	_, err := bm.db.Exec(`
INSERT OR REPLACE INTO blacklist (value, type, reason, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)
`, value, blType, reason, nullTime(expiry), entry.CreatedAt)
	if err != nil {
		bm.logger.Error("写入黑名单DB失败", err)
		return
	}
	key := bm.generateKey(blType, value)
	bm.entries.Store(key, entry)
	bm.logger.Info("封禁: 类型=%s, 值=%s, 原因: %s, 到期: %v", blType, value, reason, expiry)
}

func (bm *BlacklistManager) BatchBlock(entries []*BlacklistEntry) {
	if len(entries) == 0 {
		return
	}
	tx, err := bm.db.Begin()
	if err != nil {
		bm.logger.Error("开启批量封禁事务失败", err)
		return
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
INSERT OR REPLACE INTO blacklist (value, type, reason, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)
`)
	if err != nil {
		bm.logger.Error("准备批量封禁语句失败", err)
		return
	}
	defer stmt.Close()
	for _, entry := range entries {
		_, err := stmt.Exec(entry.Value, entry.Type, entry.Reason, nullTime(entry.Expiry), entry.CreatedAt)
		if err != nil {
			bm.logger.Error("批量封禁执行失败", err)
			continue
		}
		key := bm.generateKey(entry.Type, entry.Value)
		bm.entries.Store(key, entry)
	}
	if err := tx.Commit(); err != nil {
		bm.logger.Error("提交批量封禁事务失败", err)
		return
	}
	bm.logger.Info("批量封禁完成: 共处理 %d 条记录", len(entries))
}

func (bm *BlacklistManager) Unblock(value string) bool {
	return bm.UnblockByValue(value)
}

func (bm *BlacklistManager) UnblockByTypeAndValue(blType, value string) bool {
	key := bm.generateKey(blType, value)
	_, exists := bm.entries.Load(key)
	if !exists {
		return false
	}
	_, err := bm.db.Exec("DELETE FROM blacklist WHERE type = ? AND value = ?", blType, value)
	if err != nil {
		bm.logger.Error("删除黑名单DB失败", err)
		return false
	}
	bm.entries.Delete(key)
	bm.logger.Info("解除封禁: 类型=%s, 值=%s", blType, value)
	return true
}

func (bm *BlacklistManager) UnblockByValue(value string) bool {
	var keysToDelete []string
	bm.entries.Range(func(key, valueInterface interface{}) bool {
		entry := valueInterface.(*BlacklistEntry)
		if entry.Value == value {
			keysToDelete = append(keysToDelete, key.(string))
		}
		return true
	})
	if len(keysToDelete) == 0 {
		return false
	}
	tx, err := bm.db.Begin()
	if err != nil {
		bm.logger.Error("开启事务失败", err)
		return false
	}
	defer tx.Rollback()
	successCount := 0
	for _, key := range keysToDelete {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		blType, blValue := parts[0], parts[1]
		result, err := tx.Exec(
			"DELETE FROM blacklist WHERE value = ? AND type = ?",
			blValue, blType,
		)
		if err != nil {
			bm.logger.Error("删除黑名单失败", err)
			continue
		}
		if rows, _ := result.RowsAffected(); rows > 0 {
			successCount++
		}
	}
	if successCount == 0 {
		return false
	}
	if err := tx.Commit(); err != nil {
		bm.logger.Error("提交事务失败", err)
		return false
	}
	for _, key := range keysToDelete {
		bm.entries.Delete(key)
	}
	bm.logger.Info("解除封禁: 值=%s (删除了 %d 个条目)", value, successCount)
	return true
}

func (bm *BlacklistManager) GetBlacklist() []*BlacklistEntry {
	var result []*BlacklistEntry
	bm.entries.Range(func(key, value interface{}) bool {
		result = append(result, value.(*BlacklistEntry))
		return true
	})
	return result
}

func (bm *BlacklistManager) CleanupExpired() int {
	cleaned := 0
	now := time.Now()
	var expiredKeys []string
	bm.entries.Range(func(key, value interface{}) bool {
		entry := value.(*BlacklistEntry)
		if !entry.Expiry.IsZero() && now.After(entry.Expiry) {
			expiredKeys = append(expiredKeys, key.(string))
		}
		return true
	})
	for _, key := range expiredKeys {
		bm.entries.Delete(key)
		cleaned++
	}
	if cleaned > 0 {
		_, err := bm.db.Exec("DELETE FROM blacklist WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP")
		if err != nil {
			bm.logger.Error("清理过期黑名单DB失败", err)
		}
	}
	return cleaned
}

func (bm *BlacklistManager) GetBlockedCount() map[string]int {
	stats := make(map[string]int)
	bm.entries.Range(func(key, value interface{}) bool {
		entry := value.(*BlacklistEntry)
		stats[entry.Type]++
		return true
	})
	return stats
}

func (bm *BlacklistManager) cleanupExpiredRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cleaned := bm.CleanupExpired()
		if cleaned > 0 {
			bm.logger.Debug("清理了 %d 个过期的黑名单条目", cleaned)
		}
	}
}

func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

func getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if isPrivateIP(clientIP) && len(ips) > 1 {
				for i := 1; i < len(ips); i++ {
					candidate := strings.TrimSpace(ips[i])
					if !isPrivateIP(candidate) {
						return candidate
					}
				}
			}
			return clientIP
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type CloudCheckConfig struct {
	Name      string
	APIURL    string
	Method    string
	Headers   map[string]string
	CheckFunc func(response string) (bool, string, string)
}

type LoadBalancerConfig struct {
	Strategy      string `json:"strategy"`
	HealthCheck   bool   `json:"health_check"`
	CheckInterval int    `json:"check_interval"`
	Timeout       int    `json:"timeout"`
}

type APIServer struct {
	URL                 string
	IsHealthy           bool
	ResponseTime        time.Duration
	LastCheck           time.Time
	ErrorCount          int
	SuccessCount        int
	LeastConnErrorCount int
	mutex               sync.RWMutex
}

type LoadBalancer struct {
	servers           []*APIServer
	strategy          string
	currentIdx        int
	mutex             sync.RWMutex
	logger            *Logger
	stopChan          chan struct{}
	healthCheckClient *http.Client
	checkInterval     int
}

func DefaultLoadBalancerConfig() LoadBalancerConfig {
	return LoadBalancerConfig{
		Strategy:      "round_robin",
		HealthCheck:   true,
		CheckInterval: 600,
		Timeout:       5,
	}
}

func (lb *LoadBalancer) RecordLeastConnFailure(serverURL string) {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()
	for _, server := range lb.servers {
		if server.URL == serverURL {
			server.mutex.Lock()
			server.LeastConnErrorCount++
			lb.logger.Debug("记录服务器 %s 的LeastConn错误计数，当前：%d", serverURL, server.LeastConnErrorCount)
			server.mutex.Unlock()
			break
		}
	}
}

func NewLoadBalancer(urls []string, strategy string, checkInterval int, logger *Logger) *LoadBalancer {
	servers := make([]*APIServer, len(urls))
	for i, url := range urls {
		servers[i] = &APIServer{
			URL:                 strings.TrimSpace(url),
			IsHealthy:           true,
			LastCheck:           time.Now(),
			ErrorCount:          0,
			LeastConnErrorCount: 0,
		}
	}
	lb := &LoadBalancer{
		servers:       servers,
		strategy:      strategy,
		logger:        logger,
		stopChan:      make(chan struct{}),
		checkInterval: checkInterval,
		healthCheckClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: globalTransport,
		},
	}
	if len(servers) > 1 {
		go lb.startHealthCheck()
	}
	return lb
}

func (lb *LoadBalancer) SelectServer() (*APIServer, error) {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()
	if len(lb.servers) == 0 {
		return nil, errors.New("没有可用的API服务器")
	}
	healthyServers := make([]*APIServer, 0)
	for _, server := range lb.servers {
		server.mutex.RLock()
		if server.IsHealthy {
			healthyServers = append(healthyServers, server)
		}
		server.mutex.RUnlock()
	}
	if len(healthyServers) == 0 {
		lb.logger.Warn("没有健康的API服务器，使用降级策略")
		return lb.servers[0], nil
	}
	if len(healthyServers) == 1 {
		return healthyServers[0], nil
	}
	switch lb.strategy {
	case "random":
		return lb.selectRandom(healthyServers), nil
	case "round_robin":
		return lb.selectRoundRobin(healthyServers), nil
	case "least_conn":
		return lb.selectLeastConn(healthyServers), nil
	case "response_time":
		return lb.selectByResponseTime(healthyServers), nil
	default:
		return lb.selectRoundRobin(healthyServers), nil
	}
}

func (lb *LoadBalancer) selectRandom(servers []*APIServer) *APIServer {
	return servers[rand.Intn(len(servers))]
}

func (lb *LoadBalancer) selectRoundRobin(servers []*APIServer) *APIServer {
	server := servers[lb.currentIdx%len(servers)]
	lb.currentIdx = (lb.currentIdx + 1) % len(servers)
	return server
}

func (lb *LoadBalancer) selectLeastConn(servers []*APIServer) *APIServer {
	if len(servers) == 0 {
		return nil
	}
	var zeroErrorServers []*APIServer
	for _, server := range servers {
		server.mutex.RLock()
		if server.LeastConnErrorCount == 0 {
			zeroErrorServers = append(zeroErrorServers, server)
		}
		server.mutex.RUnlock()
	}
	if len(zeroErrorServers) > 0 {
		selected := zeroErrorServers[rand.Intn(len(zeroErrorServers))]
		lb.logger.Debug("LeastConn选择错误计数为0的服务器: %s (计数: %d)",
			selected.URL, selected.LeastConnErrorCount)
		return selected
	}
	selected := servers[0]
	selected.mutex.RLock()
	minLeastConnErrors := selected.LeastConnErrorCount
	selected.mutex.RUnlock()
	var minLeastConnErrorServers []*APIServer
	for _, server := range servers {
		server.mutex.RLock()
		leastConnErrorCount := server.LeastConnErrorCount
		server.mutex.RUnlock()
		if leastConnErrorCount < minLeastConnErrors {
			minLeastConnErrors = leastConnErrorCount
			minLeastConnErrorServers = []*APIServer{server}
		} else if leastConnErrorCount == minLeastConnErrors {
			minLeastConnErrorServers = append(minLeastConnErrorServers, server)
		}
	}
	if len(minLeastConnErrorServers) == 1 {
		lb.logger.Debug("LeastConn选择唯一最小错误计数的服务器: %s (计数: %d)",
			minLeastConnErrorServers[0].URL, minLeastConnErrors)
		return minLeastConnErrorServers[0]
	}
	if len(minLeastConnErrorServers) > 0 {
		selected = minLeastConnErrorServers[rand.Intn(len(minLeastConnErrorServers))]
		lb.logger.Debug("LeastConn随机选择最小错误计数的服务器: %s (计数: %d)",
			selected.URL, minLeastConnErrors)
		return selected
	}
	lb.logger.Debug("LeastConn选择默认服务器: %s (计数: %d)",
		selected.URL, selected.LeastConnErrorCount)
	return selected
}

func (lb *LoadBalancer) selectByResponseTime(servers []*APIServer) *APIServer {
	if len(servers) == 0 {
		return nil
	}
	selected := servers[0]
	minResponseTime := selected.ResponseTime
	for _, server := range servers[1:] {
		if server.ResponseTime < minResponseTime {
			selected = server
			minResponseTime = server.ResponseTime
		}
	}
	return selected
}

func (lb *LoadBalancer) startHealthCheck() {
	ticker := time.NewTicker(time.Duration(lb.checkInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			lb.performHealthCheck()
		case <-lb.stopChan:
			return
		}
	}
}

func (lb *LoadBalancer) performHealthCheck() {
	lb.mutex.RLock()
	servers := make([]*APIServer, len(lb.servers))
	copy(servers, lb.servers)
	lb.mutex.RUnlock()
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(s *APIServer) {
			defer wg.Done()
			lb.checkServerHealth(s)
		}(server)
	}
	wg.Wait()
}

func (lb *LoadBalancer) checkServerHealth(server *APIServer) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	healthURL := strings.TrimSuffix(server.URL, "/") + "/api/health"
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		lb.updateServerStatus(server, false, 0)
		return
	}
	resp, err := lb.healthCheckClient.Do(req)
	if err != nil {
		lb.updateServerStatus(server, false, 0)
		return
	}
	defer resp.Body.Close()
	responseTime := time.Since(start)
	var healthResponse struct {
		Status string `json:"status"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		lb.updateServerStatus(server, false, responseTime)
		return
	}
	isHealthy := false
	if err := json.Unmarshal(body, &healthResponse); err == nil {
		isHealthy = healthResponse.Status == "ok"
	} else {
		isHealthy = strings.Contains(string(body), "ok")
	}
	lb.updateServerStatus(server, isHealthy, responseTime)
}

func (lb *LoadBalancer) updateServerStatus(server *APIServer, isHealthy bool, responseTime time.Duration) {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	oldHealth := server.IsHealthy
	server.IsHealthy = isHealthy
	server.ResponseTime = responseTime
	server.LastCheck = time.Now()
	if isHealthy {
		server.SuccessCount++
		server.ErrorCount = 0
		if !oldHealth {
			lb.logger.Info("API服务器恢复健康: %s (原有错误计数: %d, LeastConn错误计数: %d)",
				server.URL, server.ErrorCount, server.LeastConnErrorCount)
		}
	} else {
		server.ErrorCount++
		server.LeastConnErrorCount++
		if oldHealth {
			lb.logger.Warn("API服务器变为不健康: %s (原有错误计数: %d, LeastConn错误计数: %d)",
				server.URL, server.ErrorCount, server.LeastConnErrorCount)
		} else {
			lb.logger.Debug("API服务器健康检查失败: %s (原有错误计数: %d, LeastConn错误计数: %d)",
				server.URL, server.ErrorCount, server.LeastConnErrorCount)
		}
	}
}

func (lb *LoadBalancer) Stop() {
	close(lb.stopChan)
	if lb.healthCheckClient != nil {
		lb.healthCheckClient.CloseIdleConnections()
	}
}

func (lb *LoadBalancer) GetServerStats() []map[string]interface{} {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()
	stats := make([]map[string]interface{}, len(lb.servers))
	for i, server := range lb.servers {
		server.mutex.RLock()
		stats[i] = map[string]interface{}{
			"url":                    server.URL,
			"is_healthy":             server.IsHealthy,
			"response_time":          server.ResponseTime.String(),
			"last_check":             server.LastCheck,
			"error_count":            server.ErrorCount,
			"least_conn_error_count": server.LeastConnErrorCount,
			"success_count":          server.SuccessCount,
		}
		server.mutex.RUnlock()
	}
	return stats
}

type Config struct {
	PansouAPIURLs        string             `json:"pansou_api_urls"`
	PGCloudTypes         string             `json:"pg_cloud_types"`
	ZXCloudTypes         string             `json:"zx_cloud_types"`
	ServerPort           int                `json:"server_port"`
	MaxLinksPerType      int                `json:"max_links_per_type"`
	Keywords             string             `json:"keywords"`
	Channels             string             `json:"channels"`
	Plugins              string             `json:"plugins"`
	PGImageProxyMode     string             `json:"pg_image_proxy_mode"`
	ZXImageProxyMode     string             `json:"zx_image_proxy_mode"`
	APITimeout           int                `json:"api_timeout"`
	WorkerTaskTimeout    int                `json:"worker_task_timeout"`
	MaxWorkers           int                `json:"max_workers"`
	LinkCheckEnabled     bool               `json:"link_check_enabled"`
	LinkCheckWorkers     int                `json:"link_check_workers"`
	LinkCheckTimeout     int                `json:"link_check_timeout"`
	LoadBalancerConfig   LoadBalancerConfig `json:"load_balancer_config"`
	AutoBlockIP          bool               `json:"auto_block_ip"`
	LinkCheckAPIURL      string             `json:"link_check_api_url"`
	LinkCheckMode        string             `json:"link_check_mode"`
	BlockKeywordsContain string             `json:"block_keywords_contain"`
	BlockKeywordsExact   string             `json:"block_keywords_exact"`
}

func DefaultConfig() Config {
	return Config{
		PansouAPIURLs:        defaultPansouAPIURL,
		PGCloudTypes:         defaultPGCloudTypes,
		ZXCloudTypes:         defaultZXCloudTypes,
		ServerPort:           defaultPort,
		MaxLinksPerType:      defaultMaxLinks,
		Keywords:             "",
		Channels:             "",
		Plugins:              "",
		PGImageProxyMode:     defaultPGImageProxy,
		ZXImageProxyMode:     defaultZXImageProxy,
		APITimeout:           defaultAPITimeout,
		WorkerTaskTimeout:    defaultWorkerTaskTimeout,
		MaxWorkers:           defaultWorkers,
		LinkCheckEnabled:     false,
		LinkCheckWorkers:     defaultCheckWorkers,
		LinkCheckTimeout:     15,
		LoadBalancerConfig:   DefaultLoadBalancerConfig(),
		AutoBlockIP:          false,
		LinkCheckAPIURL:      "",
		LinkCheckMode:        "auto",
		BlockKeywordsContain: "",
		BlockKeywordsExact:   "",
	}
}

func NewApplication() (*Application, error) {
	app := &Application{}
	app.logger = NewLogger(InfoLevel)
	logLevel := InfoLevel
	if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
		switch strings.TrimSpace(strings.ToUpper(envLevel)) {
		case "DEBUG":
			logLevel = DebugLevel
			app.logger.Info("日志级别已设置为 DEBUG（海量日志）")
		case "INFO":
			logLevel = InfoLevel
		case "WARN", "WARNING":
			logLevel = WarnLevel
		case "ERROR":
			logLevel = ErrorLevel
		default:
			app.logger.Warn("未知的 LOG_LEVEL 值: %s，已使用默认 INFO 级别", envLevel)
		}
	} else {
		app.logger.Info("未设置 LOG_LEVEL 环境变量，使用默认 INFO 级别")
	}
	if logLevel != InfoLevel {
		app.logger.SetLevel(logLevel)
	}
	var err error
	app.db, err = initSQLiteDB()
	if err != nil {
		return nil, fmt.Errorf("数据库初始化失败: %w", err)
	}
	app.configManager, err = NewConfigManager(app.db, app.logger)
	if err != nil {
		return nil, fmt.Errorf("配置管理器初始化失败: %w", err)
	}
	app.configManager.SetApplication(app)
	if err := app.initializeLoadBalancer(); err != nil {
		return nil, fmt.Errorf("负载均衡器初始化失败: %w", err)
	}
	app.metricsManager = NewMetricsManager()
	app.blacklistManager = NewBlacklistManager(app.db, app.logger)
	app.geoipService = NewGeoIPService(app.logger)
	app.passwordProtectionManager = NewPasswordProtectionManager(app.logger)
	if err := app.initializeTemplates(); err != nil {
		return nil, fmt.Errorf("模板初始化失败: %w", err)
	}
	cfg := app.configManager.GetConfig()
	initialPool := NewWorkerPool(cfg.MaxWorkers, time.Duration(cfg.WorkerTaskTimeout)*time.Second, app.logger)
	app.workerPool.Store(initialPool)
	app.logger.Info("Worker池初始化完成: workers=%d, timeout=%ds", cfg.MaxWorkers, cfg.WorkerTaskTimeout)

	globalLinkCheckPool = NewLinkCheckWorkerPool(cfg.LinkCheckWorkers, app.logger)

	app.linkCheckManager = NewLinkCheckTaskManager(
		time.Duration(cfg.LinkCheckTimeout)*time.Second,
		app.logger,
		app.db,
		cfg.LinkCheckAPIURL,
		cfg.LinkCheckMode,
	)
	app.logger.Info("链接检查任务管理器初始化完成，模式: %s", cfg.LinkCheckMode)
	app.pansouClient = &http.Client{
		Transport: globalTransport,
	}
	adminToken := os.Getenv("ADMIN_TOKEN")
	app.authMiddleware = &AuthMiddleware{adminToken: adminToken}
	if adminToken == "" {
		app.logger.Warn("未设置ADMIN_TOKEN，配置API将无保护")
	} else {
		app.logger.Info("已设置ADMIN_TOKEN，配置API需要认证")
	}
	go app.startBlacklistCleanup()
	app.logger.Info("应用初始化完成")
	return app, nil
}

func initSQLiteDB() (*sql.DB, error) {
	dbPath := os.Getenv("P2T_DB_PATH")
	if dbPath == "" {
		dbPath = "p2t.db"
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(maxDBConnections)
	db.SetMaxIdleConns(maxDBIdleConnections)
	db.SetConnMaxLifetime(time.Hour)
	db.Exec("PRAGMA busy_timeout = 10000;")
	db.Exec("PRAGMA journal_mode = WAL;")
	db.Exec("PRAGMA synchronous = NORMAL;")
	db.Exec("PRAGMA cache_size = -64000;")
	db.Exec("PRAGMA temp_store = memory;")
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS app_config (
key_name TEXT PRIMARY KEY,
value TEXT,
description TEXT,
updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
`)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
INSERT OR IGNORE INTO app_config (key_name, value, description) VALUES
('BLOCK_KEYWORDS_CONTAIN', '', '包含关键词（逗号分隔）'),
('BLOCK_KEYWORDS_EXACT', '', '完全匹配关键词（逗号分隔）')
`)
	if err != nil {
		log.Printf("[ERROR] 初始化屏蔽关键词配置失败: %v", err)
	}

	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS blacklist (
value TEXT NOT NULL,
type TEXT NOT NULL DEFAULT 'ip',
reason TEXT,
expires_at DATETIME,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
PRIMARY KEY (value, type)
)
`)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_blacklist_expiry ON blacklist(expires_at)`)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_blacklist_type ON blacklist(type)`)
	if err != nil {
		return nil, err
	}
	var oldTableExists bool
	err = db.QueryRow(`
SELECT COUNT(*) FROM sqlite_master 
WHERE type='table' AND name='ip_blacklist'
`).Scan(&oldTableExists)
	if err != nil {
		return nil, err
	}
	if oldTableExists {
		log.Println("[INFO] 检测到旧的黑名单表，正在迁移数据...")
		_, err = db.Exec(`
INSERT OR IGNORE INTO blacklist (value, type, reason, expires_at, created_at)
SELECT ip, 'ip', reason, expires_at, created_at FROM ip_blacklist
WHERE ip IS NOT NULL AND ip != ''
`)
		if err != nil {
			log.Printf("[ERROR] 迁移黑名单数据失败: %v", err)
		} else {
			_, err = db.Exec("DROP TABLE IF EXISTS ip_blacklist")
			if err != nil {
				log.Printf("[ERROR] 删除旧黑名单表失败: %v", err)
			} else {
				log.Println("[INFO] 黑名单数据迁移完成")
			}
		}
	}
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS link_cache (
url_hash TEXT PRIMARY KEY,
original_url TEXT NOT NULL,
cloud_type TEXT NOT NULL,
is_valid INTEGER NOT NULL,
status TEXT NOT NULL,
file_info TEXT,
check_time DATETIME NOT NULL
)
`)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_check_time ON link_cache(check_time)`)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (app *Application) startBlacklistCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cleaned := app.blacklistManager.CleanupExpired()
		if cleaned > 0 {
			app.logger.Debug("清理了 %d 个过期的黑名单条目", cleaned)
		}
	}
}

func (app *Application) initializeLoadBalancer() error {
	cfg := app.configManager.GetConfig()
	urls := strings.Split(cfg.PansouAPIURLs, ",")
	validURLs := make([]string, 0)
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" && isValidURL(url) {
			validURLs = append(validURLs, url)
		}
	}
	if len(validURLs) == 0 {
		return errors.New("没有有效的API服务器地址")
	}
	app.loadBalancer = NewLoadBalancer(validURLs, cfg.LoadBalancerConfig.Strategy, cfg.LoadBalancerConfig.CheckInterval, app.logger)
	if len(validURLs) > 1 {
		app.logger.Info("负载均衡器初始化完成: 策略=%s, 服务器数量=%d",
			cfg.LoadBalancerConfig.Strategy, len(validURLs))
		for i, url := range validURLs {
			app.logger.Info(" API服务器%d: %s", i+1, url)
		}
	} else {
		app.logger.Info("使用单个API服务器: %s", validURLs[0])
	}
	return nil
}

func (app *Application) GetWorkerPool() *WorkerPool {
	return app.workerPool.Load().(*WorkerPool)
}

func (app *Application) UpdateWorkerPool(workers int, timeout time.Duration) {
	newPool := NewWorkerPool(workers, timeout, app.logger)
	oldPool := app.workerPool.Swap(newPool)
	if oldPool != nil {
		oldPool.(*WorkerPool).Close()
		app.logger.Info("旧Worker池已关闭")
	}
	app.logger.Info("Worker池已更新: workers=%d, timeout=%v", workers, timeout)
}

func (app *Application) Reconfigure(newConfig Config) error {
	app.UpdateWorkerPool(newConfig.MaxWorkers, time.Duration(newConfig.WorkerTaskTimeout)*time.Second)
	app.linkCheckManager.SetCheckMode(newConfig.LinkCheckMode)
	if err := app.initializeLoadBalancer(); err != nil {
		return fmt.Errorf("重新初始化负载均衡器失败: %w", err)
	}
	app.linkCheckManager.UpdateAPIURL(newConfig.LinkCheckAPIURL)
	return nil
}

func (app *Application) Close() {
	if app.metricsManager != nil {
		app.metricsManager.Close()
	}
	if app.geoipService != nil {
		app.geoipService.Close()
	}
	if app.loadBalancer != nil {
		app.loadBalancer.Stop()
	}
	if app.db != nil {
		app.db.Close()
	}
	if globalLinkCheckPool != nil {
		globalLinkCheckPool.Close()
	}
}

type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

type Logger struct {
	*log.Logger
	level LogLevel
}

func NewLogger(level LogLevel) *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
		level:  level,
	}
}

func (l *Logger) ShouldLog(level LogLevel) bool {
	return level >= l.level
}

func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

func (l *Logger) GetLevel() LogLevel {
	return l.level
}

func (l *Logger) Info(msg string, fields ...interface{}) {
	if l.ShouldLog(InfoLevel) {
		if len(fields) > 0 {
			l.Printf("[INFO] "+msg, fields...)
		} else {
			l.Print("[INFO] " + msg)
		}
	}
}

func (l *Logger) Error(msg string, err error, fields ...interface{}) {
	if l.ShouldLog(ErrorLevel) {
		allFields := make([]interface{}, 0, len(fields)+1)
		allFields = append(allFields, err)
		allFields = append(allFields, fields...)
		l.Printf("[ERROR] "+msg+": %v", allFields...)
	}
}

func (l *Logger) Warn(msg string, fields ...interface{}) {
	if l.ShouldLog(WarnLevel) {
		if len(fields) > 0 {
			l.Printf("[WARN] "+msg, fields...)
		} else {
			l.Print("[WARN] " + msg)
		}
	}
}

func (l *Logger) Debug(msg string, fields ...interface{}) {
	if l.ShouldLog(DebugLevel) {
		if len(fields) > 0 {
			l.Printf("[DEBUG] "+msg, fields...)
		} else {
			l.Print("[DEBUG] " + msg)
		}
	}
}

func getBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

func putBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}

type ConfigManager struct {
	config     Config
	configLock sync.RWMutex
	app        *Application
	logger     *Logger
	db         *sql.DB
}

func NewConfigManager(db *sql.DB, logger *Logger) (*ConfigManager, error) {
	cm := &ConfigManager{
		config: DefaultConfig(),
		logger: logger,
		db:     db,
	}
	cm.applyEnvironmentOverrides()
	cm.loadFromDB()
	return cm, nil
}

func (cm *ConfigManager) SetApplication(app *Application) {
	cm.app = app
}

func (cm *ConfigManager) applyEnvironmentOverrides() {
	cm.configLock.Lock()
	defer cm.configLock.Unlock()
	tempConfig := cm.config

	if envVal := os.Getenv("PANSOU_API_URLS"); envVal != "" {
		tempConfig.PansouAPIURLs = envVal
	} else if envVal := os.Getenv("PANSOU_API_URL"); envVal != "" {
		tempConfig.PansouAPIURLs = envVal
	}
	if envVal := os.Getenv("PANSOU_PG_CLOUD_TYPES"); envVal != "" {
		tempConfig.PGCloudTypes = envVal
	}
	if envVal := os.Getenv("PANSOU_ZX_CLOUD_TYPES"); envVal != "" {
		tempConfig.ZXCloudTypes = envVal
	}
	if envVal := os.Getenv("PORT"); envVal != "" {
		if port, err := strconv.Atoi(envVal); err == nil {
			tempConfig.ServerPort = port
		}
	}
	if envVal := os.Getenv("MAX_LINKS_PER_TYPE"); envVal != "" {
		if maxLinks, err := strconv.Atoi(envVal); err == nil && maxLinks > 0 && maxLinks <= maxLinksLimit {
			tempConfig.MaxLinksPerType = maxLinks
		}
	}
	if envVal := os.Getenv("KEYWORDS"); envVal != "" {
		tempConfig.Keywords = envVal
	}
	if envVal := os.Getenv("CHANNELS"); envVal != "" {
		tempConfig.Channels = envVal
	}
	if envVal := os.Getenv("PLUGINS"); envVal != "" {
		tempConfig.Plugins = envVal
	}
	if envVal := os.Getenv("PG_IMAGE_PROXY_MODE"); envVal != "" {
		tempConfig.PGImageProxyMode = envVal
	}
	if envVal := os.Getenv("ZX_IMAGE_PROXY_MODE"); envVal != "" {
		tempConfig.ZXImageProxyMode = envVal
	}
	if envVal := os.Getenv("APITIME"); envVal != "" {
		if timeout, err := strconv.Atoi(envVal); err == nil && timeout > 0 && timeout <= maxAPITimeout {
			tempConfig.APITimeout = timeout
		}
	}
	if envVal := os.Getenv("WORKER_TASK_TIMEOUT"); envVal != "" {
		if timeout, err := strconv.Atoi(envVal); err == nil && timeout > 0 && timeout <= maxWorkerTaskTimeout {
			tempConfig.WorkerTaskTimeout = timeout
		}
	}
	if envVal := os.Getenv("MAX_WORKERS"); envVal != "" {
		if workers, err := strconv.Atoi(envVal); err == nil && workers > 0 && workers <= maxWorkersLimit {
			tempConfig.MaxWorkers = workers
		}
	}
	if envVal := os.Getenv("LINK_CHECK_ENABLED"); envVal != "" {
		if enabled, err := strconv.ParseBool(envVal); err == nil {
			tempConfig.LinkCheckEnabled = enabled
		}
	}
	if envVal := os.Getenv("LINK_CHECK_WORKERS"); envVal != "" {
		if workers, err := strconv.Atoi(envVal); err == nil && workers > 0 && workers <= maxCheckWorkers {
			tempConfig.LinkCheckWorkers = workers
		}
	}
	if envVal := os.Getenv("LINK_CHECK_TIMEOUT"); envVal != "" {
		if timeout, err := strconv.Atoi(envVal); err == nil && timeout > 0 && timeout <= 60 {
			tempConfig.LinkCheckTimeout = timeout
		}
	}
	if envVal := os.Getenv("LB_STRATEGY"); envVal != "" {
		tempConfig.LoadBalancerConfig.Strategy = envVal
	}
	if envVal := os.Getenv("LB_HEALTH_CHECK"); envVal != "" {
		if enabled, err := strconv.ParseBool(envVal); err == nil {
			tempConfig.LoadBalancerConfig.HealthCheck = enabled
		}
	}
	if envVal := os.Getenv("LB_CHECK_INTERVAL"); envVal != "" {
		if interval, err := strconv.Atoi(envVal); err == nil && interval > 0 {
			tempConfig.LoadBalancerConfig.CheckInterval = interval
		}
	}
	if envVal := os.Getenv("LB_TIMEOUT"); envVal != "" {
		if timeout, err := strconv.Atoi(envVal); err == nil && timeout > 0 {
			tempConfig.LoadBalancerConfig.Timeout = timeout
		}
	}
	if envVal := os.Getenv("AUTO_BLOCK_IP"); envVal != "" {
		if enabled, err := strconv.ParseBool(envVal); err == nil {
			tempConfig.AutoBlockIP = enabled
		}
	}
	if envVal := os.Getenv("LINK_CHECK_API_URL"); envVal != "" {
		tempConfig.LinkCheckAPIURL = envVal
	}
	if envVal := os.Getenv("LINK_CHECK_MODE"); envVal != "" {
		tempConfig.LinkCheckMode = envVal
	}
	if envVal := os.Getenv("BLOCK_KEYWORDS_CONTAIN"); envVal != "" {
		tempConfig.BlockKeywordsContain = envVal
	}
	if envVal := os.Getenv("BLOCK_KEYWORDS_EXACT"); envVal != "" {
		tempConfig.BlockKeywordsExact = envVal
	}

	if err := cm.validateConfig(&tempConfig); err != nil {
		cm.logger.Warn("环境变量配置验证失败，使用默认配置: %v", err)
		return
	}
	cm.config = tempConfig
}

func (cm *ConfigManager) loadFromDB() {
	rows, err := cm.db.Query("SELECT key_name, value FROM app_config")
	if err != nil {
		cm.logger.Error("从DB加载配置失败", err)
		return
	}
	defer rows.Close()
	loaded := 0
	cm.configLock.Lock()
	defer cm.configLock.Unlock()
	for rows.Next() {
		var key string
		var value string
		if err := rows.Scan(&key, &value); err != nil {
			cm.logger.Error("扫描配置行失败", err)
			continue
		}
		updates := map[string]string{key: value}
		results := cm.updateConfigNoLock(updates)
		if _, ok := results[key]; ok && !strings.HasPrefix(results[key], "错误") {
			loaded++
		}
	}
	cm.logger.Info("从DB加载 %d 条配置", loaded)
}

func validateCloudTypes(cloudTypes string) error {
	if cloudTypes == "" {
		return nil
	}
	types := strings.Split(cloudTypes, ",")
	for _, t := range types {
		t = strings.TrimSpace(strings.ToLower(t))
		if t != "" && !validCloudTypes[t] {
			return fmt.Errorf("无效的云类型: %s", t)
		}
	}
	return nil
}

func (cm *ConfigManager) validateConfig(cfg *Config) error {
	urls := strings.Split(cfg.PansouAPIURLs, ",")
	validCount := 0
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" && isValidURL(url) {
			validCount++
		}
	}
	if validCount == 0 {
		return fmt.Errorf("无效URL: PANSOU_API_URLS '%s'", cfg.PansouAPIURLs)
	}
	if err := validateCloudTypes(cfg.PGCloudTypes); err != nil {
		return fmt.Errorf("无效配置: PGCloudTypes %v", err)
	}
	if err := validateCloudTypes(cfg.ZXCloudTypes); err != nil {
		return fmt.Errorf("无效配置: ZXCloudTypes %v", err)
	}
	if cfg.MaxLinksPerType < 1 || cfg.MaxLinksPerType > maxLinksLimit {
		return fmt.Errorf("无效配置: MaxLinksPerType 必须在1-%d之间", maxLinksLimit)
	}
	if cfg.APITimeout < 1 || cfg.APITimeout > maxAPITimeout {
		return fmt.Errorf("无效配置: APITimeout 必须在1-%d之间", maxAPITimeout)
	}
	if cfg.WorkerTaskTimeout < 1 || cfg.WorkerTaskTimeout > maxWorkerTaskTimeout {
		return fmt.Errorf("无效配置: WorkerTaskTimeout 必须在1-%d之间", maxWorkerTaskTimeout)
	}
	if cfg.MaxWorkers < 1 || cfg.MaxWorkers > maxWorkersLimit {
		return fmt.Errorf("无效配置: MaxWorkers 必须在1-%d之间", maxWorkersLimit)
	}
	if !validProxyModes[cfg.PGImageProxyMode] {
		return fmt.Errorf("无效配置: PG_IMAGE_PROXY_MODE 必须是 proxy/direct/none")
	}
	if !validProxyModes[cfg.ZXImageProxyMode] {
		return fmt.Errorf("无效配置: ZX_IMAGE_PROXY_MODE 必须是 proxy/direct/none")
	}
	if cfg.LinkCheckWorkers < 1 || cfg.LinkCheckWorkers > maxCheckWorkers {
		return fmt.Errorf("无效配置: LinkCheckWorkers 必须在1-%d之间", maxCheckWorkers)
	}
	if cfg.LinkCheckTimeout < 1 || cfg.LinkCheckTimeout > 60 {
		return fmt.Errorf("无效配置: LinkCheckTimeout 必须在1-60秒之间")
	}
	strategies := map[string]bool{
		"random":        true,
		"round_robin":   true,
		"least_conn":    true,
		"response_time": true,
	}
	if !strategies[cfg.LoadBalancerConfig.Strategy] {
		return fmt.Errorf("无效配置: 负载均衡策略必须是 random/round_robin/least_conn/response_time")
	}
	if cfg.LinkCheckAPIURL != "" && !isValidURL(cfg.LinkCheckAPIURL) {
		return fmt.Errorf("无效配置: LinkCheckAPIURL 必须是有效的URL")
	}
	return nil
}

func (cm *ConfigManager) GetConfig() Config {
	cm.configLock.RLock()
	defer cm.configLock.RUnlock()
	return cm.config
}

func (cm *ConfigManager) UpdateConfigOptimized(updates map[string]string) map[string]string {
	results := make(map[string]string)
	tx, err := cm.db.Begin()
	if err != nil {
		cm.logger.Error("开启事务失败", err)
		results["_error"] = "系统错误: 无法开启数据库事务"
		return results
	}
	defer tx.Rollback()
	cm.configLock.RLock()
	tempConfig := cm.config
	oldConfig := cm.config
	cm.configLock.RUnlock()
	validUpdates := make(map[string]string)
	hasValidationError := false
	for key, value := range updates {
		if key == "token" {
			continue
		}
		var errMsg string
		switch key {
		case "PANSOU_API_URLS":
			urls := strings.Split(value, ",")
			validCount := 0
			for _, url := range urls {
				if isValidURL(strings.TrimSpace(url)) {
					validCount++
				}
			}
			if validCount == 0 {
				errMsg = "至少需要一个有效的URL"
			}
		case "PANSOU_PG_CLOUD_TYPES":
			if err := validateCloudTypes(value); err != nil {
				errMsg = err.Error()
			}
		case "PANSOU_ZX_CLOUD_TYPES":
			if err := validateCloudTypes(value); err != nil {
				errMsg = err.Error()
			}
		case "MAX_LINKS_PER_TYPE":
			if intValue, err := strconv.Atoi(value); err != nil || intValue <= 0 || intValue > maxLinksLimit {
				errMsg = fmt.Sprintf("无效正整数 (1-%d)", maxLinksLimit)
			}
		case "APITIME":
			if intValue, err := strconv.Atoi(value); err != nil || intValue <= 0 || intValue > maxAPITimeout {
				errMsg = fmt.Sprintf("无效正整数 (1-%d)", maxAPITimeout)
			}
		case "WORKER_TASK_TIMEOUT":
			if intValue, err := strconv.Atoi(value); err != nil || intValue <= 0 || intValue > maxWorkerTaskTimeout {
				errMsg = fmt.Sprintf("无效正整数 (1-%d)", maxWorkerTaskTimeout)
			}
		case "MAX_WORKERS":
			if intValue, err := strconv.Atoi(value); err != nil || intValue <= 0 || intValue > maxWorkersLimit {
				errMsg = fmt.Sprintf("无效正整数 (1-%d)", maxWorkersLimit)
			}
		case "PG_IMAGE_PROXY_MODE":
			if value != "proxy" && value != "direct" && value != "none" {
				errMsg = "必须是 proxy/direct/none"
			}
		case "ZX_IMAGE_PROXY_MODE":
			if value != "proxy" && value != "direct" && value != "none" {
				errMsg = "必须是 proxy/direct/none"
			}
		case "KEYWORDS":
		case "CHANNELS":
		case "PLUGINS":
		case "LINK_CHECK_ENABLED":
			if value != "true" && value != "false" {
				errMsg = "必须是 true/false"
			}
		case "LINK_CHECK_WORKERS":
			if intValue, err := strconv.Atoi(value); err != nil || intValue <= 0 || intValue > maxCheckWorkers {
				errMsg = fmt.Sprintf("无效正整数 (1-%d)", maxCheckWorkers)
			}
		case "LINK_CHECK_TIMEOUT":
			if intValue, err := strconv.Atoi(value); err != nil || intValue <= 0 || intValue > 60 {
				errMsg = "无效正整数 (1-60)"
			}
		case "LB_STRATEGY":
			strategies := map[string]bool{
				"random":        true,
				"round_robin":   true,
				"least_conn":    true,
				"response_time": true,
			}
			if !strategies[value] {
				errMsg = "必须是 random/round_robin/least_conn/response_time"
			}
		case "LB_HEALTH_CHECK":
			if value != "true" && value != "false" {
				errMsg = "必须是 true/false"
			}
		case "LB_CHECK_INTERVAL":
			if intValue, err := strconv.Atoi(value); err != nil || intValue < 10 {
				errMsg = "必须是大于等于10的整数"
			}
		case "LB_TIMEOUT":
			if intValue, err := strconv.Atoi(value); err != nil || intValue <= 0 || intValue > 30 {
				errMsg = "必须是1-30之间的整数"
			}
		case "AUTO_BLOCK_IP":
			if value != "true" && value != "false" {
				errMsg = "必须是 true/false"
			}
		case "LINK_CHECK_API_URL":
			if value != "" && !isValidURL(value) {
				errMsg = "必须是有效的URL"
			}
		case "LINK_CHECK_MODE":
			if value != "auto" && value != "pancheck" && value != "legacy" {
				errMsg = "必须是 auto/pancheck/legacy"
			}
		case "BLOCK_KEYWORDS_CONTAIN":
			if value != "" {
				keywords := strings.Split(value, ",")
				for _, kw := range keywords {
					kw = strings.TrimSpace(kw)
					if kw == "" {
						errMsg = "关键词不能为空"
						break
					}
					if len(kw) > 100 {
						errMsg = "单个关键词长度不能超过100字符"
						break
					}
				}
			}
		case "BLOCK_KEYWORDS_EXACT":
			if value != "" {
				keywords := strings.Split(value, ",")
				for _, kw := range keywords {
					kw = strings.TrimSpace(kw)
					if kw == "" {
						errMsg = "关键词不能为空"
						break
					}
					if len(kw) > 100 {
						errMsg = "单个关键词长度不能超过100字符"
						break
					}
				}
			}
		default:
			errMsg = "未知配置项"
		}

		if errMsg != "" {
			results[key] = fmt.Sprintf("错误: %s '%s'", errMsg, value)
			hasValidationError = true
		} else {
			validUpdates[key] = value
			results[key] = "验证通过"
		}
	}
	if hasValidationError {
		results["_error"] = "配置验证失败，请检查错误信息"
		return results
	}
	for key, value := range validUpdates {
		switch key {
		case "PANSOU_API_URLS":
			tempConfig.PansouAPIURLs = value
		case "PANSOU_PG_CLOUD_TYPES":
			tempConfig.PGCloudTypes = value
		case "PANSOU_ZX_CLOUD_TYPES":
			tempConfig.ZXCloudTypes = value
		case "MAX_LINKS_PER_TYPE":
			intValue, _ := strconv.Atoi(value)
			tempConfig.MaxLinksPerType = intValue
		case "APITIME":
			intValue, _ := strconv.Atoi(value)
			tempConfig.APITimeout = intValue
		case "WORKER_TASK_TIMEOUT":
			intValue, _ := strconv.Atoi(value)
			tempConfig.WorkerTaskTimeout = intValue
		case "MAX_WORKERS":
			intValue, _ := strconv.Atoi(value)
			tempConfig.MaxWorkers = intValue
		case "PG_IMAGE_PROXY_MODE":
			tempConfig.PGImageProxyMode = value
		case "ZX_IMAGE_PROXY_MODE":
			tempConfig.ZXImageProxyMode = value
		case "KEYWORDS":
			tempConfig.Keywords = value
		case "CHANNELS":
			tempConfig.Channels = value
		case "PLUGINS":
			tempConfig.Plugins = value
		case "LINK_CHECK_ENABLED":
			tempConfig.LinkCheckEnabled = (value == "true")
		case "LINK_CHECK_WORKERS":
			intValue, _ := strconv.Atoi(value)
			tempConfig.LinkCheckWorkers = intValue
		case "LINK_CHECK_TIMEOUT":
			intValue, _ := strconv.Atoi(value)
			tempConfig.LinkCheckTimeout = intValue
		case "LB_STRATEGY":
			tempConfig.LoadBalancerConfig.Strategy = value
		case "LB_HEALTH_CHECK":
			tempConfig.LoadBalancerConfig.HealthCheck = (value == "true")
		case "LB_CHECK_INTERVAL":
			intValue, _ := strconv.Atoi(value)
			tempConfig.LoadBalancerConfig.CheckInterval = intValue
		case "LB_TIMEOUT":
			intValue, _ := strconv.Atoi(value)
			tempConfig.LoadBalancerConfig.Timeout = intValue
		case "AUTO_BLOCK_IP":
			tempConfig.AutoBlockIP = (value == "true")
		case "LINK_CHECK_API_URL":
			tempConfig.LinkCheckAPIURL = value
		case "LINK_CHECK_MODE":
			tempConfig.LinkCheckMode = value
		case "BLOCK_KEYWORDS_CONTAIN":
			tempConfig.BlockKeywordsContain = value
		case "BLOCK_KEYWORDS_EXACT":
			tempConfig.BlockKeywordsExact = value
		}
		_, err := tx.Exec(`
INSERT OR REPLACE INTO app_config (key_name, value)
VALUES (?, ?)
`, key, value)
		if err != nil {
			cm.logger.Error("配置项写入数据库失败", err)
			results["_error"] = fmt.Sprintf("配置项 '%s' 写入数据库失败: %v", key, err)
			return results
		}
		results[key] = fmt.Sprintf("已应用: %s", value)
	}
	if err := cm.validateConfig(&tempConfig); err != nil {
		results["_error"] = "配置验证失败，所有修改已回滚: " + err.Error()
		cm.logger.Error("配置更新验证失败，已回滚所有修改", err)
		return results
	}
	if err := tx.Commit(); err != nil {
		results["_error"] = "事务提交失败: " + err.Error()
		cm.logger.Error("配置事务提交失败", err)
		return results
	}
	cm.configLock.Lock()
	cm.config = tempConfig
	cm.configLock.Unlock()
	needUpdatePool := oldConfig.WorkerTaskTimeout != tempConfig.WorkerTaskTimeout || oldConfig.MaxWorkers != tempConfig.MaxWorkers
	needUpdateLinkCheck := oldConfig.LinkCheckAPIURL != tempConfig.LinkCheckAPIURL
	needUpdateLB := oldConfig.PansouAPIURLs != tempConfig.PansouAPIURLs ||
		oldConfig.LoadBalancerConfig.Strategy != tempConfig.LoadBalancerConfig.Strategy ||
		oldConfig.LoadBalancerConfig.HealthCheck != tempConfig.LoadBalancerConfig.HealthCheck ||
		oldConfig.LoadBalancerConfig.CheckInterval != tempConfig.LoadBalancerConfig.CheckInterval ||
		oldConfig.LoadBalancerConfig.Timeout != tempConfig.LoadBalancerConfig.Timeout
	needUpdateLinkCheckMode := oldConfig.LinkCheckMode != tempConfig.LinkCheckMode
	if (needUpdatePool || needUpdateLB || needUpdateLinkCheck || needUpdateLinkCheckMode) && cm.app != nil {
		if err := cm.app.Reconfigure(tempConfig); err != nil {
			cm.logger.Error("重新配置应用组件失败", err)
			results["_warning"] = "配置已保存但组件重载失败: " + err.Error()
		} else {
			cm.logger.Info("应用组件重新配置完成")
		}
	}
	var appliedUpdates []string
	for key := range validUpdates {
		appliedUpdates = append(appliedUpdates, key)
	}
	if len(appliedUpdates) > 0 {
		cm.logger.Info("配置更新成功: %v", appliedUpdates)
	}
	return results
}

func (cm *ConfigManager) updateConfigNoLock(updates map[string]string) map[string]string {
	results := make(map[string]string)
	tempConfig := cm.config
	for key, value := range updates {
		var errMsg string
		switch key {
		case "PANSOU_API_URLS":
			tempConfig.PansouAPIURLs = value
		case "PANSOU_PG_CLOUD_TYPES":
			tempConfig.PGCloudTypes = value
		case "PANSOU_ZX_CLOUD_TYPES":
			tempConfig.ZXCloudTypes = value
		case "MAX_LINKS_PER_TYPE":
			if intValue, err := strconv.Atoi(value); err == nil {
				tempConfig.MaxLinksPerType = intValue
			}
		case "APITIME":
			if intValue, err := strconv.Atoi(value); err == nil {
				tempConfig.APITimeout = intValue
			}
		case "WORKER_TASK_TIMEOUT":
			if intValue, err := strconv.Atoi(value); err == nil {
				tempConfig.WorkerTaskTimeout = intValue
			}
		case "MAX_WORKERS":
			if intValue, err := strconv.Atoi(value); err == nil {
				tempConfig.MaxWorkers = intValue
			}
		case "PG_IMAGE_PROXY_MODE":
			tempConfig.PGImageProxyMode = value
		case "ZX_IMAGE_PROXY_MODE":
			tempConfig.ZXImageProxyMode = value
		case "KEYWORDS":
			tempConfig.Keywords = value
		case "CHANNELS":
			tempConfig.Channels = value
		case "PLUGINS":
			tempConfig.Plugins = value
		case "LINK_CHECK_ENABLED":
			if enabled, err := strconv.ParseBool(value); err == nil {
				tempConfig.LinkCheckEnabled = enabled
			}
		case "LINK_CHECK_WORKERS":
			if intValue, err := strconv.Atoi(value); err == nil {
				tempConfig.LinkCheckWorkers = intValue
			}
		case "LINK_CHECK_TIMEOUT":
			if intValue, err := strconv.Atoi(value); err == nil {
				tempConfig.LinkCheckTimeout = intValue
			}
		case "LB_STRATEGY":
			tempConfig.LoadBalancerConfig.Strategy = value
		case "LB_HEALTH_CHECK":
			if enabled, err := strconv.ParseBool(value); err == nil {
				tempConfig.LoadBalancerConfig.HealthCheck = enabled
			}
		case "LB_CHECK_INTERVAL":
			if intValue, err := strconv.Atoi(value); err == nil {
				tempConfig.LoadBalancerConfig.CheckInterval = intValue
			}
		case "LB_TIMEOUT":
			if intValue, err := strconv.Atoi(value); err == nil {
				tempConfig.LoadBalancerConfig.Timeout = intValue
			}
		case "LINK_CHECK_API_URL":
			tempConfig.LinkCheckAPIURL = value
		case "BLOCK_KEYWORDS_CONTAIN":
			tempConfig.BlockKeywordsContain = value
		case "BLOCK_KEYWORDS_EXACT":
			tempConfig.BlockKeywordsExact = value
		}
		if errMsg != "" {
			results[key] = fmt.Sprintf("错误: %s", errMsg)
		}
	}
	cm.config = tempConfig
	return results
}

func (cm *ConfigManager) ResetConfig() {
	cm.configLock.Lock()
	defer cm.configLock.Unlock()
	cm.config = DefaultConfig()
	_, err := cm.db.Exec("DELETE FROM app_config")
	if err != nil {
		cm.logger.Error("重置配置DB失败", err)
	}
}

func isValidURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

func getISONow() string {
	return time.Now().UTC().Format(isoFormatStandard)
}

type PansouResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		MergedByType map[string][]Resource `json:"merged_by_type"`
	} `json:"data"`
}

type Resource struct {
	Note      string   `json:"note"`
	URL       string   `json:"url"`
	Password  string   `json:"password"`
	Source    string   `json:"source"`
	DateTime  string   `json:"datetime"`
	Images    []string `json:"images"`
	CloudType string   `json:"cloud_type"`
}

type ProcessedResource struct {
	*Resource
	CloudType     string
	CleanedSource string
	ParsedTime    time.Time
}

type SearchRequest struct {
	Keyword string `json:"keyword"`
	Q       string `json:"q"`
	Type    string `json:"type"`
}

type ZXResponse struct {
	Results []string `json:"results"`
}

type ChannelParams struct {
	Types         []string
	Keywords      []string
	Channels      []string
	Plugins       []string
	CheckLinks    bool
	MaxCheckLinks int
	Include       []string
	Exclude       []string
}

type LinkCheckResult struct {
	URL        string    `json:"url"`
	IsValid    bool      `json:"is_valid"`
	Status     string    `json:"status"`
	Title      string    `json:"title"`
	FileSize   string    `json:"file_size"`
	CheckTime  time.Time `json:"check_time"`
	Error      string    `json:"error,omitempty"`
	CloudType  string    `json:"cloud_type"`
	StatusCode int       `json:"status_code"`
	FinalURL   string    `json:"final_url"`
	Password   string    `json:"password,omitempty"`
}

type LinkCheckTaskManager struct {
	memoryCache *SearchCache
	timeout     time.Duration
	httpClient  *http.Client
	logger      *Logger
	db          *sql.DB
	mutex       sync.RWMutex
	writeQueue  chan *LinkCheckResult
	apiURL      string
	checkMode   string
}

type PipelineConfig struct {
	MaxLinksPerType int
	CheckLinks      bool
	CheckMaxPerType int
	CheckWorkers    int
}

type PipelineResult struct {
	SearchResults     interface{}     `json:"search_results"`
	CheckStats        *LinkCheckStats `json:"check_stats,omitempty"`
	ProcessingTime    time.Duration   `json:"processing_time"`
	TotalResources    int             `json:"total_resources"`
	FilteredResources int             `json:"filtered_resources"`
}

type LinkCheckStats struct {
	Total       int                       `json:"total"`
	Valid       int                       `json:"valid"`
	Invalid     int                       `json:"invalid"`
	Error       int                       `json:"error"`
	Password    int                       `json:"password"`
	ByCloudType map[string]map[string]int `json:"by_cloud_type"`
	Duration    time.Duration             `json:"duration"`
}

type SearchCache struct {
	cache      map[string]*list.Element
	ll         *list.List
	capacity   int
	defaultTTL time.Duration
	mutex      sync.RWMutex
}

type CacheItem struct {
	Key       string
	Data      interface{}
	ExpiresAt time.Time
}

func NewSearchCache(maxSize int, defaultTTL time.Duration) *SearchCache {
	return &SearchCache{
		cache:      make(map[string]*list.Element, maxSize),
		ll:         list.New(),
		capacity:   maxSize,
		defaultTTL: defaultTTL,
	}
}

func (c *SearchCache) Get(key string) (interface{}, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if elem, exists := c.cache[key]; exists {
		item := elem.Value.(*CacheItem)
		if time.Now().After(item.ExpiresAt) {
			c.deleteItem(elem)
			return nil, false
		}
		c.ll.MoveToFront(elem)
		return item.Data, true
	}
	return nil, false
}

func (c *SearchCache) Set(key string, data interface{}) {
	c.SetWithTTL(key, data, c.defaultTTL)
}

func (c *SearchCache) SetWithTTL(key string, data interface{}, ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if elem, exists := c.cache[key]; exists {
		c.ll.MoveToFront(elem)
		item := elem.Value.(*CacheItem)
		item.Data = data
		item.ExpiresAt = time.Now().Add(ttl)
		return
	}
	if c.ll.Len() >= c.capacity {
		c.evictOldest()
	}
	item := &CacheItem{
		Key:       key,
		Data:      data,
		ExpiresAt: time.Now().Add(ttl),
	}
	elem := c.ll.PushFront(item)
	c.cache[key] = elem
}

func (c *SearchCache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if elem, exists := c.cache[key]; exists {
		c.deleteItem(elem)
	}
}

func (c *SearchCache) deleteItem(elem *list.Element) {
	item := elem.Value.(*CacheItem)
	c.ll.Remove(elem)
	delete(c.cache, item.Key)
}

func (c *SearchCache) evictOldest() {
	elem := c.ll.Back()
	if elem != nil {
		c.deleteItem(elem)
	}
}

func (c *SearchCache) CleanupExpired() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	now := time.Now()
	var next *list.Element
	for elem := c.ll.Back(); elem != nil; elem = next {
		next = elem.Prev()
		item := elem.Value.(*CacheItem)
		if now.After(item.ExpiresAt) {
			c.deleteItem(elem)
		}
	}
}

type WorkFunc func(keyword string) (interface{}, error)

type WorkerPool struct {
	workChan   chan *WorkRequest
	workers    int
	timeout    time.Duration
	workerWg   sync.WaitGroup
	ctx        context.Context
	cancelFunc context.CancelFunc
	isRunning  bool
	mu         sync.RWMutex
	logger     *Logger
}

type WorkRequest struct {
	Keyword  string
	Fn       WorkFunc
	Response chan<- *WorkResult
}

type WorkResult struct {
	Data interface{}
	Err  error
}

func NewWorkerPool(workers int, timeout time.Duration, logger *Logger) *WorkerPool {
	if workers <= 0 {
		workers = 1
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool := &WorkerPool{
		workChan:   make(chan *WorkRequest, 1000),
		workers:    workers,
		timeout:    timeout,
		ctx:        ctx,
		cancelFunc: cancel,
		isRunning:  true,
		logger:     logger,
	}
	logger.Info("正在启动 %d 个worker (超时 %v)...", workers, timeout)
	pool.startWorkers()
	logger.Info("Worker池创建完成: workers=%d, timeout=%v", workers, timeout)
	return pool
}

func (p *WorkerPool) startWorkers() {
	for i := 0; i < p.workers; i++ {
		p.workerWg.Add(1)
		go func(id int) {
			defer p.workerWg.Done()
			p.logger.Debug("Worker %d 已启动", id)
			for {
				select {
				case <-p.ctx.Done():
					p.logger.Debug("Worker %d 收到关闭信号，退出", id)
					return
				case work, ok := <-p.workChan:
					if !ok {
						p.logger.Debug("Worker %d: workChan 已关闭，退出", id)
						return
					}
					p.logger.Debug("Worker %d 处理任务: %s", id, work.Keyword)
					result, err := work.Fn(work.Keyword)
					select {
					case work.Response <- &WorkResult{Data: result, Err: err}:
					case <-p.ctx.Done():
						return
					case <-time.After(100 * time.Millisecond):
						p.logger.Warn("Worker %d: 结果发送超时，已丢弃: %s", id, work.Keyword)
					}
				}
			}
		}(i)
	}
}

func (p *WorkerPool) SubmitOptimized(keyword string, fn WorkFunc) (*WorkResult, error) {
	p.mu.RLock()
	if !p.isRunning {
		p.mu.RUnlock()
		return nil, errors.New("worker pool 已关闭")
	}
	p.mu.RUnlock()
	resultChan := make(chan *WorkResult, 1)
	work := &WorkRequest{
		Keyword:  keyword,
		Fn:       fn,
		Response: resultChan,
	}
	select {
	case p.workChan <- work:
	case <-p.ctx.Done():
		return nil, errors.New("worker pool 正在关闭")
	case <-time.After(50 * time.Millisecond):
		return nil, errors.New("任务提交超时（队列满）")
	}
	timeoutCtx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	select {
	case result := <-resultChan:
		return result, nil
	case <-timeoutCtx.Done():
		return nil, errors.New("任务执行超时")
	case <-p.ctx.Done():
		return nil, errors.New("worker pool 已关闭")
	}
}

func (p *WorkerPool) Close() {
	p.mu.Lock()
	if !p.isRunning {
		p.mu.Unlock()
		return
	}
	p.isRunning = false
	p.mu.Unlock()
	p.cancelFunc()
	close(p.workChan)
	p.workerWg.Wait()
	p.logger.Info("WorkerPool 已优雅关闭")
}

type AuthMiddleware struct {
	adminToken string
}

func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func (a *AuthMiddleware) validateToken(token string) bool {
	if a.adminToken == "" {
		return true
	}
	if secureCompare(token, a.adminToken) {
		return true
	}
	hash := sha256.Sum256([]byte(a.adminToken))
	expectedHash := hex.EncodeToString(hash[:])
	return secureCompare(token, expectedHash)
}

func (a *AuthMiddleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.adminToken == "" {
			next(w, r)
			return
		}
		token := r.URL.Query().Get("token")
		if !a.validateToken(token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func sendJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("[ERROR] JSON编码失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success":false,"message":"Internal Server Error"}`))
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonData)))
	if _, err := w.Write(jsonData); err != nil {
		log.Printf("[ERROR] 响应写入失败: %v", err)
	}
}

func sendErrorResponse(w http.ResponseWriter, statusCode int, publicMessage string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"success": false,
		"message": publicMessage,
	}
	jsonData, _ := json.Marshal(response)
	w.Write(jsonData)
}

func recoveryMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("Recovered from panic: %v", rec)
				sendErrorResponse(w, http.StatusInternalServerError, "Internal Server Error")
			}
		}()
		next(w, r)
	}
}

func parseChannelParams(paramStr string, logger *Logger) *ChannelParams {
	params := &ChannelParams{
		Types:         []string{},
		Keywords:      []string{},
		Channels:      []string{},
		Plugins:       []string{},
		CheckLinks:    false,
		MaxCheckLinks: 0,
		Include:       []string{},
		Exclude:       []string{},
	}
	if paramStr == "" {
		return params
	}
	logger.Debug("解析channelUsername参数: %s", paramStr)
	parts := strings.Split(paramStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		keyValue := strings.SplitN(part, ":", 2)
		if len(keyValue) != 2 {
			logger.Warn("channelUsername参数格式错误: %s", part)
			continue
		}
		prefix := strings.TrimSpace(strings.ToLower(keyValue[0]))
		value := strings.TrimSpace(keyValue[1])
		switch prefix {
		case "type":
			params.Types = append(params.Types, value)
		case "keywords":
			params.Keywords = append(params.Keywords, value)
		case "channels":
			params.Channels = append(params.Channels, value)
		case "plugins":
			params.Plugins = append(params.Plugins, value)
		case "check":
			if value == "true" {
				params.CheckLinks = true
				logger.Debug("启用链接检测")
			} else if value == "false" {
				params.CheckLinks = false
				logger.Debug("禁用链接检测")
			} else {
				logger.Warn("check参数值无效: %s", value)
			}
		case "links":
			if intValue, err := strconv.Atoi(value); err == nil && intValue >= 0 {
				params.MaxCheckLinks = intValue
				logger.Debug("设置每类网盘检测数量: %d", intValue)
			} else {
				logger.Warn("links参数值无效: %s", value)
			}
		case "include":
			params.Include = append(params.Include, value)
			logger.Debug("添加包含关键词: %s", value)
		case "exclude":
			params.Exclude = append(params.Exclude, value)
			logger.Debug("添加排除关键词: %s", value)
		default:
			logger.Warn("未知的channelUsername参数前缀: %s", prefix)
		}
	}
	logger.Debug("解析结果 - 类型: %v, 关键词: %v, 频道: %v, 插件: %v, 检测链接: %v, 检测数量: %d, 包含: %v, 排除: %v",
		params.Types, params.Keywords, params.Channels, params.Plugins, params.CheckLinks, params.MaxCheckLinks,
		params.Include, params.Exclude)
	return params
}

func ensure123URLWithWWW(urlStr string) string {
	for _, domain := range domains123Pan {
		searchDomain := "://" + domain
		if strings.Contains(urlStr, searchDomain) {
			wwwDomain := "://www." + domain
			if !strings.Contains(urlStr, wwwDomain) {
				replaced := strings.Replace(urlStr, searchDomain, wwwDomain, 1)
				log.Printf("[INFO] 修复123网盘链接: %s -> %s", urlStr, replaced)
				return replaced
			}
			return urlStr
		}
	}
	return urlStr
}

func ParseTime(datetimeStr string) time.Time {
	if datetimeStr == "" || datetimeStr == "0001-01-01T00:04:00Z" || datetimeStr == "未知" {
		return time.Time{}
	}
	if strings.HasSuffix(datetimeStr, "Z") {
		datetimeStr = strings.TrimSuffix(datetimeStr, "Z") + "+00:00"
	}
	for _, format := range timeFormats {
		if t, err := time.Parse(format, datetimeStr); err == nil {
			return t.UTC()
		}
	}
	log.Printf("[WARN] 时间解析失败: %s", datetimeStr)
	return time.Time{}
}

func getMonthDayFromTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

func cleanChannelName(source string) string {
	if source == "" || source == "unknown" {
		return "bridge"
	}
	return strings.ToLower(source)
}

func compileKeywordRules(keywordConfig string) [][]string {
	var andGroups [][]string
	for _, group := range strings.Split(keywordConfig, ";") {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		var cleaned []string
		for _, kw := range strings.Split(group, ",") {
			kw = strings.TrimSpace(strings.ToLower(kw))
			if kw != "" {
				cleaned = append(cleaned, kw)
			}
		}
		if len(cleaned) > 0 {
			andGroups = append(andGroups, cleaned)
		}
	}
	return andGroups
}

func matchKeywordRules(note string, rules [][]string) bool {
	noteLower := strings.ToLower(note)
	for _, group := range rules {
		groupMatch := false
		for _, kw := range group {
			if strings.Contains(noteLower, kw) {
				groupMatch = true
				break
			}
		}
		if !groupMatch {
			return false
		}
	}
	return true
}

func matchKeywordRulesOR(note string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	noteLower := strings.ToLower(note)
	for _, kw := range keywords {
		if strings.Contains(noteLower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func parseCloudOrder(cloudTypes string) []string {
	if cloudTypes == "" {
		return []string{"aliyun", "quark", "tianyi", "uc", "mobile", "115", "pikpak", "xunlei", "123", "magnet"}
	}
	clouds := strings.Split(cloudTypes, ",")
	seen := make(map[string]bool)
	var ordered []string
	for _, c := range clouds {
		trimmed := strings.ToLower(strings.TrimSpace(c))
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			ordered = append(ordered, trimmed)
		}
	}
	return ordered
}

func cleanTitle(title string) string {
	if !strings.ContainsAny(title, "#$@") {
		return title
	}
	return titleReplacer.Replace(title)
}

func mapCloudType(originalCloudType string) string {
	if mapped, exists := cloudTypeMapping[originalCloudType]; exists {
		return mapped
	}
	return originalCloudType
}

func matchTypeFilter(resource Resource, typeFilters []string) bool {
	if len(typeFilters) == 0 {
		return true
	}
	resourceType := resource.CloudType
	if resourceType == "" {
		resourceType = mapCloudType(resourceType)
	} else {
		resourceType = mapCloudType(resourceType)
	}
	for _, filterType := range typeFilters {
		if resourceType == filterType {
			return true
		}
	}
	return false
}

func ProcessResourcesWithLimit(resources []Resource, cloudTypes string, maxLinks int, logger *Logger) (map[string][]*ProcessedResource, []string) {
	cloudTypeGroups := make(map[string][]*ProcessedResource)
	for i := range resources {
		resourceCopy := resources[i]
		cloudType := resourceCopy.CloudType
		if cloudType == "" {
			logger.Warn("资源缺少 CloudType: URL=%s", resourceCopy.URL)
			cloudType = "unknown"
		} else {
			cloudType = mapCloudType(cloudType)
		}
		pr := &ProcessedResource{
			Resource:      &resourceCopy,
			CloudType:     cloudType,
			CleanedSource: cleanChannelName(resourceCopy.Source),
			ParsedTime:    ParseTime(resourceCopy.DateTime),
		}
		cloudTypeGroups[cloudType] = append(cloudTypeGroups[cloudType], pr)
	}
	limitedGroups := make(map[string][]*ProcessedResource)
	cloudOrder := parseCloudOrder(cloudTypes)
	for cloudType, group := range cloudTypeGroups {
		var withTime, withoutTime []*ProcessedResource
		for _, pr := range group {
			if pr.ParsedTime.IsZero() {
				withoutTime = append(withoutTime, pr)
			} else {
				withTime = append(withTime, pr)
			}
		}
		sort.Slice(withTime, func(i, j int) bool {
			return withTime[i].ParsedTime.After(withTime[j].ParsedTime)
		})
		group = append(withTime, withoutTime...)
		if len(group) > maxLinks {
			group = group[:maxLinks]
		}
		limitedGroups[cloudType] = group
	}
	return limitedGroups, cloudOrder
}

func ProcessPansouDataWithChannelParams(keyword string, channelParams *ChannelParams, cloudTypes string, configManager *ConfigManager, logger *Logger, loadBalancer *LoadBalancer, pansouClient *http.Client) ([]Resource, string, error) {
	cfg := configManager.GetConfig()

	if shouldBlockKeyword(keyword, cfg, logger) {
		logger.Info("关键词被屏蔽: %s", keyword)
		return []Resource{}, "", nil
	}

	cfg = configManager.GetConfig()
	maxRetries := 2
	if loadBalancer != nil && len(strings.Split(cfg.PansouAPIURLs, ",")) > 1 {
		maxRetries = 1
	}
	var selectedServer *APIServer
	var err error
	var allRes []Resource
	for retry := 0; retry <= maxRetries; retry++ {
		if loadBalancer != nil {
			selectedServer, err = loadBalancer.SelectServer()
			if err != nil {
				logger.Warn("选择API服务器失败，重试 %d/%d: %v", retry+1, maxRetries+1, err)
				time.Sleep(time.Duration(retry+1) * 500 * time.Millisecond)
				continue
			}
			logger.Debug("选择的API服务器: %s (重试 %d/%d，原有错误计数: %d, LeastConn错误计数: %d)",
				selectedServer.URL, retry+1, maxRetries+1, selectedServer.ErrorCount, selectedServer.LeastConnErrorCount)
		} else {
			selectedServer = &APIServer{URL: cfg.PansouAPIURLs}
		}
		apiURL := strings.TrimSuffix(selectedServer.URL, "/") + "/api/search"
		params := url.Values{
			"kw":          {keyword},
			"cloud_types": {cloudTypes},
		}
		if len(channelParams.Types) > 0 {
			typeStr := strings.Join(channelParams.Types, ",")
			logger.Debug("使用 channelParams.Types 作为 cloud_types 参数: %s", typeStr)
			params.Set("cloud_types", typeStr)
		}
		channelsToUse := cfg.Channels
		if len(channelParams.Channels) > 0 {
			channelsToUse = strings.Join(channelParams.Channels, ",")
		}
		if channelsToUse != "" {
			params.Add("channels", channelsToUse)
		}
		pluginsToUse := cfg.Plugins
		if len(channelParams.Plugins) > 0 {
			pluginsToUse = strings.Join(channelParams.Plugins, ",")
		}
		if pluginsToUse != "" {
			params.Add("plugins", pluginsToUse)
		}
		if len(channelParams.Include) > 0 || len(channelParams.Exclude) > 0 {
			filter := map[string][]string{}
			if len(channelParams.Include) > 0 {
				filter["include"] = channelParams.Include
			}
			if len(channelParams.Exclude) > 0 {
				filter["exclude"] = channelParams.Exclude
			}
			filterJSON, err := json.Marshal(filter)
			if err != nil {
				logger.Warn("构建filter参数失败: %v", err)
			} else {
				params.Add("filter", string(filterJSON))
				logger.Debug("添加filter参数: %s", string(filterJSON))
			}
		}
		apiTimeout := time.Duration(cfg.APITimeout) * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
		defer cancel()
		startTime := time.Now()
		client := pansouClient
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"?"+params.Encode(), nil)
		if err != nil {
			if loadBalancer != nil {
				loadBalancer.RecordLeastConnFailure(selectedServer.URL)
			}
			logger.Warn("创建请求失败，重试 %d/%d: %v", retry+1, maxRetries+1, err)
			time.Sleep(time.Duration(retry+1) * 500 * time.Millisecond)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			if loadBalancer != nil {
				loadBalancer.RecordLeastConnFailure(selectedServer.URL)
			}
			logger.Warn("API请求失败，重试 %d/%d: %v", retry+1, maxRetries+1, err)
			time.Sleep(time.Duration(retry+1) * 500 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			if loadBalancer != nil {
				loadBalancer.RecordLeastConnFailure(selectedServer.URL)
			}
			logger.Warn("HTTP %d: %s，重试 %d/%d", resp.StatusCode, apiURL, retry+1, maxRetries+1)
			time.Sleep(time.Duration(retry+1) * 500 * time.Millisecond)
			continue
		}
		if loadBalancer != nil {
			responseTime := time.Since(startTime)
			loadBalancer.updateServerStatus(selectedServer, true, responseTime)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			if loadBalancer != nil {
				loadBalancer.RecordLeastConnFailure(selectedServer.URL)
			}
			logger.Warn("读取响应失败，重试 %d/%d: %v", retry+1, maxRetries+1, err)
			time.Sleep(time.Duration(retry+1) * 500 * time.Millisecond)
			continue
		}
		var pr PansouResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			if loadBalancer != nil {
				loadBalancer.RecordLeastConnFailure(selectedServer.URL)
			}
			logger.Warn("JSON解析失败，重试 %d/%d: %v", retry+1, maxRetries+1, err)
			time.Sleep(time.Duration(retry+1) * 500 * time.Millisecond)
			continue
		}
		if pr.Code != 0 {
			if loadBalancer != nil {
				loadBalancer.RecordLeastConnFailure(selectedServer.URL)
			}
			logger.Warn("Pansou错误: %s，重试 %d/%d", pr.Message, retry+1, maxRetries+1)
			time.Sleep(time.Duration(retry+1) * 500 * time.Millisecond)
			continue
		}
		logger.Info("pansou 引擎返回: %d 种网盘类型", len(pr.Data.MergedByType))
		allRes = []Resource{}
		globalDefaultImage := ""
		foundGlobalImage := false
		for _, items := range pr.Data.MergedByType {
			for i := range items {
				if len(items[i].Images) > 0 && items[i].Images[0] != "" {
					globalDefaultImage = html.EscapeString(items[i].Images[0])
					foundGlobalImage = true
					break
				}
			}
			if foundGlobalImage {
				break
			}
		}
		var globalFilterRules [][]string
		if cfg.Keywords != "" {
			globalFilterRules = compileKeywordRules(cfg.Keywords)
		}
		for typ, items := range pr.Data.MergedByType {
			var filteredItems []Resource
			for i := range items {
				var shouldSkip bool
				if len(globalFilterRules) > 0 {
					if !matchKeywordRules(items[i].Note, globalFilterRules) {
						shouldSkip = true
					}
				} else if len(channelParams.Keywords) > 0 {
					if !matchKeywordRulesOR(items[i].Note, channelParams.Keywords) {
						shouldSkip = true
					}
				}
				if shouldSkip {
					continue
				}
				items[i].CloudType = mapCloudType(typ)
				filteredItems = append(filteredItems, items[i])
			}
			allRes = append(allRes, filteredItems...)
		}
		logger.Info("总共找到 %d 条资源（过滤后）", len(allRes))
		return allRes, globalDefaultImage, nil
	}
	return nil, "", fmt.Errorf("盘搜API请求失败，重试%d次后仍失败", maxRetries+1)
}

func shouldBlockKeyword(keyword string, cfg Config, logger *Logger) bool {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		logger.Debug("关键词为空，不进行屏蔽检查")
		return false
	}

	keywordLower := strings.ToLower(keyword)

	if cfg.BlockKeywordsContain != "" {
		keywords := strings.Split(cfg.BlockKeywordsContain, ",")
		for _, kw := range keywords {
			kw = strings.TrimSpace(kw)
			if kw == "" {
				continue
			}
			kwLower := strings.ToLower(kw)
			if strings.Contains(keywordLower, kwLower) {
				logger.Debug("关键词匹配包含屏蔽词: 关键词=%s, 屏蔽词=%s", keyword, kw)
				return true
			}
		}
	}

	if cfg.BlockKeywordsExact != "" {
		keywords := strings.Split(cfg.BlockKeywordsExact, ",")
		for _, kw := range keywords {
			kw = strings.TrimSpace(kw)
			if kw == "" {
				continue
			}
			kwLower := strings.ToLower(kw)
			keywordTrimmedLower := strings.ToLower(strings.TrimSpace(keyword))
			if keywordTrimmedLower == kwLower {
				logger.Debug("关键词匹配完全屏蔽词: 关键词=%s, 屏蔽词=%s", keyword, kw)
				return true
			}
		}
	}

	logger.Debug("关键词未匹配任何屏蔽规则: %s", keyword)
	return false
}

func getImageURL(originalURL string, proxyBase string, imageProxyMode string) string {
	if originalURL == "" {
		return ""
	}
	if strings.HasPrefix(originalURL, proxyBase) {
		return originalURL
	}
	switch imageProxyMode {
	case "proxy":
		return proxyBase + url.PathEscape(originalURL)
	case "direct":
		return originalURL
	case "none":
		return ""
	default:
		return originalURL
	}
}

func extractShareID(urlStr string, cloudType string) string {
	switch cloudType {
	case "aliyun":
		if matches := aliyunPatterns.FindStringSubmatch(urlStr); len(matches) > 1 {
			return matches[1]
		}
	case "quark":
		if matches := quarkPatterns.FindStringSubmatch(urlStr); len(matches) > 1 {
			return matches[1]
		}
	case "uc":
		if matches := ucPattern.FindStringSubmatch(urlStr); len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

func checkWithAPI(urlStr string, cloudType string, config *CloudCheckConfig, password string, httpClient *http.Client) (*LinkCheckResult, error) {
	result := &LinkCheckResult{
		URL:       urlStr,
		CloudType: cloudType,
		CheckTime: time.Now(),
		Password:  password,
	}
	shareID := extractShareID(urlStr, cloudType)
	if shareID == "" {
		return result, fmt.Errorf("无法提取分享ID")
	}
	apiURL := config.APIURL
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var req *http.Request
	var err error
	if config.Method == "POST" {
		var bodyData map[string]interface{}
		switch cloudType {
		case "aliyun":
			bodyData = map[string]interface{}{
				"share_id": shareID,
			}
		case "quark":
			bodyData = map[string]interface{}{
				"pwd_id":   shareID,
				"passcode": password,
			}
		default:
			bodyData = map[string]interface{}{
				"share_id": shareID,
				"password": password,
			}
		}
		jsonData, err := json.Marshal(bodyData)
		if err != nil {
			result.IsValid = false
			result.Status = "error"
			result.Error = fmt.Sprintf("JSON编码失败: %v", err)
			return result, err
		}
		req, err = http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	} else {
		params := url.Values{}
		params.Add("share_id", shareID)
		if password != "" {
			params.Add("password", password)
		}
		if strings.Contains(apiURL, "?") {
			apiURL += "&" + params.Encode()
		} else {
			apiURL += "?" + params.Encode()
		}
		req, err = http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	}
	if err != nil {
		result.IsValid = false
		result.Status = "error"
		result.Error = fmt.Sprintf("创建请求失败: %v", err)
		return result, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Referer", urlStr)
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		result.IsValid = false
		result.Status = "error"
		result.Error = fmt.Sprintf("API请求失败: %v", err)
		return result, err
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		result.IsValid = false
		result.Status = "invalid"
		result.Error = fmt.Sprintf("API返回HTTP %d", resp.StatusCode)
		return result, nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.IsValid = false
		result.Status = "error"
		result.Error = fmt.Sprintf("读取API响应失败: %v", err)
		return result, err
	}
	content := string(body)
	if config.CheckFunc != nil {
		isValid, title, fileSize := config.CheckFunc(content)
		result.IsValid = isValid
		result.Status = title
		result.FileSize = fileSize
		if isValid {
			result.Status = "valid"
		} else {
			result.Status = "invalid"
			result.Error = title
		}
	} else {
		result.IsValid = true
		result.Status = "valid"
		result.Title = fmt.Sprintf("%s分享", config.Name)
	}
	return result, nil
}

func checkSingleURLGeneric(urlStr string, cloudType string, httpClient *http.Client) (*LinkCheckResult, error) {
	result := &LinkCheckResult{
		URL:       urlStr,
		CloudType: cloudType,
		CheckTime: time.Now(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		result.IsValid = false
		result.Status = "error"
		result.Error = fmt.Sprintf("创建请求失败: %v", err)
		return result, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	resp, err := httpClient.Do(req)
	if err != nil {
		result.IsValid = false
		result.Status = "error"
		result.Error = fmt.Sprintf("请求失败: %v", err)
		return result, err
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode
	result.FinalURL = resp.Request.URL.String()
	if resp.StatusCode != http.StatusOK {
		result.IsValid = false
		result.Status = "invalid"
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result, nil
	}
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			result.IsValid = false
			result.Status = "error"
			result.Error = fmt.Sprintf("GZIP解压失败: %v", err)
			return result, err
		}
		defer gzReader.Close()
		reader = gzReader
	}
	limitedReader := &io.LimitedReader{R: reader, N: maxReadSize}
	bufPtr := byteBufferPool.Get().(*[]byte)
	defer byteBufferPool.Put(bufPtr)
	buf := *bufPtr
	buf = buf[:0]
	n, err := io.ReadFull(limitedReader, buf[:cap(buf)])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		result.IsValid = false
		result.Status = "error"
		result.Error = fmt.Sprintf("读取响应失败: %v", err)
		return result, err
	}
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		buf = buf[:n]
	}
	content := string(buf)
	isValid, title, fileSize := analyzeCloudContentAdvanced(cloudType, content, urlStr)
	result.IsValid = isValid
	result.Title = title
	result.FileSize = fileSize
	if isValid {
		result.Status = "valid"
	} else {
		result.Status = "invalid"
		result.Error = "链接失效或文件不存在"
	}
	return result, nil
}

func analyzeCloudContentAdvanced(cloudType, content, urlStr string) (bool, string, string) {
	contentLower := strings.ToLower(content)
	errorFound := false
	errorMsg := ""
	switch cloudType {
	case "aliyun":
		errorPatterns := []string{
			"文件不存在", "文件已删除", "文件违规", "访问页面不存在",
			"sharelink not found", "invalid share", "分享已失效",
		}
		for _, pattern := range errorPatterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				errorFound = true
				errorMsg = "文件不存在或分享已失效"
				break
			}
		}
		if !errorFound && (strings.Contains(contentLower, "文件名称") ||
			strings.Contains(contentLower, "文件大小") ||
			strings.Contains(contentLower, "download") ||
			strings.Contains(contentLower, "保存到网盘")) {
		} else if !errorFound {
			errorFound = true
			errorMsg = "页面内容异常"
		}
	case "quark":
		errorPatterns := []string{
			"文件不存在", "文件已删除", "分享不存在", "链接错误",
			"not found", "deleted", "invalid",
		}
		for _, pattern := range errorPatterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				errorFound = true
				errorMsg = "文件不存在"
				break
			}
		}
		if strings.Contains(contentLower, "需要提取码") {
			errorFound = true
			errorMsg = "需要提取码"
		}
	case "uc":
		errorPatterns := []string{
			"文件不存在", "文件已删除", "分享不存在", "链接失效",
		}
		for _, pattern := range errorPatterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				errorFound = true
				errorMsg = "文件不存在"
				break
			}
		}
	default:
		errorPatterns := []string{
			"文件不存在", "文件已删除", "文件违规", "访问页面不存在",
			"not found", "deleted", "invalid", "error",
			"分享不存在", "分享已取消", "分享已过期",
		}
		for _, pattern := range errorPatterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				errorFound = true
				errorMsg = pattern
				break
			}
		}
	}
	if errorFound {
		return false, errorMsg, ""
	}
	successFound := false
	switch cloudType {
	case "aliyun", "quark", "uc":
		successPatterns := []string{
			"文件名称", "文件大小", "下载", "保存", "文件名", "大小",
			"download", "save", "file name", "file size",
		}
		for _, pattern := range successPatterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				successFound = true
				break
			}
		}
	default:
		successFound = true
	}
	if !successFound {
		return false, "页面内容异常", ""
	}
	title := extractTitle(content)
	fileSize := extractFileSize(content, cloudType)
	return true, title, fileSize
}

func extractTitle(content string) string {
	matches := titleRegex.FindStringSubmatch(content)
	if len(matches) > 1 {
		title := html.UnescapeString(matches[1])
		title = strings.TrimSpace(title)
		suffixes := []string{"- 百度网盘", "- 阿里云盘", "- 夸克网盘", "- 115网盘", "- 迅雷云盘"}
		for _, suffix := range suffixes {
			title = strings.TrimSuffix(title, suffix)
		}
		return strings.TrimSpace(title)
	}
	return ""
}

func extractFileSize(content, cloudType string) string {
	var sizeRegex *regexp.Regexp
	if regex, exists := fileSizeRegexes[cloudType]; exists {
		sizeRegex = regex
	} else {
		sizeRegex = fileSizeRegexes["default"]
	}
	matches := sizeRegex.FindStringSubmatch(content)
	if len(matches) > 2 {
		return matches[1] + " " + matches[2]
	}
	return ""
}

func (m *LinkCheckTaskManager) batchGetFromDB(urlHashes []string) (map[string]*LinkCheckResult, []string) {
	results := make(map[string]*LinkCheckResult)
	var missingHashes []string
	if len(urlHashes) == 0 {
		return results, missingHashes
	}
	placeholders := make([]string, len(urlHashes))
	args := make([]interface{}, len(urlHashes))
	for i, hash := range urlHashes {
		placeholders[i] = "?"
		args[i] = hash
	}
	query := fmt.Sprintf(`
SELECT url_hash, original_url, cloud_type, is_valid, status, file_info, check_time
FROM link_cache
WHERE url_hash IN (%s)
`, strings.Join(placeholders, ","))
	rows, err := m.db.Query(query, args...)
	if err != nil {
		m.logger.Error("批量查询缓存失败", err)
		return results, urlHashes
	}
	defer rows.Close()
	foundHashes := make(map[string]bool)
	for rows.Next() {
		var result LinkCheckResult
		var urlHash string
		var fileInfo sql.NullString
		err := rows.Scan(&urlHash, &result.URL, &result.CloudType, &result.IsValid, &result.Status, &fileInfo, &result.CheckTime)
		if err != nil {
			m.logger.Error("扫描缓存行失败", err)
			continue
		}
		if fileInfo.Valid {
			var info map[string]interface{}
			if err := json.Unmarshal([]byte(fileInfo.String), &info); err == nil {
				if title, ok := info["title"].(string); ok {
					result.Title = title
				}
				if size, ok := info["size"].(string); ok {
					result.FileSize = size
				}
			}
		}
		if time.Since(result.CheckTime) <= linkCacheTTL {
			results[urlHash] = &result
			foundHashes[urlHash] = true
		}
	}
	for _, hash := range urlHashes {
		if !foundHashes[hash] {
			missingHashes = append(missingHashes, hash)
		}
	}
	return results, missingHashes
}

func (m *LinkCheckTaskManager) getFromDB(urlHash string) (*LinkCheckResult, bool) {
	results, missing := m.batchGetFromDB([]string{urlHash})
	if result, exists := results[urlHash]; exists {
		return result, true
	}
	return nil, len(missing) == 0
}

func (m *LinkCheckTaskManager) batchSetToDB(results []*LinkCheckResult) {
	if len(results) == 0 {
		return
	}
	tx, err := m.db.Begin()
	if err != nil {
		m.logger.Error("开启批量写入事务失败", err)
		return
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
INSERT OR REPLACE INTO link_cache (url_hash, original_url, cloud_type, is_valid, status, file_info, check_time)
VALUES (?, ?, ?, ?, ?, ?, ?)
`)
	if err != nil {
		m.logger.Error("准备批量写入语句失败", err)
		return
	}
	defer stmt.Close()
	for _, result := range results {
		urlHash := fmt.Sprintf("%x", md5.Sum([]byte(result.URL)))
		fileInfo, _ := json.Marshal(map[string]string{"title": result.Title, "size": result.FileSize})
		_, err := stmt.Exec(urlHash, result.URL, result.CloudType, result.IsValid, result.Status, fileInfo, result.CheckTime)
		if err != nil {
			m.logger.Error("批量写入缓存失败", err)
			continue
		}
	}
	if err := tx.Commit(); err != nil {
		m.logger.Error("提交批量写入事务失败", err)
		return
	}
	m.logger.Debug("批量写入 %d 条链接检查缓存", len(results))
}

func (m *LinkCheckTaskManager) setToDB(result *LinkCheckResult) {
	select {
	case m.writeQueue <- result:
	default:
		m.logger.Warn("链接缓存写入队列满，丢弃: %s", result.URL[:60])
	}
}

func (m *LinkCheckTaskManager) asyncDBWriter() {
	const batchSize = 128
	batch := make([]*LinkCheckResult, 0, batchSize)
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		m.batchSetToDB(batch)
		batch = batch[:0]
	}
	for {
		select {
		case res := <-m.writeQueue:
			batch = append(batch, res)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (m *LinkCheckTaskManager) cleanupExpiredDB() {
	_, err := m.db.Exec(`
DELETE FROM link_cache
WHERE check_time < DATETIME('now', '-24 hours')
`)
	if err != nil {
		m.logger.Error("清理过期缓存DB失败", err)
	}
}

func (m *LinkCheckTaskManager) UpdateAPIURL(apiURL string) {
	m.mutex.Lock()
	m.apiURL = apiURL
	m.mutex.Unlock()
	m.logger.Info("链接检查API URL已更新: %s", apiURL)
}

func NewLinkCheckTaskManager(timeout time.Duration, logger *Logger, db *sql.DB, apiURL string, checkMode string) *LinkCheckTaskManager {
	cache := NewSearchCache(defaultCacheCapacity, linkCacheTTL)
	client := &http.Client{
		Timeout:   timeout,
		Transport: globalTransport,
	}
	if checkMode == "" {
		checkMode = "auto"
	}
	validModes := map[string]bool{"auto": true, "pancheck": true, "legacy": true}
	if !validModes[checkMode] {
		logger.Warn("无效的checkMode: %s，使用默认auto", checkMode)
		checkMode = "auto"
	}
	manager := &LinkCheckTaskManager{
		memoryCache: cache,
		timeout:     timeout,
		httpClient:  client,
		logger:      logger,
		db:          db,
		writeQueue:  make(chan *LinkCheckResult, 5000),
		apiURL:      apiURL,
		checkMode:   checkMode,
	}
	go manager.asyncDBWriter()
	go manager.cleanupRoutine()
	logger.Info("链接检查任务管理器初始化完成，模式: %s", checkMode)
	return manager
}

func (m *LinkCheckTaskManager) SetCheckMode(mode string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	validModes := map[string]bool{
		"auto":     true,
		"pancheck": true,
		"legacy":   true,
	}
	if validModes[mode] {
		m.checkMode = mode
		m.logger.Info("链接检查模式已设置为: %s", mode)
	} else {
		m.logger.Warn("无效的检查模式: %s，保持当前模式: %s", mode, m.checkMode)
	}
}

func (m *LinkCheckTaskManager) GetCheckMode() string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.checkMode
}

func (m *LinkCheckTaskManager) cleanupRoutine() {
	ticker := time.NewTicker(linkCacheCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		m.memoryCache.CleanupExpired()
		m.cleanupExpiredDB()
	}
}

const (
	defaultNewLinkCheckAPIURL = "https://pancheck.banye.tech:7777"
)

type NewLinkCheckRequest struct {
	Links             []string `json:"links"`
	SelectedPlatforms []string `json:"selected_platforms,omitempty"`
}

func getSelectedPlatforms() []string {
	return []string{
		"quark",
		"uc",
		"tianyi",
		"pan123",
		"pan115",
		"xunlei",
		"cmcc",
		"baidu",
		"aliyun",
	}
}

type NewLinkCheckResponse struct {
	SubmissionID int      `json:"submission_id"`
	InvalidLinks []string `json:"invalid_links"`
	PendingLinks []string `json:"pending_links"`
	ValidLinks   []string `json:"valid_links"`
	TotalDura    int      `json:"total_dura"`
}

func (m *LinkCheckTaskManager) createDefaultValidResults(urls []string) map[string]*LinkCheckResult {
	results := make(map[string]*LinkCheckResult)
	for _, urlStr := range urls {
		cloudType := mapCloudType("unknown")
		results[urlStr] = &LinkCheckResult{
			URL:       urlStr,
			CloudType: cloudType,
			CheckTime: time.Now(),
			IsValid:   true,
			Status:    "valid",
			Title:     fmt.Sprintf("%s分享", cloudType),
			Error:     "pancheck检测失败，使用默认有效结果",
		}
	}
	return results
}

func (m *LinkCheckTaskManager) batchCheckWithNewAPI(urls []string, apiURL string, httpClient *http.Client, logger *Logger) (map[string]*LinkCheckResult, error) {
	results := make(map[string]*LinkCheckResult)
	if len(urls) == 0 {
		return results, nil
	}
	logger.Info("开始pancheck批量检测: %d 个链接", len(urls))
	requestData := NewLinkCheckRequest{
		Links:             urls,
		SelectedPlatforms: getSelectedPlatforms(),
	}
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		logger.Error("pancheck批量请求JSON编码失败", err)
		return nil, err
	}
	logger.Debug("pancheck批量请求数据: %d 个链接, 平台: %v", len(urls), requestData.SelectedPlatforms)
	finalAPIURL := defaultNewLinkCheckAPIURL
	if apiURL != "" {
		finalAPIURL = apiURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", finalAPIURL+"/api/v1/links/check", bytes.NewReader(jsonData))
	if err != nil {
		logger.Error("创建pancheck批量请求失败", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json")
	startTime := time.Now()
	resp, err := newAPIClient.Do(req)
	if err != nil {
		logger.Error("pancheck批量请求失败", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("读取pancheck批量响应失败", err)
		return nil, err
	}
	requestTime := time.Since(startTime)
	logger.Debug("pancheck批量请求耗时: %v", requestTime)
	if resp.StatusCode != http.StatusOK {
		logger.Warn("pancheck返回非200状态码: %d, 响应: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("API返回状态码: %d", resp.StatusCode)
	}
	var apiResponse NewLinkCheckResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		logger.Error("解析pancheck批量响应失败", err)
		return nil, err
	}
	logger.Info("pancheck批量检测结果: 有效=%d, 无效=%d, 待处理=%d",
		len(apiResponse.ValidLinks), len(apiResponse.InvalidLinks), len(apiResponse.PendingLinks))
	for _, url := range urls {
		cloudType := mapCloudType("unknown")
		result := &LinkCheckResult{
			URL:       url,
			CloudType: cloudType,
			CheckTime: time.Now(),
		}
		if contains(apiResponse.ValidLinks, url) {
			result.IsValid = true
			result.Status = "valid"
			result.Title = fmt.Sprintf("%s分享", cloudType)
		} else if contains(apiResponse.InvalidLinks, url) {
			result.IsValid = false
			result.Status = "invalid"
			result.Error = "链接无效"
		} else if contains(apiResponse.PendingLinks, url) {
			result.IsValid = false
			result.Status = "pending"
			result.Error = "链接检测中"
		} else {
			logger.Warn("链接未在API返回的任何列表中，使用旧方式检测: %s", url)
			legacyResult, err := checkSingleURLAdvanced(url, m, nil, httpClient, logger)
			if err != nil {
				result.IsValid = false
				result.Status = "error"
				result.Error = fmt.Sprintf("旧方式检测失败: %v", err)
			} else {
				result.IsValid = legacyResult.IsValid
				result.Status = legacyResult.Status
				result.Error = legacyResult.Error
				result.Title = legacyResult.Title
			}
		}
		results[url] = result
	}
	validCount := 0
	for _, result := range results {
		if result.IsValid {
			validCount++
		}
	}
	logger.Info("pancheck批量检测完成: 总共=%d, 有效=%d, 耗时=%v", len(urls), validCount, requestTime)
	return results, nil
}

type LinkCheckWorkerPool struct {
	taskChan   chan linkCheckTask
	workers    int
	workerWg   sync.WaitGroup
	ctx        context.Context
	cancelFunc context.CancelFunc
	isRunning  bool
	mu         sync.RWMutex
	logger     *Logger
}

type linkCheckTask struct {
	urlStr     string
	resource   *Resource
	manager    *LinkCheckTaskManager
	httpClient *http.Client
	resultChan chan<- *LinkCheckResult
}

func NewLinkCheckWorkerPool(workers int, logger *Logger) *LinkCheckWorkerPool {
	if workers <= 0 {
		workers = 10
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool := &LinkCheckWorkerPool{
		taskChan:   make(chan linkCheckTask, 1000),
		workers:    workers,
		ctx:        ctx,
		cancelFunc: cancel,
		isRunning:  true,
		logger:     logger,
	}
	logger.Info("正在启动 %d 个链接检查worker...", workers)
	pool.startWorkers()
	logger.Info("链接检查工作池创建完成: workers=%d", workers)
	return pool
}

func (p *LinkCheckWorkerPool) startWorkers() {
	for i := 0; i < p.workers; i++ {
		p.workerWg.Add(1)
		go func(id int) {
			defer p.workerWg.Done()
			p.logger.Debug("链接检查Worker %d 已启动", id)
			for {
				select {
				case <-p.ctx.Done():
					p.logger.Debug("链接检查Worker %d 收到关闭信号，退出", id)
					return
				case task, ok := <-p.taskChan:
					if !ok {
						p.logger.Debug("链接检查Worker %d: taskChan 已关闭，退出", id)
						return
					}
					p.logger.Debug("链接检查Worker %d 处理任务: %s", id, task.urlStr)
					result, err := checkSingleURLAdvanced(task.urlStr, task.manager, task.resource, task.httpClient, p.logger)
					if err != nil {
						p.logger.Debug("链接检查Worker %d 处理失败: %s, 错误: %v", id, task.urlStr, err)
						result = &LinkCheckResult{
							URL:       task.urlStr,
							CloudType: mapCloudType("unknown"),
							CheckTime: time.Now(),
							IsValid:   false,
							Status:    "error",
							Error:     err.Error(),
						}
					}
					select {
					case task.resultChan <- result:
					case <-p.ctx.Done():
						return
					case <-time.After(100 * time.Millisecond):
						p.logger.Warn("链接检查Worker %d: 结果发送超时，已丢弃: %s", id, task.urlStr)
					}
				}
			}
		}(i)
	}
}

func (p *LinkCheckWorkerPool) Submit(urlStr string, resource *Resource, manager *LinkCheckTaskManager, httpClient *http.Client) (*LinkCheckResult, error) {
	p.mu.RLock()
	if !p.isRunning {
		p.mu.RUnlock()
		return nil, errors.New("链接检查工作池已关闭")
	}
	p.mu.RUnlock()

	resultChan := make(chan *LinkCheckResult, 1)
	task := linkCheckTask{
		urlStr:     urlStr,
		resource:   resource,
		manager:    manager,
		httpClient: httpClient,
		resultChan: resultChan,
	}

	select {
	case p.taskChan <- task:
	case <-p.ctx.Done():
		return nil, errors.New("链接检查工作池正在关闭")
	case <-time.After(50 * time.Millisecond):
		return nil, errors.New("任务提交超时（队列满）")
	}

	select {
	case result := <-resultChan:
		return result, nil
	case <-time.After(30 * time.Second):
		return nil, errors.New("任务执行超时")
	case <-p.ctx.Done():
		return nil, errors.New("链接检查工作池已关闭")
	}
}

func (p *LinkCheckWorkerPool) Close() {
	p.mu.Lock()
	if !p.isRunning {
		p.mu.Unlock()
		return
	}
	p.isRunning = false
	p.mu.Unlock()

	p.cancelFunc()
	close(p.taskChan)
	p.workerWg.Wait()
	p.logger.Info("链接检查工作池已优雅关闭")
}

func (m *LinkCheckTaskManager) batchCheckWithLegacy(urls []string, resources []*Resource, httpClient *http.Client, logger *Logger) (map[string]*LinkCheckResult, error) {
	results := make(map[string]*LinkCheckResult)
	if len(urls) == 0 {
		return results, nil
	}
	logger.Info("开始旧方式批量检测: %d 个链接", len(urls))
	resourceMap := make(map[string]*Resource)
	if resources != nil {
		for _, resource := range resources {
			if resource != nil && resource.URL != "" {
				resourceMap[resource.URL] = resource
			}
		}
	}

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(10)

	resultChan := make(chan struct {
		urlStr string
		result *LinkCheckResult
		err    error
	}, len(urls))

	for _, urlStr := range urls {
		urlStr := urlStr
		resource := resourceMap[urlStr]

		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				cloudType := "unknown"
				if resource != nil && resource.CloudType != "" {
					cloudType = mapCloudType(resource.CloudType)
				} else {
					cloudType = mapCloudType("unknown")
				}

				if !legacyCheckTypes[cloudType] {
					result := &LinkCheckResult{
						URL:       urlStr,
						CloudType: cloudType,
						CheckTime: time.Now(),
						IsValid:   true,
						Status:    "valid",
						Title:     fmt.Sprintf("%s分享", cloudType),
					}
					select {
					case resultChan <- struct {
						urlStr string
						result *LinkCheckResult
						err    error
					}{urlStr: urlStr, result: result, err: nil}:
					case <-ctx.Done():
					}
					return nil
				}

				var result *LinkCheckResult
				var err error
				if globalLinkCheckPool != nil {
					result, err = globalLinkCheckPool.Submit(urlStr, resource, m, httpClient)
				} else {
					result, err = checkSingleURLAdvanced(urlStr, m, resource, httpClient, logger)
				}

				select {
				case resultChan <- struct {
					urlStr string
					result *LinkCheckResult
					err    error
				}{urlStr: urlStr, result: result, err: err}:
				case <-ctx.Done():
				}
				return nil
			}
		})
	}

	go func() {
		g.Wait()
		close(resultChan)
	}()

	for res := range resultChan {
		if res.err != nil {
			logger.Debug("旧方式检测链接失败: %s, 错误: %v", res.urlStr, res.err)
			results[res.urlStr] = &LinkCheckResult{
				URL:       res.urlStr,
				CloudType: mapCloudType("unknown"),
				CheckTime: time.Now(),
				IsValid:   false,
				Status:    "error",
				Error:     res.err.Error(),
			}
			continue
		}
		results[res.urlStr] = res.result
	}

	validCount := 0
	for _, result := range results {
		if result.IsValid {
			validCount++
		}
	}
	logger.Info("旧方式批量检测完成: 总共=%d, 有效=%d", len(urls), validCount)
	return results, nil
}

func (m *LinkCheckTaskManager) batchCheckURLsAdvanced(urls []string, resources []*Resource, httpClient *http.Client, logger *Logger) (map[string]*LinkCheckResult, error) {
	results := make(map[string]*LinkCheckResult)
	if len(urls) == 0 {
		return results, nil
	}
	m.mutex.RLock()
	checkMode := m.checkMode
	m.mutex.RUnlock()
	if checkMode == "" {
		checkMode = "auto"
	}
	logger.Info("使用链接检查模式: %s, 链接数量: %d", checkMode, len(urls))
	switch checkMode {
	case "pancheck":
		return m.batchCheckPancheckOnly(urls, resources, httpClient, logger)
	case "legacy":
		return m.batchCheckLegacyOnly(urls, resources, httpClient, logger)
	case "auto":
		fallthrough
	default:
		return m.batchCheckWithAutoFallback(urls, resources, httpClient, logger)
	}
}

func (m *LinkCheckTaskManager) batchCheckPancheckOnly(urls []string, resources []*Resource, httpClient *http.Client, logger *Logger) (map[string]*LinkCheckResult, error) {
	results := make(map[string]*LinkCheckResult)
	resourceMap := make(map[string]*Resource)
	if resources != nil {
		for _, resource := range resources {
			if resource != nil && resource.URL != "" {
				resourceMap[resource.URL] = resource
			}
		}
	}
	var pancheckResults map[string]*LinkCheckResult
	var err error
	for retry := 0; retry < 2; retry++ {
		pancheckResults, err = m.batchCheckWithNewAPIWithRetry(urls, m.apiURL, httpClient, logger)
		if err == nil {
			break
		}
		logger.Warn("pancheck第%d次检测失败: %v", retry+1, err)
		if retry < 1 {
			time.Sleep(time.Duration(retry+1) * 500 * time.Millisecond)
		}
	}
	if err != nil {
		logger.Warn("pancheck检测完全失败，将所有链接标记为有效")
		for _, urlStr := range urls {
			cloudType := mapCloudType("unknown")
			if resource, exists := resourceMap[urlStr]; exists && resource.CloudType != "" {
				cloudType = mapCloudType(resource.CloudType)
			}
			results[urlStr] = &LinkCheckResult{
				URL:       urlStr,
				CloudType: cloudType,
				CheckTime: time.Now(),
				IsValid:   true,
				Status:    "valid",
				Title:     fmt.Sprintf("%s分享", cloudType),
				Error:     "pancheck检测失败，默认标记为有效",
			}
		}
		var toCache []*LinkCheckResult
		for _, result := range results {
			toCache = append(toCache, result)
		}
		m.batchSetToDB(toCache)
		return results, nil
	}
	for _, urlStr := range urls {
		if result, exists := pancheckResults[urlStr]; exists {
			results[urlStr] = result
		} else {
			cloudType := mapCloudType("unknown")
			if resource, exists := resourceMap[urlStr]; exists && resource.CloudType != "" {
				cloudType = mapCloudType(resource.CloudType)
			}
			results[urlStr] = &LinkCheckResult{
				URL:       urlStr,
				CloudType: cloudType,
				CheckTime: time.Now(),
				IsValid:   true,
				Status:    "valid",
				Title:     fmt.Sprintf("%s分享", cloudType),
				Error:     "链接不在pancheck返回结果中，默认标记为有效",
			}
		}
	}
	var toCache []*LinkCheckResult
	for _, result := range results {
		toCache = append(toCache, result)
	}
	m.batchSetToDB(toCache)
	validCount := 0
	for _, result := range results {
		if result.IsValid {
			validCount++
		}
	}
	logger.Info("pancheck-only模式检测完成: 总共=%d, 有效=%d", len(results), validCount)
	return results, nil
}

func (m *LinkCheckTaskManager) batchCheckLegacyOnly(urls []string, resources []*Resource, httpClient *http.Client, logger *Logger) (map[string]*LinkCheckResult, error) {
	results := make(map[string]*LinkCheckResult)
	logger.Info("使用旧方式检测，只检测三种目标网盘: aliym, quark, uc")
	resourceMap := make(map[string]*Resource)
	if resources != nil {
		for _, resource := range resources {
			if resource != nil && resource.URL != "" {
				resourceMap[resource.URL] = resource
			}
		}
	}
	targetCloudTypes := map[string]bool{
		"aliyun": true,
		"quark":  true,
		"uc":     true,
	}

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(10)

	resultChan := make(chan struct {
		urlStr string
		result *LinkCheckResult
		err    error
	}, len(urls))

	for _, urlStr := range urls {
		urlStr := urlStr
		resource := resourceMap[urlStr]

		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				cloudType := "unknown"
				if resource != nil && resource.CloudType != "" {
					cloudType = mapCloudType(resource.CloudType)
				}

				if !targetCloudTypes[cloudType] {
					result := &LinkCheckResult{
						URL:       urlStr,
						CloudType: cloudType,
						CheckTime: time.Now(),
						IsValid:   true,
						Status:    "valid",
						Title:     fmt.Sprintf("%s分享", cloudType),
						Error:     fmt.Sprintf("非目标网盘类型(%s)，默认标记为有效", cloudType),
					}
					select {
					case resultChan <- struct {
						urlStr string
						result *LinkCheckResult
						err    error
					}{urlStr: urlStr, result: result, err: nil}:
					case <-ctx.Done():
					}
					return nil
				}

				var result *LinkCheckResult
				var err error
				if globalLinkCheckPool != nil {
					result, err = globalLinkCheckPool.Submit(urlStr, resource, m, httpClient)
				} else {
					result, err = checkSingleURLAdvanced(urlStr, m, resource, httpClient, logger)
				}

				select {
				case resultChan <- struct {
					urlStr string
					result *LinkCheckResult
					err    error
				}{urlStr: urlStr, result: result, err: err}:
				case <-ctx.Done():
				}
				return nil
			}
		})
	}

	go func() {
		g.Wait()
		close(resultChan)
	}()

	for res := range resultChan {
		if res.err != nil {
			logger.Debug("旧方式检测链接失败: %s, 错误: %v", res.urlStr, res.err)
			results[res.urlStr] = &LinkCheckResult{
				URL:       res.urlStr,
				CloudType: mapCloudType("unknown"),
				CheckTime: time.Now(),
				IsValid:   false,
				Status:    "error",
				Error:     res.err.Error(),
			}
			continue
		}
		results[res.urlStr] = res.result
	}

	var toCache []*LinkCheckResult
	for _, result := range results {
		toCache = append(toCache, result)
	}
	m.batchSetToDB(toCache)
	validCount := 0
	for _, result := range results {
		if result.IsValid {
			validCount++
		}
	}
	logger.Info("legacy-only模式检测完成: 总共=%d, 有效=%d", len(results), validCount)
	return results, nil
}

func (m *LinkCheckTaskManager) batchCheckWithAutoFallback(urls []string, resources []*Resource, httpClient *http.Client, logger *Logger) (map[string]*LinkCheckResult, error) {
	results := make(map[string]*LinkCheckResult)
	if len(urls) == 0 {
		return results, nil
	}
	var newAPIUrls []string
	var otherUrls []string
	resourceMap := make(map[string]*Resource)
	if resources != nil {
		for _, resource := range resources {
			if resource != nil && resource.URL != "" {
				resourceMap[resource.URL] = resource
			}
		}
	}
	supportedPlatforms := getSelectedPlatforms()
	platformSet := make(map[string]bool)
	for _, platform := range supportedPlatforms {
		platformSet[platform] = true
	}
	for _, urlStr := range urls {
		var cloudType string
		if resource, exists := resourceMap[urlStr]; exists && resource.CloudType != "" {
			cloudType = resource.CloudType
			logger.Debug("链接分类: URL=%s, 盘搜云类型=%s", urlStr, cloudType)
		} else {
			cloudType = "unknown"
			logger.Warn("无法获取链接的云类型: %s", urlStr)
		}
		if mappedPlatform, exists := platformMapping[cloudType]; exists {
			if platformSet[mappedPlatform] {
				newAPIUrls = append(newAPIUrls, urlStr)
				logger.Debug("链接 %s 使用pancheck检测，平台: %s", urlStr, mappedPlatform)
			} else {
				otherUrls = append(otherUrls, urlStr)
				logger.Debug("链接 %s 平台 %s 不在支持的平台列表中，使用旧方式", urlStr, mappedPlatform)
			}
		} else {
			otherUrls = append(otherUrls, urlStr)
			logger.Debug("链接 %s 云类型 %s 未在platformMapping中找到，使用旧方式", urlStr, cloudType)
		}
	}
	logger.Info("自动降级模式链接分类: pancheck=%d, 旧方式=%d", len(newAPIUrls), len(otherUrls))
	if len(newAPIUrls) > 0 {
		var newAPIResults map[string]*LinkCheckResult
		var err error
		for retry := 0; retry < 2; retry++ {
			newAPIResults, err = m.batchCheckWithNewAPIWithRetry(newAPIUrls, m.apiURL, httpClient, logger)
			if err == nil {
				break
			}
			logger.Warn("pancheck第%d次检测失败: %v", retry+1, err)
			if retry < 1 {
				time.Sleep(time.Duration(retry+1) * 500 * time.Millisecond)
			}
		}
		if err != nil {
			logger.Warn("pancheck检测失败，回退到旧方式: %v", err)
			fallbackResults, _ := m.batchCheckWithLegacy(newAPIUrls, resources, httpClient, logger)
			for url, result := range fallbackResults {
				results[url] = result
			}
		} else {
			for url, result := range newAPIResults {
				results[url] = result
			}
		}
	}
	if len(otherUrls) > 0 {
		legacyResults, _ := m.batchCheckWithLegacy(otherUrls, resources, httpClient, logger)
		for url, result := range legacyResults {
			results[url] = result
		}
	}
	var toCache []*LinkCheckResult
	for _, result := range results {
		toCache = append(toCache, result)
	}
	if len(toCache) > 0 {
		m.batchSetToDB(toCache)
		for _, result := range toCache {
			urlHash := fmt.Sprintf("%x", md5.Sum([]byte(result.URL)))
			m.memoryCache.SetWithTTL(urlHash, result, linkCacheTTL)
		}
	}
	validCount := 0
	for _, result := range results {
		if result.IsValid {
			validCount++
		}
	}
	logger.Info("自动降级模式检测完成: 总共=%d, 有效=%d, 无效=%d", len(results), validCount, len(results)-validCount)
	return results, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (m *LinkCheckTaskManager) batchCheckWithNewAPIWithRetry(urls []string, apiURL string, httpClient *http.Client, logger *Logger) (map[string]*LinkCheckResult, error) {
	firstResults, err := m.batchCheckWithNewAPI(urls, apiURL, httpClient, logger)
	if err != nil {
		logger.Error("第一次检测失败: %v", err)
		return nil, err
	}
	pendingUrls := m.extractPendingUrls(firstResults)
	if len(pendingUrls) == 0 {
		logger.Info("没有待处理链接，直接返回第一次检测结果")
		return firstResults, nil
	}
	logger.Info("发现 %d 个待处理链接，进行二次复查", len(pendingUrls))
	var pendingUrlsSlice []string
	for url := range pendingUrls {
		pendingUrlsSlice = append(pendingUrlsSlice, url)
	}
	time.Sleep(2 * time.Second)
	secondResults, err := m.batchCheckWithNewAPI(pendingUrlsSlice, apiURL, httpClient, logger)
	if err != nil {
		logger.Warn("待处理链接复查失败: %v，将待处理链接标记为有效", err)
		for url := range pendingUrls {
			if result, exists := firstResults[url]; exists {
				result.IsValid = true
				result.Status = "valid"
				result.Error = "复查失败，默认有效"
				logger.Debug("复查失败，将链接标记为有效: %s", url)
			}
		}
		return firstResults, nil
	}
	mergedResults := make(map[string]*LinkCheckResult)
	for url, result := range firstResults {
		mergedResults[url] = result
	}
	updatedCount := 0
	stillPendingCount := 0
	for url, secondResult := range secondResults {
		if firstResult, exists := mergedResults[url]; exists {
			firstResult.IsValid = secondResult.IsValid
			firstResult.Status = secondResult.Status
			firstResult.Error = secondResult.Error
			firstResult.Title = secondResult.Title
			firstResult.CheckTime = secondResult.CheckTime
			updatedCount++
			if secondResult.Status == "pending" {
				stillPendingCount++
				firstResult.IsValid = true
				firstResult.Status = "valid"
				firstResult.Error = "二次复查后仍待处理，标记为有效"
				logger.Debug("二次复查后仍待处理，标记为有效: %s", url)
			}
		}
	}
	logger.Info("结果合并完成: 更新了 %d 个链接状态，其中 %d 个链接二次复查后仍待处理并标记为有效",
		updatedCount, stillPendingCount)
	finalValidCount := 0
	finalInvalidCount := 0
	for _, result := range mergedResults {
		if result.IsValid {
			finalValidCount++
		} else {
			finalInvalidCount++
		}
	}
	logger.Info("最终检测结果: 总共=%d, 有效=%d, 无效=%d",
		len(mergedResults), finalValidCount, finalInvalidCount)
	return mergedResults, nil
}

func (m *LinkCheckTaskManager) extractPendingUrls(results map[string]*LinkCheckResult) map[string]bool {
	pendingUrls := make(map[string]bool)
	for url, result := range results {
		if result.Status == "pending" || result.Status == "unknown" {
			pendingUrls[url] = true
		}
	}
	return pendingUrls
}

func checkSingleURLAdvanced(urlStr string, manager *LinkCheckTaskManager, resource *Resource, httpClient *http.Client, logger *Logger) (*LinkCheckResult, error) {
	urlHash := fmt.Sprintf("%x", md5.Sum([]byte(urlStr)))
	if v, ok := manager.memoryCache.Get(urlHash); ok {
		return v.(*LinkCheckResult), nil
	}
	if dbRes, ok := manager.getFromDB(urlHash); ok {
		manager.memoryCache.Set(urlHash, dbRes)
		return dbRes, nil
	}
	v, err, _ := linkCheckSingleFlight.Do(urlStr, func() (interface{}, error) {
		cloudType := mapCloudType("unknown")
		if resource != nil && resource.CloudType != "" {
			cloudType = mapCloudType(resource.CloudType)
		}
		if !legacyCheckTypes[cloudType] {
			result := &LinkCheckResult{
				URL:       urlStr,
				CloudType: cloudType,
				CheckTime: time.Now(),
				IsValid:   true,
				Status:    "valid",
				Title:     fmt.Sprintf("%s分享", cloudType),
			}
			manager.memoryCache.Set(urlHash, result)
			manager.setToDB(result)
			return result, nil
		}
		result := &LinkCheckResult{
			URL:       urlStr,
			CloudType: cloudType,
			CheckTime: time.Now(),
		}
		config, exists := cloudCheckConfigs[cloudType]
		if !exists {
			genericResult, err := checkSingleURLGeneric(urlStr, cloudType, httpClient)
			if err != nil {
				return genericResult, err
			}
			manager.memoryCache.SetWithTTL(urlHash, genericResult, linkCacheTTL)
			manager.setToDB(genericResult)
			return genericResult, nil
		}
		logger.Debug("使用高级检查方法检测: %s, 类型: %s", urlStr, cloudType)
		if config.APIURL != "" {
			password := ""
			if resource != nil {
				password = resource.Password
			}
			apiResult, err := checkWithAPI(urlStr, cloudType, config, password, httpClient)
			if err == nil {
				result.IsValid = apiResult.IsValid
				result.Status = apiResult.Status
				result.Title = apiResult.Title
				result.FileSize = apiResult.FileSize
				result.Error = apiResult.Error
				manager.memoryCache.SetWithTTL(urlHash, result, linkCacheTTL)
				manager.setToDB(result)
				return result, nil
			}
			logger.Debug("API检查失败，回退到通用检查: %v", err)
		}
		genericResult, err := checkSingleURLGeneric(urlStr, cloudType, httpClient)
		if err != nil {
			return genericResult, err
		}
		manager.memoryCache.SetWithTTL(urlHash, genericResult, linkCacheTTL)
		manager.setToDB(genericResult)
		return genericResult, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*LinkCheckResult), nil
}

type SearchPipeline struct {
	keyword       string
	channelParams *ChannelParams
	searchType    string
	config        *PipelineConfig
	configManager *ConfigManager
	logger        *Logger
	app           *Application
}

func NewSearchPipeline(keyword string, channelParams *ChannelParams, searchType string, configManager *ConfigManager, logger *Logger, app *Application) *SearchPipeline {
	cfg := configManager.GetConfig()
	if channelParams == nil {
		channelParams = &ChannelParams{
			Types:         []string{},
			Keywords:      []string{},
			Channels:      []string{},
			Plugins:       []string{},
			CheckLinks:    false,
			MaxCheckLinks: 0,
			Include:       []string{},
			Exclude:       []string{},
		}
	}
	return &SearchPipeline{
		keyword:       keyword,
		channelParams: channelParams,
		searchType:    searchType,
		configManager: configManager,
		logger:        logger,
		app:           app,
		config: &PipelineConfig{
			MaxLinksPerType: cfg.MaxLinksPerType,
			CheckLinks:      channelParams.CheckLinks || cfg.LinkCheckEnabled,
			CheckMaxPerType: channelParams.MaxCheckLinks,
			CheckWorkers:    cfg.LinkCheckWorkers,
		},
	}
}

func (p *SearchPipeline) selectTopNPerType(limitedGroups map[string][]*ProcessedResource) []*ProcessedResource {
	var selectedResources []*ProcessedResource
	p.logger.Info("检测数量参数: %d (0表示不限制)", p.channelParams.MaxCheckLinks)
	for cloudType, resources := range limitedGroups {
		if !newAPISupportedTypes[cloudType] {
			p.logger.Debug("类型 %s 为非目标网盘类型，跳过检测", cloudType)
			continue
		}
		if p.channelParams.MaxCheckLinks == 0 {
			for _, resource := range resources {
				if resource.Resource.URL != "" {
					selectedResources = append(selectedResources, resource)
				}
			}
			p.logger.Debug("类型 %s 不限制检测数量，选择全部 %d 条链接进行检查", cloudType, len(resources))
		} else {
			selectedCount := len(resources)
			if len(resources) > p.channelParams.MaxCheckLinks {
				selectedCount = p.channelParams.MaxCheckLinks
				resources = resources[:selectedCount]
			}
			for _, resource := range resources {
				if resource.Resource.URL != "" {
					selectedResources = append(selectedResources, resource)
				}
			}
			p.logger.Debug("为类型 %s 选择 %d 条链接进行检查", cloudType, selectedCount)
		}
	}
	p.logger.Info("总共选择 %d 条链接进行检查", len(selectedResources))
	return selectedResources
}

func (p *SearchPipeline) checkURLsSync(resources []*ProcessedResource, manager *LinkCheckTaskManager) (map[string]*LinkCheckResult, *LinkCheckStats) {
	startTime := time.Now()
	results := make(map[string]*LinkCheckResult)
	stats := &LinkCheckStats{
		Total:       len(resources),
		Valid:       0,
		Invalid:     0,
		Error:       0,
		Password:    0,
		ByCloudType: make(map[string]map[string]int),
	}
	if len(resources) == 0 {
		return results, stats
	}
	urls := make([]string, len(resources))
	resourcePtrs := make([]*Resource, len(resources))
	for i, pr := range resources {
		urls[i] = pr.Resource.URL
		resourcePtrs[i] = pr.Resource
	}
	checkResults, err := manager.batchCheckURLsAdvanced(urls, resourcePtrs, manager.httpClient, p.logger)
	if err != nil {
		p.logger.Error("批量链接检查失败", err)
		return p.fallbackSingleCheck(resources, manager, stats, startTime)
	}
	for _, pr := range resources {
		if result, exists := checkResults[pr.Resource.URL]; exists {
			results[pr.Resource.URL] = result
			if _, exists := stats.ByCloudType[pr.CloudType]; !exists {
				stats.ByCloudType[pr.CloudType] = map[string]int{
					"valid":   0,
					"invalid": 0,
					"error":   0,
				}
			}
			switch result.Status {
			case "valid":
				stats.Valid++
				stats.ByCloudType[pr.CloudType]["valid"]++
				if result.Password != "" {
					stats.Password++
				}
				p.logger.Debug("链接有效: %s, 标题: %s", pr.Resource.URL, result.Title)
			case "invalid":
				stats.Invalid++
				stats.ByCloudType[pr.CloudType]["invalid"]++
				p.logger.Debug("链接无效: %s, 原因: %s", pr.Resource.URL, result.Error)
			case "error":
				stats.Error++
				stats.ByCloudType[pr.CloudType]["error"]++
				p.logger.Debug("检查错误: %s, 错误: %s", pr.Resource.URL, result.Error)
			}
		}
	}
	stats.Duration = time.Since(startTime)
	p.logger.Info("链接检查完成: 总共=%d, 有效=%d, 无效=%d, 错误=%d, 有密码=%d, 耗时=%v",
		stats.Total, stats.Valid, stats.Invalid, stats.Error, stats.Password, stats.Duration)
	return results, stats
}

func (p *SearchPipeline) fallbackSingleCheck(resources []*ProcessedResource, manager *LinkCheckTaskManager, stats *LinkCheckStats, startTime time.Time) (map[string]*LinkCheckResult, *LinkCheckStats) {
	results := make(map[string]*LinkCheckResult)
	type checkResult struct {
		pr     *ProcessedResource
		result *LinkCheckResult
		err    error
	}
	resultChan := make(chan checkResult, len(resources))
	jobChan := make(chan *ProcessedResource, len(resources))
	for _, r := range resources {
		jobChan <- r
	}
	close(jobChan)
	var wg sync.WaitGroup
	workers := p.config.CheckWorkers
	if workers <= 0 {
		workers = 10
	}
	p.logger.Info("使用单条检查降级方案，总数: %d, Workers: %d", len(resources), workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pr := range jobChan {
				result, err := checkSingleURLAdvanced(pr.Resource.URL, manager, pr.Resource, manager.httpClient, p.logger)
				resultChan <- checkResult{pr: pr, result: result, err: err}
			}
		}()
	}
	wg.Wait()
	close(resultChan)
	for res := range resultChan {
		var finalResult *LinkCheckResult
		if res.err != nil {
			finalResult = &LinkCheckResult{
				URL:       res.pr.Resource.URL,
				IsValid:   false,
				Status:    "error",
				Error:     res.err.Error(),
				CloudType: res.pr.CloudType,
				CheckTime: time.Now(),
			}
		} else {
			finalResult = res.result
		}
		results[res.pr.Resource.URL] = finalResult
		if _, exists := stats.ByCloudType[res.pr.CloudType]; !exists {
			stats.ByCloudType[res.pr.CloudType] = map[string]int{
				"valid":   0,
				"invalid": 0,
				"error":   0,
			}
		}
		switch finalResult.Status {
		case "valid":
			stats.Valid++
			stats.ByCloudType[res.pr.CloudType]["valid"]++
			if finalResult.Password != "" {
				stats.Password++
			}
			p.logger.Debug("链接有效: %s, 标题: %s", res.pr.Resource.URL, finalResult.Title)
		case "invalid":
			stats.Invalid++
			stats.ByCloudType[res.pr.CloudType]["invalid"]++
			p.logger.Debug("链接无效: %s, 原因: %s", res.pr.Resource.URL, finalResult.Error)
		case "error":
			stats.Error++
			stats.ByCloudType[res.pr.CloudType]["error"]++
			p.logger.Debug("检查错误: %s, 错误: %s", res.pr.Resource.URL, finalResult.Error)
		}
	}
	stats.Duration = time.Since(startTime)
	p.logger.Info("链接检查完成(降级模式): 总共=%d, 有效=%d, 无效=%d, 错误=%d, 有密码=%d, 耗时=%v",
		stats.Total, stats.Valid, stats.Invalid, stats.Error, stats.Password, stats.Duration)
	return results, stats
}

func (p *SearchPipeline) filterInvalidResources(limitedGroups map[string][]*ProcessedResource, checkResults map[string]*LinkCheckResult) {
	for cloudType, resources := range limitedGroups {
		var validResources []*ProcessedResource
		undetectedCount := 0
		if newAPISupportedTypes[cloudType] {
			for _, resource := range resources {
				if result, exists := checkResults[resource.Resource.URL]; exists {
					if result.IsValid {
						validResources = append(validResources, resource)
						p.logger.Debug("保留有效链接: %s (%s)", resource.Resource.URL, cloudType)
					} else {
						p.logger.Debug("过滤无效链接: %s (%s), 状态: %s", resource.Resource.URL, cloudType, result.Status)
					}
				} else {
					validResources = append(validResources, resource)
					undetectedCount++
					p.logger.Debug("保留未检测链接: %s (%s)", resource.Resource.URL, cloudType)
				}
			}
			limitedGroups[cloudType] = validResources
			p.logger.Info("类型 %s 过滤后剩余 %d 条有效资源 (包含 %d 条未检测资源)",
				cloudType, len(validResources), undetectedCount)
		} else {
			p.logger.Info("类型 %s 为非检测类型，保留全部 %d 条资源", cloudType, len(resources))
		}
	}
}

func (p *SearchPipeline) processPG(linkCheckManager *LinkCheckTaskManager) (*PipelineResult, error) {
	p.logger.Info("开始PG格式处理流程")
	startTime := time.Now()

	cfg := p.configManager.GetConfig()
	if shouldBlockKeyword(p.keyword, cfg, p.logger) {
		p.logger.Info("PG搜索被屏蔽: 关键词=%s", p.keyword)
		return &PipelineResult{
			SearchResults:     "",
			CheckStats:        nil,
			ProcessingTime:    time.Since(startTime),
			TotalResources:    0,
			FilteredResources: 0,
		}, nil
	}

	p.logger.Info("PG阶段1: 调用盘搜API")
	allRes, globalDefaultImage, err := ProcessPansouDataWithChannelParams(
		p.keyword, p.channelParams, p.getCloudTypes("pg"), p.configManager, p.logger, p.app.loadBalancer, p.app.pansouClient)
	if err != nil {
		return nil, err
	}
	p.logger.Info("PG搜索完成: 获取%d条资源", len(allRes))
	p.logger.Info("PG阶段2: 分组排序并限制每类%d条", p.config.MaxLinksPerType)
	limitedGroups, cloudOrder := ProcessResourcesWithLimit(allRes, p.getCloudTypes("pg"), p.config.MaxLinksPerType, p.logger)
	p.logger.Info("PG分组完成: %d种网盘类型", len(limitedGroups))
	var checkStats *LinkCheckStats
	if p.config.CheckLinks && linkCheckManager != nil {
		p.logger.Info("PG阶段3: 选择目标网盘类型的所有链接进行检查")
		selectedResources := p.selectTopNPerType(limitedGroups)
		p.logger.Info("PG选择完成: 共选择%d条链接进行检查", len(selectedResources))
		if len(selectedResources) > 0 {
			checkResults, stats := p.checkURLsSync(selectedResources, linkCheckManager)
			checkStats = stats
			p.logger.Info("PG链接检查完成: 总共检查%d条, 有效%d条, 无效%d条, 错误%d条",
				stats.Total, stats.Valid, stats.Invalid, stats.Error)
			p.filterInvalidResources(limitedGroups, checkResults)
			for _, resources := range limitedGroups {
				for _, resource := range resources {
					if strings.Contains(resource.Resource.URL, "123") {
						originalURL := resource.Resource.URL
						repairedURL := ensure123URLWithWWW(originalURL)
						if repairedURL != originalURL {
							p.logger.Debug("检测后修复123链接: %s -> %s", originalURL, repairedURL)
							resource.Resource.URL = repairedURL
						}
					}
				}
			}
		}
	}
	p.logger.Info("PG阶段4: 转换为PG格式")
	finalResources := p.prepareFinalPGResources(limitedGroups, cloudOrder)
	pgOutput := p.buildPGOutput(finalResources, globalDefaultImage)
	processingTime := time.Since(startTime)
	return &PipelineResult{
		SearchResults:     pgOutput,
		CheckStats:        checkStats,
		ProcessingTime:    processingTime,
		TotalResources:    len(allRes),
		FilteredResources: len(finalResources),
	}, nil
}

func (p *SearchPipeline) prepareFinalPGResources(limitedGroups map[string][]*ProcessedResource, cloudOrder []string) []*ProcessedResource {
	var finalResources []*ProcessedResource
	seen := make(map[string]bool)
	for _, cloudType := range cloudOrder {
		if resources, exists := limitedGroups[cloudType]; exists {
			finalResources = append(finalResources, resources...)
			seen[cloudType] = true
		}
	}
	for cloudType, resources := range limitedGroups {
		if !seen[cloudType] {
			finalResources = append(finalResources, resources...)
		}
	}
	p.logger.Info("PG最终资源准备完成: %d条资源", len(finalResources))
	return finalResources
}

func (p *SearchPipeline) buildPGOutput(resources []*ProcessedResource, globalDefaultImage string) string {
	var messages []string
	for _, pr := range resources {
		msg := buildPGMessage(*pr.Resource, pr.ParsedTime, globalDefaultImage, pr.CleanedSource, p.configManager)
		if msg != "" {
			messages = append(messages, msg)
		}
	}
	result := strings.Join(messages, "\n")
	p.logger.Info("PG输出构建完成: %d条消息", len(messages))
	return result
}

func (p *SearchPipeline) processZX(linkCheckManager *LinkCheckTaskManager) (*PipelineResult, error) {
	p.logger.Info("开始ZX格式处理流程")
	startTime := time.Now()

	cfg := p.configManager.GetConfig()
	if shouldBlockKeyword(p.keyword, cfg, p.logger) {
		p.logger.Info("ZX搜索被屏蔽: 关键词=%s", p.keyword)
		return &PipelineResult{
			SearchResults:     &ZXResponse{Results: []string{}},
			CheckStats:        nil,
			ProcessingTime:    time.Since(startTime),
			TotalResources:    0,
			FilteredResources: 0,
		}, nil
	}

	p.logger.Info("ZX阶段1: 调用盘搜API")
	allRes, globalDefaultImage, err := ProcessPansouDataWithChannelParams(
		p.keyword, p.channelParams, p.getCloudTypes("zx"), p.configManager, p.logger, p.app.loadBalancer, p.app.pansouClient)
	if err != nil {
		return nil, err
	}
	p.logger.Info("ZX搜索完成: 获取%d条资源", len(allRes))
	p.logger.Info("ZX阶段2: 分组排序并限制每类%d条", p.config.MaxLinksPerType)
	limitedGroups, _ := ProcessResourcesWithLimit(allRes, p.getCloudTypes("zx"), p.config.MaxLinksPerType, p.logger)
	p.logger.Info("ZX分组完成: %d种网盘类型", len(limitedGroups))
	var checkStats *LinkCheckStats
	if p.config.CheckLinks && linkCheckManager != nil {
		p.logger.Info("ZX阶段3: 选择目标网盘类型的所有链接进行检查")
		selectedResources := p.selectTopNPerType(limitedGroups)
		p.logger.Info("ZX选择完成: 共选择%d条链接进行检查", len(selectedResources))
		if len(selectedResources) > 0 {
			checkResults, stats := p.checkURLsSync(selectedResources, linkCheckManager)
			checkStats = stats
			p.logger.Info("ZX链接检查完成: 总共检查%d条, 有效%d条, 无效%d条, 错误%d条",
				stats.Total, stats.Valid, stats.Invalid, stats.Error)
			p.filterInvalidResources(limitedGroups, checkResults)
			for _, resources := range limitedGroups {
				for _, resource := range resources {
					if strings.Contains(resource.Resource.URL, "123") {
						originalURL := resource.Resource.URL
						repairedURL := ensure123URLWithWWW(originalURL)
						if repairedURL != originalURL {
							p.logger.Debug("检测后修复123链接: %s -> %s", originalURL, repairedURL)
							resource.Resource.URL = repairedURL
						}
					}
				}
			}
		}
	}
	p.logger.Info("ZX阶段4: 最终排序和格式转换")
	zxOutput := p.buildZXOutput(limitedGroups, globalDefaultImage)
	processingTime := time.Since(startTime)
	return &PipelineResult{
		SearchResults:     zxOutput,
		CheckStats:        checkStats,
		ProcessingTime:    processingTime,
		TotalResources:    len(allRes),
		FilteredResources: p.countZXResources(limitedGroups),
	}, nil
}

func (p *SearchPipeline) buildZXOutput(limitedGroups map[string][]*ProcessedResource, globalDefaultImage string) *ZXResponse {
	var allResources []*ProcessedResource
	totalCount := 0
	for cloudType, resources := range limitedGroups {
		allResources = append(allResources, resources...)
		totalCount += len(resources)
		p.logger.Info("类型 %s 有 %d 条资源", cloudType, len(resources))
	}
	p.logger.Info("构建ZX输出前总资源数: %d", totalCount)
	p.logger.Info("排序前资源数: %d", len(allResources))
	p.sortResourcesByTime(allResources)
	cfg := p.configManager.GetConfig()
	proxyBase := fmt.Sprintf("http://localhost:%d/api/proxy/", cfg.ServerPort)
	zxGroups := make(map[string][]string)
	var groupOrder []string
	seenGroups := make(map[string]bool)
	validResourceCount := 0
	for _, pr := range allResources {
		r := pr.Resource
		if r.URL == "" {
			continue
		}
		u := strings.TrimSuffix(r.URL, "#")
		date := getMonthDayFromTime(pr.ParsedTime)
		source := pr.CleanedSource
		key := source
		if date != "" {
			key = date + "|" + source
		}
		var img string
		if len(r.Images) > 0 && r.Images[0] != "" {
			img = r.Images[0]
		} else if globalDefaultImage != "" {
			img = globalDefaultImage
		}
		finalImg := getImageURL(img, proxyBase, cfg.ZXImageProxyMode)
		line := u
		if finalImg != "" {
			line += "@" + finalImg
		}
		line += "$$" + cleanTitle(r.Note)
		zxGroups[key] = append(zxGroups[key], line)
		if !seenGroups[key] {
			groupOrder = append(groupOrder, key)
			seenGroups[key] = true
		}
		validResourceCount++
	}
	p.logger.Info("有效资源数（URL不为空）: %d", validResourceCount)
	var results []string
	var sb strings.Builder
	for _, k := range groupOrder {
		if lines := zxGroups[k]; len(lines) > 0 {
			sb.Reset()
			sb.WriteString(k)
			sb.WriteString("$$$")
			for i, line := range lines {
				if i > 0 {
					sb.WriteString("##")
				}
				sb.WriteString(line)
			}
			results = append(results, sb.String())
		}
	}
	p.logger.Info("ZX输出构建完成: %d组资源, 总行数: %d", len(results), validResourceCount)
	return &ZXResponse{Results: results}
}

func (p *SearchPipeline) sortResourcesByTime(resources []*ProcessedResource) {
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].ParsedTime.After(resources[j].ParsedTime)
	})
}

func (p *SearchPipeline) countZXResources(limitedGroups map[string][]*ProcessedResource) int {
	count := 0
	for _, resources := range limitedGroups {
		count += len(resources)
	}
	return count
}

func (p *SearchPipeline) getCloudTypes(searchType string) string {
	cfg := p.configManager.GetConfig()
	if searchType == "pg" {
		return cfg.PGCloudTypes
	}
	return cfg.ZXCloudTypes
}

type PGMessageData struct {
	MonthDay      string
	CleanedSource string
	ImgHTML       template.HTML
	URLEsc        string
	NoteEsc       string
}

func buildPGMessage(res Resource, parsedTime time.Time, globalDefaultImage, cleanedSrc string, configManager *ConfigManager) string {
	data := PGMessageData{
		MonthDay:      getMonthDayFromTime(parsedTime),
		CleanedSource: cleanedSrc,
		URLEsc:        html.EscapeString(res.URL),
		NoteEsc:       html.EscapeString(strings.TrimSpace(res.Note)),
	}
	var imgURL string
	if len(res.Images) > 0 && res.Images[0] != "" {
		imgURL = res.Images[0]
	} else if globalDefaultImage != "" {
		imgURL = globalDefaultImage
	}
	cfg := configManager.GetConfig()
	proxyBase := fmt.Sprintf("http://localhost:%d/api/proxy/", cfg.ServerPort)
	finalImgURL := getImageURL(imgURL, proxyBase, cfg.PGImageProxyMode)
	if finalImgURL != "" {
		data.ImgHTML = template.HTML(fmt.Sprintf(
			` <a class="tgme_widget_message_photo_wrap" href="%s" style="width:270px;background-image:url('%s')"><div class="tgme_widget_message_photo" style="width:100%%;padding-top:56.25%%"></div></a>`,
			html.EscapeString(res.URL), html.EscapeString(finalImgURL),
		))
	}
	buf := getBuffer()
	defer putBuffer(buf)
	if configManager.app != nil && configManager.app.pgMessageTmpl != nil {
		if err := configManager.app.pgMessageTmpl.Execute(buf, data); err != nil {
			log.Printf("[ERROR] 模板执行失败: %v", err)
			return ""
		}
	} else {
		log.Printf("[ERROR] 模板未初始化")
		return ""
	}
	return spaceCleanupRegexp.ReplaceAllString(buf.String(), " ")
}

func (app *Application) handleGetAllStatsData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := app.metricsManager.GetMultipleTimeRangeStats(StandardTimeRanges)
	blacklist := app.blacklistManager.GetBlacklist()
	sort.Slice(blacklist, func(i, j int) bool {
		if blacklist[i].Type == "manual" && blacklist[j].Type != "manual" {
			return true
		}
		if blacklist[i].Type != "manual" && blacklist[j].Type == "manual" {
			return false
		}
		return blacklist[i].Value < blacklist[j].Value
	})
	responseData := map[string]interface{}{
		"stats":      stats,
		"blacklist":  blacklist,
		"timeRanges": StandardTimeRanges,
	}
	if err := json.NewEncoder(w).Encode(responseData); err != nil {
		app.logger.Error("编码统计数据失败", err)
		http.Error(w, "Failed to encode data", http.StatusInternalServerError)
	}
}

func (app *Application) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	healthStatus := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
		"services": map[string]string{
			"api":           "running",
			"worker_pool":   "running",
			"load_balancer": "running",
			"geoip":         "running",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(healthStatus)
}

func (app *Application) handleRoot(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if app.passwordProtectionManager.IsPermanentlyBlocked(clientIP) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>访问被拒绝</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #d32f2f; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 访问被拒绝</h1>
        <p>您的IP地址 %s 因多次尝试错误密码已被永久封禁。</p>
        <p>如果您认为这是个错误，请联系网站管理员。</p>
    </div>
</body>
</html>`, clientIP)
		return
	}
	hasSearchParams := r.URL.Query().Get("keyword") != "" || r.URL.Query().Get("q") != ""
	if hasSearchParams {
		app.handleZXSearch(w, r)
		return
	}
	if r.Method == http.MethodPost {
		_ = r.FormValue("password")
		isBlocked := app.passwordProtectionManager.RecordAttempt(clientIP)
		if isBlocked {
			app.blacklistManager.Block(clientIP, "ip", 0, "密码尝试次数过多")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>访问被拒绝</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #d32f2f; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 访问被拒绝</h1>
        <p>您的IP地址 %s 因多次尝试错误密码已被永久封禁。</p>
        <p>如果您认为这是个错误，请联系网站管理员。</p>
    </div>
</body>
</html>`, clientIP)
			return
		}
		remainingAttempts := 10 - app.passwordProtectionManager.GetAttempts(clientIP)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>密码错误</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .container { max-width: 400px; margin: 0 auto; }
        .error { color: #d32f2f; margin: 20px 0; }
        input[type="password"] { 
            width: 100%%; 
            padding: 12px; 
            margin: 10px 0; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            box-sizing: border-box;
        }
        button { 
            background: #2196F3; 
            color: white; 
            border: none; 
            padding: 12px 24px; 
            border-radius: 4px; 
            cursor: pointer; 
            width: 100%%;
        }
        button:hover { background: #1976D2; }
        .attempts { color: #666; margin-top: 10px; font-size: 14px; }
        .search-link { margin-top: 20px; }
        .search-link a { color: #2196F3; text-decoration: none; }
        .search-link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 需要密码</h1>
        <div class="error">密码错误！</div>
        <p>剩余尝试次数: %d</p>
        <form method="post">
            <input type="password" name="password" placeholder="请输入密码" required>
            <button type="submit">提交</button>
        </form>
        <div class="attempts">注意: 连续10次错误密码将导致IP被永久封禁</div>
    </div>
</body>
</html>`, remainingAttempts)
		return
	}
	attempts := app.passwordProtectionManager.GetAttempts(clientIP)
	remainingAttempts := 10 - attempts
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>需要密码</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .container { max-width: 400px; margin: 0 auto; }
        input[type="password"] { 
            width: 100%%; 
            padding: 12px; 
            margin: 10px 0; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            box-sizing: border-box;
        }
        button { 
            background: #2196F3; 
            color: white; 
            border: none; 
            padding: 12px 24px; 
            border-radius: 4px; 
            cursor: pointer; 
            width: 100%%;
        }
        button:hover { background: #1976D2; }
        .attempts { color: #666; margin-top: 10px; font-size: 14px; }
        .search-link { margin-top: 20px; }
        .search-link a { color: #2196F3; text-decoration: none; }
        .search-link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 需要密码</h1>
        <p>请输入密码以访问此页面</p>
        <form method="post">
            <input type="password" name="password" placeholder="请输入密码" required>
            <button type="submit">提交</button>
        </form>
        <div class="attempts">剩余尝试次数: %d</div>
    </div>
</body>
</html>`, remainingAttempts)
}

func (app *Application) handleZXSearch(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	var keyword string
	keyword = r.URL.Query().Get("keyword")
	if keyword == "" {
		keyword = r.URL.Query().Get("q")
	}
	if keyword == "" && r.Method == http.MethodPost {
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			body, err := io.ReadAll(r.Body)
			if err == nil {
				r.Body = io.NopCloser(bytes.NewReader(body))
				var req SearchRequest
				if json.Unmarshal(body, &req) == nil {
					if req.Keyword != "" {
						keyword = req.Keyword
					} else if req.Q != "" {
						keyword = req.Q
					}
				}
			}
		} else {
			if err := r.ParseForm(); err == nil {
				keyword = r.FormValue("keyword")
				if keyword == "" {
					keyword = r.FormValue("q")
				}
			}
		}
	}
	var channelParams *ChannelParams
	if channelUsername := r.URL.Query().Get("channelUsername"); channelUsername != "" {
		channelParams = parseChannelParams(channelUsername, app.logger)
	}
	if channelParams == nil {
		channelParams = &ChannelParams{
			Types:         []string{},
			Keywords:      []string{},
			Channels:      []string{},
			Plugins:       []string{},
			CheckLinks:    false,
			MaxCheckLinks: 0,
			Include:       []string{},
			Exclude:       []string{},
		}
	}
	if keyword != "" {
		r.Header.Set("X-Search-Term", keyword)
	}
	if keyword == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(&ZXResponse{})
		return
	}
	app.logger.Info("ZX搜索 - 关键词: %s, 检测链接: %v, 检测数量: %d",
		keyword, channelParams.CheckLinks, channelParams.MaxCheckLinks)
	zxWork := func(kw string) (interface{}, error) {
		pipeline := NewSearchPipeline(kw, channelParams, "zx", app.configManager, app.logger, app)
		result, err := pipeline.processZX(app.linkCheckManager)
		if err != nil {
			return nil, err
		}
		return result.SearchResults, nil
	}
	result, err := app.GetWorkerPool().SubmitOptimized(keyword, zxWork)
	if err != nil {
		app.logger.Error("ZX搜索 - Worker池错误", err)
		sendErrorResponse(w, http.StatusServiceUnavailable, "Service Unavailable")
		return
	}
	if result.Err != nil {
		app.logger.Error("ZX搜索 - 核心逻辑错误", result.Err)
		sendErrorResponse(w, http.StatusBadGateway, "Bad Gateway")
		return
	}
	processingTime := time.Since(startTime)
	app.logger.Info("ZX搜索完成 - 关键词: %s, 耗时: %v", keyword, processingTime)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(result.Data)
}

func (app *Application) handleLoadBalancerStatus(w http.ResponseWriter, r *http.Request) {
	if app.loadBalancer == nil {
		sendJSONResponse(w, map[string]interface{}{
			"success": false,
			"message": "负载均衡器未启用",
		})
		return
	}
	stats := app.loadBalancer.GetServerStats()
	sendJSONResponse(w, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

func (app *Application) handleStatsPage(w http.ResponseWriter, r *http.Request) {
	if app.statsTmpl == nil {
		app.logger.Error("统计模板未初始化", nil)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := app.statsTmpl.Execute(w, nil); err != nil {
		app.logger.Error("执行统计模板失败", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (app *Application) handleGetStatsData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	timeRange := r.URL.Query().Get("range")
	stats := app.metricsManager.GetAggregatedStats(timeRange)
	blacklist := app.blacklistManager.GetBlacklist()
	sort.Slice(blacklist, func(i, j int) bool {
		if blacklist[i].Type == "manual" && blacklist[j].Type != "manual" {
			return true
		}
		if blacklist[i].Type != "manual" && blacklist[j].Type == "manual" {
			return false
		}
		return blacklist[i].Value < blacklist[j].Value
	})
	responseData := map[string]interface{}{
		"stats":     stats,
		"blacklist": blacklist,
	}
	if err := json.NewEncoder(w).Encode(responseData); err != nil {
		app.logger.Error("编码统计数据失败", err)
		http.Error(w, "Failed to encode data", http.StatusInternalServerError)
	}
}

func (app *Application) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var data BlockRequest
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		sendErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	validTypes := map[string]bool{
		"ip":         true,
		"user_agent": true,
		"region":     true,
		"city":       true,
	}
	if !validTypes[data.Type] {
		sendErrorResponse(w, http.StatusBadRequest, "Invalid block type")
		return
	}
	if data.Value == "" {
		sendErrorResponse(w, http.StatusBadRequest, "Value is required")
		return
	}
	if data.Type == "ip" && net.ParseIP(data.Value) == nil {
		sendErrorResponse(w, http.StatusBadRequest, "Invalid IP address format")
		return
	}
	var duration time.Duration
	rawDuration := strings.ToLower(strings.TrimSpace(data.Duration))
	if rawDuration == "permanent" || rawDuration == "0" || rawDuration == "" {
		duration = 0
	} else if strings.HasSuffix(rawDuration, "d") {
		daysStr := strings.TrimSuffix(rawDuration, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Invalid day format (e.g., 7d)")
			return
		}
		duration = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		duration, err = time.ParseDuration(data.Duration)
		if err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Invalid duration format (e.g., 1h, 7d, permanent)")
			return
		}
	}
	reason := data.Reason
	if reason == "" {
		reason = "手动封禁"
	}
	app.blacklistManager.Block(data.Value, data.Type, duration, reason)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("%s %s has been blocked for %s", data.Type, data.Value, data.Duration),
	})
}

func (app *Application) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var data struct {
		Value string `json:"value"`
		Type  string `json:"type,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		sendErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	var success bool
	if data.Type != "" {
		success = app.blacklistManager.UnblockByTypeAndValue(data.Type, data.Value)
	} else {
		success = app.blacklistManager.UnblockByValue(data.Value)
	}
	if success {
		w.WriteHeader(http.StatusOK)
		if data.Type != "" {
			json.NewEncoder(w).Encode(map[string]string{
				"message": fmt.Sprintf("%s %s has been unblocked", data.Type, data.Value),
			})
		} else {
			json.NewEncoder(w).Encode(map[string]string{
				"message": fmt.Sprintf("%s has been unblocked from all types", data.Value),
			})
		}
	} else {
		sendErrorResponse(w, http.StatusNotFound, "Value not found in blacklist")
	}
}

func (app *Application) handleBlacklistStats(w http.ResponseWriter, r *http.Request) {
	stats := app.blacklistManager.GetBlockedCount()
	sendJSONResponse(w, map[string]interface{}{
		"success": true,
		"stats":   stats,
	})
}

func (app *Application) handlePGSearch(w http.ResponseWriter, r *http.Request) {
	app.logger.Info("PG搜索请求: %s %s", r.Method, r.URL.String())
	if r.Method != http.MethodPost {
		sendErrorResponse(w, http.StatusMethodNotAllowed, "仅支持POST")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendErrorResponse(w, http.StatusBadRequest, "读取请求体失败")
		return
	}
	r.Body.Close()
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		app.logger.Debug("非base64请求体，直接使用原文: %s", string(body))
		decoded = body
	} else {
		app.logger.Debug("成功解码base64请求体: %s", string(decoded))
	}
	var req struct {
		Keyword         string `json:"keyword"`
		Q               string `json:"q"`
		ChannelUsername string `json:"channelUsername"`
	}
	if err := json.Unmarshal(decoded, &req); err != nil {
		app.logger.Error("解析请求JSON失败: %v, 内容: %s", err, string(decoded))
		sendErrorResponse(w, http.StatusBadRequest, "无效的请求格式")
		return
	}
	keyword := req.Keyword
	if keyword == "" {
		keyword = req.Q
	}
	if keyword == "" {
		sendErrorResponse(w, http.StatusBadRequest, "缺少关键词")
		return
	}
	channelParams := &ChannelParams{
		MaxCheckLinks: 0,
	}
	if req.ChannelUsername != "" {
		app.logger.Debug("检测到channelUsername参数: %s", req.ChannelUsername)
		channelParams = parseChannelParams(req.ChannelUsername, app.logger)
	}
	app.logger.Info("PG搜索解析完成 → 关键词: [%s], 参数: %+v", keyword, channelParams)
	r.Header.Set("X-Search-Term", keyword)
	pgWork := func(kw string) (interface{}, error) {
		pipeline := NewSearchPipeline(kw, channelParams, "pg", app.configManager, app.logger, app)
		result, err := pipeline.processPG(app.linkCheckManager)
		if err != nil {
			return "", err
		}
		return result.SearchResults, nil
	}
	result, err := app.GetWorkerPool().SubmitOptimized(keyword, pgWork)
	if err != nil {
		app.logger.Error("Worker池错误", err)
		sendErrorResponse(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}
	if result.Err != nil {
		app.logger.Error("搜索核心逻辑错误", result.Err)
		sendErrorResponse(w, http.StatusBadGateway, "搜索失败")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(result.Data.(string)))
}

func (app *Application) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	app.logger.Info("配置设置请求: %s %s", r.Method, r.URL.String())
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
	w.Header().Set("Access-Control-Max-Age", "86400")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		sendErrorResponse(w, http.StatusMethodNotAllowed, "仅支持POST方法")
		return
	}
	var updates map[string]string
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "解析表单失败")
			return
		}
		updates = make(map[string]string)
		for key, vals := range r.Form {
			if len(vals) > 0 {
				updates[key] = vals[0]
			}
		}
	} else if strings.Contains(contentType, "application/json") {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "读取请求体失败")
			return
		}
		if err := json.Unmarshal(body, &updates); err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "解析JSON失败")
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "解析表单失败")
			return
		}
		updates = make(map[string]string)
		for key, vals := range r.Form {
			if len(vals) > 0 {
				updates[key] = vals[0]
			}
		}
	}
	if len(updates) == 0 {
		sendErrorResponse(w, http.StatusBadRequest, "无配置参数")
		return
	}
	app.logger.Info("收到配置更新请求: %v", updates)
	results := app.configManager.UpdateConfigOptimized(updates)
	response := map[string]interface{}{
		"success":   true,
		"message":   "配置更新完成",
		"results":   results,
		"timestamp": getISONow(),
	}
	app.logger.Info("返回配置更新响应: 成功=%v, 结果数=%d", response["success"], len(results))
	sendJSONResponse(w, response)
}

func (app *Application) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	cfg := app.configManager.GetConfig()
	workerPool := app.GetWorkerPool()
	workerPoolStatus := map[string]interface{}{
		"is_healthy": workerPool != nil && workerPool.isRunning,
		"workers":    workerPool.workers,
		"timeout":    workerPool.timeout.String(),
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"config":      cfg,
		"worker_pool": workerPoolStatus,
		"timestamp":   getISONow(),
	})
}

func (app *Application) handleResetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	app.configManager.ResetConfig()
	cfg := app.configManager.GetConfig()
	app.UpdateWorkerPool(cfg.MaxWorkers, time.Duration(cfg.WorkerTaskTimeout)*time.Second)
	app.logger.Info("Worker池已重置: workers=%d, timeout=%ds", cfg.MaxWorkers, cfg.WorkerTaskTimeout)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"message":   "已重置为默认配置",
		"config":    cfg,
		"timestamp": getISONow(),
	})
}

func (app *Application) handleImageProxy(w http.ResponseWriter, r *http.Request) {
	encodedURL := strings.TrimPrefix(r.URL.Path, "/api/proxy/")
	if encodedURL == "" {
		sendErrorResponse(w, http.StatusBadRequest, "无效URL")
		return
	}
	decodedURL, err := url.PathUnescape(encodedURL)
	if err != nil {
		app.logger.Error("代理解码失败", err)
		sendErrorResponse(w, http.StatusBadRequest, "URL解码失败")
		return
	}
	if strings.HasPrefix(decodedURL, "https:/") && !strings.HasPrefix(decodedURL, "https://") {
		decodedURL = strings.Replace(decodedURL, "https:/", "https://", 1)
	} else if strings.HasPrefix(decodedURL, "http:/") && !strings.HasPrefix(decodedURL, "http://") {
		decodedURL = strings.Replace(decodedURL, "http:/", "http://", 1)
	}
	if !isValidURL(decodedURL) {
		sendErrorResponse(w, http.StatusBadRequest, "无效URL协议")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", decodedURL, nil)
	if err != nil {
		sendErrorResponse(w, http.StatusInternalServerError, "请求创建失败")
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "image/webp,image/apng,image/*,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Referer", "https://www.google.com/")
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: globalTransport,
	}
	resp, err := client.Do(req)
	if err != nil {
		app.logger.Error("代理请求失败", err)
		sendErrorResponse(w, http.StatusBadGateway, "图片代理失败")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		app.logger.Warn("代理状态: %d", resp.StatusCode)
		sendErrorResponse(w, resp.StatusCode, "图片获取失败")
		return
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	limited := http.MaxBytesReader(w, resp.Body, maxBodySize)
	_, err = io.Copy(w, limited)
	if err != nil {
		if !strings.Contains(err.Error(), "broken pipe") &&
			!strings.Contains(err.Error(), "client disconnected") {
			app.logger.Error("代理复制失败", err)
		}
	}
}

func (app *Application) initializeTemplates() error {
	var err error
	configTmplStr, err := templateFS.ReadFile("templates/config.html")
	if err != nil {
		return fmt.Errorf("配置页面模板加载失败: %w", err)
	}
	statsTmplStr, err := templateFS.ReadFile("templates/stats.html")
	if err != nil {
		return fmt.Errorf("统计页面模板加载失败: %w", err)
	}
	app.pgMessageTmpl, err = template.New("pgMessage").Parse(
		`{{.MonthDay}} {{.CleanedSource}} <a href="{{.URLEsc}}"><b>{{.NoteEsc}}</b></a>{{.ImgHTML}}`,
	)
	if err != nil {
		return err
	}
	app.configTmpl, err = template.New("config").Parse(string(configTmplStr))
	if err != nil {
		return fmt.Errorf("配置页面模板加载失败: %w", err)
	}
	app.statsTmpl, err = template.New("stats").Parse(string(statsTmplStr))
	if err != nil {
		return fmt.Errorf("统计页面模板加载失败: %w", err)
	}
	app.logger.Info("模板从 embed 文件加载完成")
	return nil
}

var (
	cachedDefaultsJSON []byte
	cachedDefaultsOnce sync.Once
)

func (app *Application) handleConfigPage(w http.ResponseWriter, r *http.Request) {
	cfg := app.configManager.GetConfig()
	cachedDefaultsOnce.Do(func() {
		defaults := DefaultConfig()
		cachedDefaultsJSON, _ = json.Marshal(map[string]interface{}{
			"PANSOU_API_URLS":        defaults.PansouAPIURLs,
			"PANSOU_PG_CLOUD_TYPES":  defaults.PGCloudTypes,
			"PANSOU_ZX_CLOUD_TYPES":  defaults.ZXCloudTypes,
			"MAX_LINKS_PER_TYPE":     defaults.MaxLinksPerType,
			"APITIME":                defaults.APITimeout,
			"WORKER_TASK_TIMEOUT":    defaults.WorkerTaskTimeout,
			"MAX_WORKERS":            defaults.MaxWorkers,
			"PG_IMAGE_PROXY_MODE":    defaults.PGImageProxyMode,
			"ZX_IMAGE_PROXY_MODE":    defaults.ZXImageProxyMode,
			"KEYWORDS":               defaults.Keywords,
			"CHANNELS":               defaults.Channels,
			"PLUGINS":                defaults.Plugins,
			"LINK_CHECK_ENABLED":     defaults.LinkCheckEnabled,
			"LINK_CHECK_WORKERS":     defaults.LinkCheckWorkers,
			"LINK_CHECK_TIMEOUT":     defaults.LinkCheckTimeout,
			"LB_STRATEGY":            defaults.LoadBalancerConfig.Strategy,
			"LB_HEALTH_CHECK":        defaults.LoadBalancerConfig.HealthCheck,
			"LB_CHECK_INTERVAL":      defaults.LoadBalancerConfig.CheckInterval,
			"LB_TIMEOUT":             defaults.LoadBalancerConfig.Timeout,
			"AUTO_BLOCK_IP":          defaults.AutoBlockIP,
			"LINK_CHECK_API_URL":     defaults.LinkCheckAPIURL,
			"LINK_CHECK_MODE":        defaults.LinkCheckMode,
			"BLOCK_KEYWORDS_CONTAIN": defaults.BlockKeywordsContain,
			"BLOCK_KEYWORDS_EXACT":   defaults.BlockKeywordsExact,
		})
	})

	buf := getBuffer()
	defer putBuffer(buf)

	data := struct {
		PansouAPIURLs        string
		PGCloudTypes         string
		ZXCloudTypes         string
		MaxLinksPerType      int
		APITimeout           int
		WorkerTaskTimeout    int
		MaxWorkers           int
		PGImageProxyMode     string
		ZXImageProxyMode     string
		Keywords             string
		Channels             string
		Plugins              string
		LinkCheckEnabled     bool
		LinkCheckWorkers     int
		LinkCheckTimeout     int
		LoadBalancerConfig   LoadBalancerConfig
		DefaultsJSON         template.JS
		Token                string
		AutoBlockIP          bool
		LinkCheckAPIURL      string
		LinkCheckMode        string
		BlockKeywordsContain string
		BlockKeywordsExact   string
	}{
		PansouAPIURLs:        cfg.PansouAPIURLs,
		PGCloudTypes:         cfg.PGCloudTypes,
		ZXCloudTypes:         cfg.ZXCloudTypes,
		MaxLinksPerType:      cfg.MaxLinksPerType,
		APITimeout:           cfg.APITimeout,
		WorkerTaskTimeout:    cfg.WorkerTaskTimeout,
		MaxWorkers:           cfg.MaxWorkers,
		PGImageProxyMode:     cfg.PGImageProxyMode,
		ZXImageProxyMode:     cfg.ZXImageProxyMode,
		Keywords:             cfg.Keywords,
		Channels:             cfg.Channels,
		Plugins:              cfg.Plugins,
		LinkCheckEnabled:     cfg.LinkCheckEnabled,
		LinkCheckWorkers:     cfg.LinkCheckWorkers,
		LinkCheckTimeout:     cfg.LinkCheckTimeout,
		LoadBalancerConfig:   cfg.LoadBalancerConfig,
		DefaultsJSON:         template.JS(cachedDefaultsJSON),
		Token:                r.URL.Query().Get("token"),
		AutoBlockIP:          cfg.AutoBlockIP,
		LinkCheckAPIURL:      cfg.LinkCheckAPIURL,
		LinkCheckMode:        cfg.LinkCheckMode,
		BlockKeywordsContain: cfg.BlockKeywordsContain,
		BlockKeywordsExact:   cfg.BlockKeywordsExact,
	}

	if err := app.configTmpl.Execute(buf, data); err != nil {
		http.Error(w, "模板渲染失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func (app *Application) handleUpdateGeoIPDatabase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, http.StatusMethodNotAllowed, "仅支持POST方法")
		return
	}
	if err := app.geoipService.updateMaxMindDB(); err != nil {
		app.logger.Error("更新GeoIP数据库失败", err)
		sendErrorResponse(w, http.StatusInternalServerError, "更新失败: "+err.Error())
		return
	}
	sendJSONResponse(w, map[string]interface{}{
		"success": true,
		"message": "GeoIP数据库更新成功",
	})
}

func main() {
	app, err := NewApplication()
	if err != nil {
		log.Fatalf("应用初始化失败: %v", err)
	}
	defer app.Close()
	app.configManager.SetApplication(app)
	cfg := app.configManager.GetConfig()
	app.logger.Info("P2T 启动中...")
	app.logger.Info("监听端口 : %d", cfg.ServerPort)
	app.logger.Info("盘搜后端 : %s", cfg.PansouAPIURLs)
	app.logger.Info("并发 Worker : %d (超时 %ds)", cfg.MaxWorkers, cfg.WorkerTaskTimeout)
	app.logger.Info("每类最大链接 : %d", cfg.MaxLinksPerType)
	app.logger.Info("链接检测 : %v", cfg.LinkCheckEnabled)
	if app.loadBalancer != nil {
		app.logger.Info("负载均衡策略 : %s (健康检查: %v)", cfg.LoadBalancerConfig.Strategy, cfg.LoadBalancerConfig.HealthCheck)
	}
	if app.authMiddleware.adminToken != "" {
		app.logger.Info("管理后台认证已启用 (token 长度: %d)", len(app.authMiddleware.adminToken))
	} else {
		app.logger.Warn("【严重警告】ADMIN_TOKEN 未设置，所有管理接口完全公开！建议立即设置环境变量 ADMIN_TOKEN")
	}
	mux := http.NewServeMux()
	auth := app.authMiddleware.RequireAuth
	mux.HandleFunc("/", recoveryMiddleware(app.handleRoot))
	mux.HandleFunc("/api/search", recoveryMiddleware(app.handleZXSearch))
	mux.HandleFunc("/s/", recoveryMiddleware(app.handlePGSearch))
	mux.HandleFunc("/health", recoveryMiddleware(app.handleHealthCheck))
	mux.HandleFunc("/api/proxy/", recoveryMiddleware(app.handleImageProxy))
	mux.HandleFunc("/api/config/set", auth(recoveryMiddleware(app.handleSetConfig)))
	mux.HandleFunc("/api/config/reset", auth(recoveryMiddleware(app.handleResetConfig)))
	mux.HandleFunc("/api/config/get", auth(recoveryMiddleware(app.handleGetConfig)))
	mux.HandleFunc("/config", auth(recoveryMiddleware(app.handleConfigPage)))
	mux.HandleFunc("/stats", auth(recoveryMiddleware(app.handleStatsPage)))
	mux.HandleFunc("/api/stats/get", auth(recoveryMiddleware(app.handleGetStatsData)))
	mux.HandleFunc("/api/stats/getAll", auth(recoveryMiddleware(app.handleGetAllStatsData)))
	mux.HandleFunc("/api/blacklist/block", auth(recoveryMiddleware(app.handleBlock)))
	mux.HandleFunc("/api/blacklist/unblock", auth(recoveryMiddleware(app.handleUnblock)))
	mux.HandleFunc("/api/loadbalancer/status", auth(recoveryMiddleware(app.handleLoadBalancerStatus)))
	mux.HandleFunc("/api/geoip/update", auth(recoveryMiddleware(app.handleUpdateGeoIPDatabase)))
	finalHandler := app.MonitoringMiddleware(mux)
	addr := fmt.Sprintf("0.0.0.0:%d", cfg.ServerPort)
	app.logger.Info("P2T 已就绪 → http://0.0.0.0:%d", cfg.ServerPort)
	if app.authMiddleware.adminToken != "" {
		app.logger.Info("管理界面 → http://0.0.0.0:%d/config?token=%s", cfg.ServerPort, app.authMiddleware.adminToken)
	} else {
		app.logger.Info("管理界面 → http://0.0.0.0:%d/config", cfg.ServerPort)
	}
	srv := &http.Server{
		Addr:         addr,
		Handler:      finalHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Error("HTTP服务器异常退出", err)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	app.logger.Info("收到关闭信号，正在优雅关闭服务器...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		app.logger.Error("服务器强制关闭失败", err)
	} else {
		app.logger.Info("服务器已安全关闭，拜拜 👋")
	}
}
