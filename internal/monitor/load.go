package monitor

// System load history uses periodic sampling and a dashboard chart endpoint.

import (
	"database/sql"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"servika/internal/httpx"
	"servika/internal/logx"
	"servika/internal/system"
)

// StartLoadSampler records the load average, memory, CPU, swap, root disk and
// network rate every interval. It retains seven days of data, prunes
// approximately hourly, and recovers from panics.
func StartLoadSampler(db *sql.DB, every time.Duration) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				logx.Errorf("load sampler panic: %v", rec)
			}
		}()
		sampleLoad(db) // Record one sample immediately at startup.
		t := time.NewTicker(every)
		defer t.Stop()
		var n int
		for range t.C {
			sampleLoad(db)
			if n++; n%60 == 0 {
				if _, err := db.Exec(`DELETE FROM system_load WHERE ts < NOW() - INTERVAL 7 DAY`); err != nil {
					logx.Errorf("load sampler prune: %v", err)
				}
			}
		}
	}()
}

// loadSample is one row of history.
//
// The network figures are RATES in bytes per second, not the interface
// counters. A counter resets when the host reboots or the interface is renamed,
// and a reader differencing two stored rows would draw a negative spike or a
// wrap-sized positive one; internal/system already differences against its own
// previous reading and clamps a backwards counter to zero.
type loadSample struct {
	load1, load5, load15           float64
	memPercent, cpuPercent         float64
	swapPercent, diskPercent       float64
	netRxPerSecond, netTxPerSecond int64
}

// hostSample is a variable so a test can stand in for the host. The readings
// below come from /proc and statfs, which macOS does not have.
var hostSample = readHostSample

// readHostSample takes one reading of everything the history keeps.
//
// The CPU reading costs a 150 ms sleep inside internal/system, which is why
// this runs on the sampler goroutine and never on a request path.
func readHostSample() loadSample {
	load1, load5, load15 := readLoad()
	cpu, err := system.ReadCPU()
	if err != nil {
		// A reading that failed is stored as zero rather than skipped: the row
		// still carries the load average, and a missing row is a gap in every
		// chart, not just this one.
		logx.Warnf("load sampler: read the CPU usage: %v", err)
	}
	disk, err := system.ReadDisk("/")
	if err != nil {
		logx.Warnf("load sampler: read the root filesystem: %v", err)
	}
	network := system.ReadNetwork()
	return loadSample{
		load1: load1, load5: load5, load15: load15,
		memPercent:     readMemoryPercent(),
		cpuPercent:     cpu.Percent,
		swapPercent:    system.ReadSwap().Percent,
		diskPercent:    disk.Percent,
		netRxPerSecond: network.RxBytes, netTxPerSecond: network.TxBytes,
	}
}

func sampleLoad(db *sql.DB) {
	s := hostSample()
	if _, err := db.Exec(
		`INSERT INTO system_load
		   (load1, load5, load15, mem_percent, cpu_percent, swap_percent, disk_percent, net_rx_bps, net_tx_bps)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		s.load1, s.load5, s.load15, s.memPercent, s.cpuPercent,
		s.swapPercent, s.diskPercent, s.netRxPerSecond, s.netTxPerSecond); err != nil {
		logx.Errorf("load sampler insert: %v", err)
	}
}

func readLoad() (float64, float64, float64) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		logx.Errorf("load sampler: read /proc/loadavg: %v", err)
		return 0, 0, 0
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return 0, 0, 0
	}
	a, _ := strconv.ParseFloat(f[0], 64)
	c, _ := strconv.ParseFloat(f[1], 64)
	d, _ := strconv.ParseFloat(f[2], 64)
	return a, c, d
}

func readMemoryPercent() float64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		logx.Errorf("load sampler: read /proc/meminfo: %v", err)
		return 0
	}
	var total, avail float64
	for line := range strings.SplitSeq(string(b), "\n") {
		ff := strings.Fields(line)
		if len(ff) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(ff[1], 64)
		switch ff[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total <= 0 {
		return 0
	}
	return math.Round(10000*(total-avail)/total) / 100
}

type LoadPoint struct {
	Timestamp string  `json:"ts"`
	Load1     float64 `json:"load_1m"`
	Load5     float64 `json:"load_5m"`
	Load15    float64 `json:"load_15m"`
	Memory    float64 `json:"memory"`
	CPU       float64 `json:"cpu"`
	Swap      float64 `json:"swap"`
	Disk      float64 `json:"disk"`
	NetRx     int64   `json:"net_rx_bps"`
	NetTx     int64   `json:"net_tx_bps"`
}

// historyQuery averages each bucket. The network rates are averaged too, not
// summed: a bucket holds several samples of a per-second rate, and adding them
// would report a figure that scales with the bucket width rather than with the
// traffic.
const historyQuery = `
	SELECT MIN(ts)          AS ts,
	       ROUND(AVG(load1),2),
	       ROUND(AVG(load5),2),
	       ROUND(AVG(load15),2),
	       ROUND(AVG(mem_percent),1),
	       ROUND(AVG(cpu_percent),1),
	       ROUND(AVG(swap_percent),1),
	       ROUND(AVG(disk_percent),1),
	       ROUND(AVG(net_rx_bps)),
	       ROUND(AVG(net_tx_bps))
	  FROM system_load
	 WHERE ts >= NOW() - INTERVAL ? HOUR
	 GROUP BY FLOOR(UNIX_TIMESTAMP(ts) / ?)
	 ORDER BY ts`

// scanPoint reads one bucket in the order historyQuery selects.
func scanPoint(rows *sql.Rows) (LoadPoint, error) {
	var p LoadPoint
	err := rows.Scan(&p.Timestamp, &p.Load1, &p.Load5, &p.Load15, &p.Memory,
		&p.CPU, &p.Swap, &p.Disk, &p.NetRx, &p.NetTx)
	return p, err
}

// GET /system/load-history?hour=24 returns 1 to 168 hours of load data in about 500 buckets.
func (h *Handlers) LoadHistory(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if s := r.URL.Query().Get("hour"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 1 && v <= 168 {
			hours = v
		}
	}
	bucket := hours * 3600 / 500 // Seconds per bucket, targeting about 500 points.
	bucket = max(bucket, 60)
	rows, err := h.DB.QueryContext(r.Context(), historyQuery, hours, bucket)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to read load history")
		return
	}
	defer func() { _ = rows.Close() }()
	out := []LoadPoint{}
	for rows.Next() {
		// A dropped point is a GAP in the chart, and a gap is exactly how a
		// server that was too loaded to record a sample renders. Skipping the
		// row would draw the incident the operator opened the chart to
		// investigate, with nothing anywhere contradicting it, so the read is
		// refused instead.
		point, err := scanPoint(rows)
		if err != nil {
			httpx.LogR(r, "load history: a sample could not be read: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "failed to read load history")
			return
		}
		out = append(out, point)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to process load history")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"hour": hours, "cores": coreCount(), "points": out})
}

func coreCount() int {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "processor\t")
}
