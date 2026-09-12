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
)

// StartLoadSampler samples /proc/loadavg and /proc/meminfo every interval and stores the result.
// It retains seven days of data, prunes approximately hourly, and recovers from panics.
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

func sampleLoad(db *sql.DB) {
	load1, load5, load15 := readLoad()
	memory := readMemoryPercent()
	if _, err := db.Exec(`INSERT INTO system_load (load1, load5, load15, mem_percent) VALUES (?,?,?,?)`, load1, load5, load15, memory); err != nil {
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
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT MIN(ts)          AS ts,
		       ROUND(AVG(load1),2),
		       ROUND(AVG(load5),2),
		       ROUND(AVG(load15),2),
		       ROUND(AVG(mem_percent),1)
		  FROM system_load
		 WHERE ts >= NOW() - INTERVAL ? HOUR
		 GROUP BY FLOOR(UNIX_TIMESTAMP(ts) / ?)
		 ORDER BY ts`, hours, bucket)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to read load history")
		return
	}
	defer func() { _ = rows.Close() }()
	out := []LoadPoint{}
	for rows.Next() {
		var point LoadPoint
		if err := rows.Scan(&point.Timestamp, &point.Load1, &point.Load5, &point.Load15, &point.Memory); err == nil {
			out = append(out, point)
		}
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
