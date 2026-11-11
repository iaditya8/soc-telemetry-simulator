package generator

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// QueueSensor allows the scheduler to monitor downstream queue saturation for backpressure.
type QueueSensor interface {
	QueueDepthPercent() float64
}

// SchedulerConfig controls event pacing and concurrency.
type SchedulerConfig struct {
	TargetEPS       int
	DurationSeconds int
	WorkerCount     int
}

// Scheduler coordinates high-frequency event generation ticks and distributes work quotas.
type Scheduler struct {
	cfg            SchedulerConfig
	sensor         QueueSensor
	fractionAcc    float64
	generatedCount uint64
	lastTickTime   time.Time
	running        uint32
	paused         uint32
	currentEPS     uint64
	mu             sync.Mutex
}

// NewScheduler creates a rate scheduler tuned for 100k+ EPS workloads.
func NewScheduler(cfg SchedulerConfig, sensor QueueSensor) *Scheduler {
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = runtime.NumCPU()
		if cfg.WorkerCount < 2 {
			cfg.WorkerCount = 2
		}
	}

	return &Scheduler{
		cfg:    cfg,
		sensor: sensor,
	}
}

// Start begins the generation loop, dispatching work tokens to the worker callback.
// The callback `workFn(workerID int, tokenQuota int)` is invoked concurrently across workers.
func (s *Scheduler) Start(ctx context.Context, workFn func(workerID int, quota int)) {
	atomic.StoreUint32(&s.running, 1)
	defer atomic.StoreUint32(&s.running, 0)

	tickInterval := 10 * time.Millisecond
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	tokensPerTick := float64(s.cfg.TargetEPS) / 100.0
	workers := s.cfg.WorkerCount

	var runTimer <-chan time.Time
	if s.cfg.DurationSeconds > 0 {
		runTimer = time.After(time.Duration(s.cfg.DurationSeconds) * time.Second)
	}

	var secondWindowCount uint64
	secondTicker := time.NewTicker(1 * time.Second)
	defer secondTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-runTimer:
			return

		case <-secondTicker.C:
			// Record instantaneous observed EPS
			total := atomic.LoadUint64(&s.generatedCount)
			eps := total - secondWindowCount
			secondWindowCount = total
			atomic.StoreUint64(&s.currentEPS, eps)

		case <-ticker.C:
			if atomic.LoadUint32(&s.paused) == 1 {
				continue
			}

			// 1. Calculate base token quota with fractional accumulation
			s.mu.Lock()
			s.fractionAcc += tokensPerTick
			quota := int(s.fractionAcc)
			s.fractionAcc -= float64(quota)
			s.mu.Unlock()

			if quota <= 0 {
				continue
			}

			// 2. Evaluate reactive backpressure if sensor is attached
			if s.sensor != nil {
				depth := s.sensor.QueueDepthPercent()
				if depth >= 0.98 {
					// Queue saturated: pause generation tick completely
					continue
				} else if depth > 0.80 {
					// Scale down throughput proportionally between 80% and 98%
					scaleFactor := 1.0 - ((depth - 0.80) / 0.18)
					quota = int(float64(quota) * scaleFactor)
					if quota <= 0 {
						continue
					}
				}
			}

			// 3. Dispatch quota across worker goroutines
			quotaPerWorker := quota / workers
			remainder := quota % workers

			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				workerQuota := quotaPerWorker
				if w < remainder {
					workerQuota++
				}
				if workerQuota <= 0 {
					continue
				}

				wg.Add(1)
				go func(id, count int) {
					defer wg.Done()
					workFn(id, count)
					atomic.AddUint64(&s.generatedCount, uint64(count))
				}(w, workerQuota)
			}
			wg.Wait()
		}
	}
}

// Pause pauses generation ticks.
func (s *Scheduler) Pause() {
	atomic.StoreUint32(&s.paused, 1)
}

// Resume resumes generation ticks.
func (s *Scheduler) Resume() {
	atomic.StoreUint32(&s.paused, 0)
}

// IsRunning reports whether the scheduler is actively running.
func (s *Scheduler) IsRunning() bool {
	return atomic.LoadUint32(&s.running) == 1
}

// TotalGenerated returns the cumulative count of generated events.
func (s *Scheduler) TotalGenerated() uint64 {
	return atomic.LoadUint64(&s.generatedCount)
}

// CurrentEPS returns the instantaneous observed EPS.
func (s *Scheduler) CurrentEPS() uint64 {
	return atomic.LoadUint64(&s.currentEPS)
}
