package api

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (s *Server) flagBackupNeeded() {
	s.backupNeeded.Store(true)
}

func (s *Server) backupLoop() {
	// Initial wait to let server start up
	time.Sleep(5 * time.Second)

	lastRetentionRun := time.Now()

	for {
		intervalMins := 5 // default
		val, err := s.store.GetSetting(context.Background(), "backup_interval_mins")
		if err == nil && val != "" {
			if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 {
				intervalMins = parsed
			}
		}

		// Wait for the interval
		time.Sleep(time.Duration(intervalMins) * time.Minute)

		if s.backupNeeded.Load() {
			if err := s.runBackup(); err != nil {
				s.logger.Error("background backup failed", "err", err)
			} else {
				s.backupNeeded.Store(false)
			}
			lastRetentionRun = time.Now()
		} else if time.Since(lastRetentionRun) >= 1*time.Hour {
			// Run retention policy periodically even if no backups were created
			if target, err := s.store.GetSetting(context.Background(), "backup_target"); err == nil && target != "" {
				isRemote := strings.Contains(target, "@") && strings.Contains(target, ":")
				if !isRemote {
					s.applyRetentionPolicy(target, false)
				}
			}
			lastRetentionRun = time.Now()
		}
	}
}

func (s *Server) runBackup() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Ensure we only run one backup at a time
	if !s.backupMutex.TryLock() {
		return fmt.Errorf("backup already in progress")
	}
	defer s.backupMutex.Unlock()

	target, err := s.store.GetSetting(ctx, "backup_target")
	if err != nil || target == "" {
		return nil // nothing to do
	}

	timestamp := time.Now().UTC().Format("20060102_150405")
	filename := fmt.Sprintf("tsm_backup_%s.db", timestamp)

	// A simple heuristic to avoid confusing Windows drive letters (C:\) with SCP targets.
	isRemote := strings.Contains(target, "@") && strings.Contains(target, ":")
	var finalTarget string

	if isRemote {
		if strings.HasSuffix(target, "/") || strings.HasSuffix(target, ":") {
			finalTarget = target + filename
		} else {
			finalTarget = target + "_" + filename
		}
	} else {
		// Local
		if strings.HasSuffix(target, "_") || strings.HasSuffix(target, "-") {
			finalTarget = target + filename
		} else {
			finalTarget = filepath.Join(target, filename)
		}
	}

	if !isRemote {
		if err := os.MkdirAll(filepath.Dir(finalTarget), 0755); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
		tmpFile := finalTarget + ".tmp"
		if err := s.store.Backup(ctx, tmpFile); err != nil {
			return fmt.Errorf("local backup vacuum failed: %w", err)
		}
		if err := os.Rename(tmpFile, finalTarget); err != nil {
			return fmt.Errorf("local backup rename failed: %w", err)
		}
		s.logger.Info("local database backup successful", "path", finalTarget)
		s.applyRetentionPolicy(target, false)
	} else {
		tmpFile := s.cfg.DBPath + ".backup.tmp"
		defer os.Remove(tmpFile)

		if err := s.store.Backup(ctx, tmpFile); err != nil {
			return fmt.Errorf("remote backup vacuum failed: %w", err)
		}

		cmd := exec.CommandContext(ctx, "scp", "-o", "StrictHostKeyChecking=no", tmpFile, finalTarget)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("scp backup failed: %w (output: %s)", err, string(out))
		}
		s.logger.Info("remote database backup successful", "target", finalTarget)
		s.applyRetentionPolicy(target, true)
	}

	return nil
}

func (s *Server) applyRetentionPolicy(baseTarget string, isRemote bool) {
	// For simplicity, we only run retention on local directory targets.
	// Running retention over SCP is complex without full SSH access.
	if isRemote {
		s.logger.Info("skipping retention policy for remote SCP target (not supported)")
		return
	}

	ctx := context.Background()
	keepAllStr, _ := s.store.GetSetting(ctx, "backup_retention_all_days")
	keepDailyStr, _ := s.store.GetSetting(ctx, "backup_retention_daily_days")

	keepAllDays := 1
	if v, err := strconv.Atoi(keepAllStr); err == nil && v >= 0 {
		keepAllDays = v
	}

	keepDailyDays := 30
	if v, err := strconv.Atoi(keepDailyStr); err == nil && v >= 0 {
		keepDailyDays = v
	}

	if keepAllDays == 0 && keepDailyDays == 0 {
		return // None configured
	}

	stat, err := os.Stat(baseTarget)
	if err != nil || !stat.IsDir() {
		// Only run if baseTarget is an existing directory
		return
	}

	files, err := os.ReadDir(baseTarget)
	if err != nil {
		s.logger.Error("failed to read backup directory for retention", "err", err)
		return
	}

	now := time.Now()
	var toDelete []string
	dailyBuckets := make(map[string]string) // YYYYMMDD -> filepath

	for _, f := range files {
		if f.IsDir() || !strings.HasPrefix(f.Name(), "tsm_backup_") || !strings.HasSuffix(f.Name(), ".db") {
			continue
		}

		info, err := f.Info()
		if err != nil {
			continue
		}

		path := filepath.Join(baseTarget, f.Name())
		ageDays := now.Sub(info.ModTime()).Hours() / 24.0

		if ageDays <= float64(keepAllDays) {
			continue // Keep it
		}

		if ageDays <= float64(keepAllDays+keepDailyDays) {
			// Daily bucket logic
			dateKey := info.ModTime().Format("20060102")
			existing, ok := dailyBuckets[dateKey]
			if !ok {
				dailyBuckets[dateKey] = path
			} else {
				// Keep the newest one in the bucket. We check ModTime.
				exStat, _ := os.Stat(existing)
				if exStat != nil && info.ModTime().After(exStat.ModTime()) {
					toDelete = append(toDelete, existing)
					dailyBuckets[dateKey] = path
				} else {
					toDelete = append(toDelete, path)
				}
			}
		} else {
			// Older than keepAll + keepDaily -> delete
			toDelete = append(toDelete, path)
		}
	}

	for _, p := range toDelete {
		if err := os.Remove(p); err != nil {
			s.logger.Error("failed to prune backup", "path", p, "err", err)
		} else {
			s.logger.Info("pruned old backup", "path", p)
		}
	}
}
