package store

import (
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/andycol/sipreaper/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

func New(path string) (*Store, error) {
	// WAL gives us concurrent readers + a single writer, busy_timeout retries
	// briefly when another goroutine holds the lock instead of failing fast,
	// foreign_keys + synchronous=NORMAL is the documented "safe & fast" combo
	// for WAL.
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=on"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// SQLite is single-writer; cap connections so we serialise writes inside
	// the driver instead of getting SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	return &Store{db: db}, nil
}

// HealthCheck verifies the DB is reachable and writable.
func (s *Store) HealthCheck() error {
	return s.db.Ping()
}

func (s *Store) Close() error {
	return s.db.Close()
}

func migrate(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS bans (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		ip          TEXT NOT NULL,
		detector    TEXT NOT NULL,
		reason      TEXT NOT NULL,
		severity    TEXT NOT NULL,
		banned_at   DATETIME NOT NULL,
		duration    INTEGER NOT NULL,
		expires_at  DATETIME,
		ban_count   INTEGER NOT NULL,
		status      TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS events (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		ip          TEXT NOT NULL,
		method      TEXT NOT NULL,
		detector    TEXT,
		timestamp   DATETIME NOT NULL,
		raw_data    TEXT
	);

	CREATE TABLE IF NOT EXISTS whitelist (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_cidr     TEXT NOT NULL UNIQUE,
		comment     TEXT,
		source      TEXT NOT NULL,
		created_at  DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_bans_ip_status ON bans(ip, status);
	CREATE INDEX IF NOT EXISTS idx_bans_status ON bans(status);
	CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	`
	_, err := db.Exec(schema)
	return err
}

func (s *Store) CreateBan(e models.BanEntry) (int64, error) {
	var expiresAt *time.Time
	if e.ExpiresAt != nil {
		t := *e.ExpiresAt
		expiresAt = &t
	}

	res, err := s.db.Exec(
		`INSERT INTO bans (ip, detector, reason, severity, banned_at, duration, expires_at, ban_count, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.IP, e.Detector, e.Reason, e.Severity, e.BannedAt,
		int64(e.Duration.Seconds()), expiresAt, e.BanCount, e.Status,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListBans(status string) ([]models.BanEntry, error) {
	query := `SELECT id, ip, detector, reason, severity, banned_at, duration, expires_at, ban_count, status FROM bans`
	var args []interface{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY banned_at DESC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanBans(rows)
}

func (s *Store) GetActiveBanByIP(ip string) (*models.BanEntry, error) {
	// dry_run is included so the decision engine doesn't fire repeatedly for
	// the same IP during a tuning run.
	row := s.db.QueryRow(
		`SELECT id, ip, detector, reason, severity, banned_at, duration, expires_at, ban_count, status
		 FROM bans WHERE ip = ? AND status IN ('active', 'manual', 'dry_run') LIMIT 1`, ip,
	)

	var e models.BanEntry
	var durSecs int64
	var expiresAt sql.NullTime

	err := row.Scan(&e.ID, &e.IP, &e.Detector, &e.Reason, &e.Severity,
		&e.BannedAt, &durSecs, &expiresAt, &e.BanCount, &e.Status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	e.Duration = time.Duration(durSecs) * time.Second
	if expiresAt.Valid {
		e.ExpiresAt = &expiresAt.Time
	}
	return &e, nil
}

func (s *Store) UpdateBanStatus(id int64, status string) error {
	_, err := s.db.Exec(`UPDATE bans SET status = ? WHERE id = ?`, status, id)
	return err
}

func (s *Store) BanCountByIP(ip string, since time.Time) (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM bans WHERE ip = ? AND banned_at >= ?`, ip, since,
	).Scan(&count)
	return count, err
}

func (s *Store) GetExpiredBans() ([]models.BanEntry, error) {
	// dry_run entries expire too — otherwise an IP only ever produces one
	// would-be-ban record, masking the true rate during a tuning window.
	rows, err := s.db.Query(
		`SELECT id, ip, detector, reason, severity, banned_at, duration, expires_at, ban_count, status
		 FROM bans WHERE status IN ('active','dry_run') AND expires_at IS NOT NULL AND expires_at <= ?`,
		time.Now(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBans(rows)
}

func (s *Store) RecordEvent(evt models.SIPEvent, detector string) error {
	_, err := s.db.Exec(
		`INSERT INTO events (ip, method, detector, timestamp, raw_data) VALUES (?, ?, ?, ?, ?)`,
		evt.SourceIP.String(), evt.Method, detector, evt.Timestamp, "",
	)
	return err
}

func (s *Store) ListEvents(ip, detector string, since time.Duration, limit int) ([]models.SIPEvent, error) {
	query := `SELECT ip, method, detector, timestamp FROM events WHERE 1=1`
	var args []interface{}

	if ip != "" {
		query += ` AND ip = ?`
		args = append(args, ip)
	}
	if detector != "" {
		query += ` AND detector = ?`
		args = append(args, detector)
	}
	if since > 0 {
		query += ` AND timestamp >= ?`
		args = append(args, time.Now().Add(-since))
	}

	query += ` ORDER BY timestamp DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.SIPEvent
	for rows.Next() {
		var e models.SIPEvent
		var ipStr, det string
		if err := rows.Scan(&ipStr, &e.Method, &det, &e.Timestamp); err != nil {
			return nil, err
		}
		e.SourceIP = net.ParseIP(ipStr)
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) AddWhitelist(ipCIDR, comment, source string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO whitelist (ip_cidr, comment, source, created_at) VALUES (?, ?, ?, ?)`,
		ipCIDR, comment, source, time.Now(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) RemoveWhitelist(ipCIDR string) error {
	_, err := s.db.Exec(`DELETE FROM whitelist WHERE ip_cidr = ?`, ipCIDR)
	return err
}

func (s *Store) ListWhitelist() ([]models.WhitelistEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, ip_cidr, comment, source, created_at FROM whitelist ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.WhitelistEntry
	for rows.Next() {
		var e models.WhitelistEntry
		if err := rows.Scan(&e.ID, &e.IPCIDR, &e.Comment, &e.Source, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func scanBans(rows *sql.Rows) ([]models.BanEntry, error) {
	var bans []models.BanEntry
	for rows.Next() {
		var e models.BanEntry
		var durSecs int64
		var expiresAt sql.NullTime

		if err := rows.Scan(&e.ID, &e.IP, &e.Detector, &e.Reason, &e.Severity,
			&e.BannedAt, &durSecs, &expiresAt, &e.BanCount, &e.Status); err != nil {
			return nil, err
		}

		e.Duration = time.Duration(durSecs) * time.Second
		if expiresAt.Valid {
			e.ExpiresAt = &expiresAt.Time
		}
		bans = append(bans, e)
	}
	return bans, rows.Err()
}
