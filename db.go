package auditlog

import (
	"database/sql"
	"errors"

	_ "github.com/mxk/go-sqlite/sqlite3"
	// _ "github.com/mattn/go-sqlite3"
)

var tables = map[string]string{
	"events": `CREATE TABLE events (
    id          INTEGER PRIMARY KEY NOT NULL,
    timestamp   INTEGER NOT NULL,
    received    INTEGER NOT NULL,
    level       TEXT NOT NULL,
    actor       TEXT NOT NULL,
    event       TEXT NOT NULL,
    signature   BLOB NOT NULL
)`,
	"attributes": `CREATE TABLE attributes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    value       TEXT NOT NULL,
    event       INTEGER NOT NULL,
    position    INTEGER NOT NULL
)`,
	"error_events": `CREATE TABLE error_events (
    id          INTEGER PRIMARY KEY NOT NULL,
    serial      INTEGER NOT NULL,
    timestamp   INTEGER NOT NULL,
    received    INTEGER NOT NULL,
    level       TEXT NOT NULL,
    actor       TEXT NOT NULL,
    event       TEXT NOT NULL
)`,
	"error_attributes": `CREATE TABLE error_attributes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    value       TEXT NOT NULL,
    event       INTEGER NOT NULL,
    position    INTEGER NOT NULL
)`,
	"errors": `CREATE TABLE errors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,
    message     TEXT NOT NULL,
    event       INTEGER
)`,
}

func (l *Logger) setupDB(dbFile string) (err error) {
	l.db, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		return
	}

	if l.db == nil {
		err = errors.New("auditlog: failed to open database")
		return
	}

	err = l.db.Ping()
	if err != nil {
		return
	}

	for tableName, tableSQL := range tables {
		err = checkTable(l.db, tableName, tableSQL)
		if err != nil {
			return
		}
	}

	return
}

func checkTable(db *sql.DB, tableName, tableSQL string) error {
	rows, err := db.Query(`select sql from sqlite_master
where type='table' and name=?`, tableName)
	if err != nil {
		return err
	}
	var tblSql string
	for rows.Next() {
		err = rows.Scan(&tblSql)
		break
	}
	rows.Close()
	if err != nil {
		return err
	} else if tblSql == "" {
		_, err = db.Exec(tableSQL)
		if err != nil {
			return err
		}
	} else if tblSql != tableSQL {
		_, err = db.Exec("drop table " + tableName)
		if err != nil {
			return err
		}
		_, err = db.Exec(tableSQL)
		if err != nil {
			return err
		}
	}
	return nil
}

func storeEvent(db *sql.DB, ev *Event) error {
	_, err := db.Exec(`INSERT INTO events
		(id, timestamp, received, level, actor, event, signature)
		values (?, ?, ?, ?, ?, ?, ?)`,
		ev.Serial, ev.When, ev.Received, ev.Level, ev.Actor, ev.Event, ev.Signature)
	if err != nil {
		return err
	}

	for i, attr := range ev.Attributes {
		_, err = db.Exec(`INSERT INTO attributes (id, name, value, event, position) values (?, ?, ?, ?, ?)`,
			nil, attr.Name, attr.Value, ev.Serial, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func commit(db *sql.DB) error {
	_, err := db.Exec(`COMMIT`)
	return err
}

func begin(db *sql.DB) error {
	_, err := db.Exec(`BEGIN IMMEDIATE TRANSACTION`)
	return err
}

func rollback(db *sql.DB) error {
	_, err := db.Exec(`ROLLBACK TRANSACTION`)
	return err
}

func storeError(db *sql.DB, ev *ErrorEvent) error {
	_, err := db.Exec(`INSERT INTO error_events
		(id, serial, timestamp, received, level, actor, event)
		values (?, ?, ?, ?, ?, ?, ?)`, nil,
		ev.Event.Serial, ev.Event.When, ev.Event.Received, ev.Event.Level,
		ev.Event.Actor, ev.Event.Event)
	if err != nil {
		return err
	}

	var eventID int64
	err = db.QueryRow(`SELECT last_insert_rowid()`).Scan(&eventID)
	if err != nil {
		return err
	}

	_, err = db.Exec(`INSERT INTO errors (timestamp, event, message)
		values (?, ?, ?)`,
		ev.When, eventID, ev.Message)
	if err != nil {
		return err
	}

	for i, attr := range ev.Event.Attributes {
		_, err = db.Exec(`INSERT INTO error_attributes (name, value, event, position) values (?, ?, ?, ?)`,
			attr.Name, attr.Value, eventID, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func loadEvents(db *sql.DB, start, end uint64) (events []*Event, err error) {
	rows, err := db.Query(`SELECT * FROM events WHERE id >= ? AND id <= ?`,
		start, end)
	if err != nil {
		return
	}

	for rows.Next() {
		var ev Event
		err = rows.Scan(&ev.Serial, &ev.When, &ev.Received, &ev.Level,
			&ev.Actor, &ev.Event, &ev.Signature)
		if err != nil {
			return
		}

		err = loadAttributes(db, &ev)
		if err != nil {
			return
		}

		events = append(events, &ev)
	}

	return
}

func loadAttributes(db *sql.DB, ev *Event) error {
	rows, err := db.Query(`SELECT name, value FROM attributes
			      WHERE event = ? ORDER BY position`,
		ev.Serial)
	if err != nil {
		return err
	}

	for rows.Next() {
		var attr Attribute
		err = rows.Scan(&attr.Name, &attr.Value)
		if err != nil {
			return err
		}

		ev.Attributes = append(ev.Attributes, attr)
	}
	return nil
}

func countEvents(db *sql.DB) (uint64, error) {
	var count uint64
	err := db.QueryRow(`SELECT count(*) FROM events`).Scan(&count)
	return count, err
}

var errAuditFailure = errors.New("auditlog: failed to verify audit chain")

func getSignature(db *sql.DB, serial uint64) ([]byte, error) {
	var sig []byte
	err := db.QueryRow(`SELECT signature FROM events WHERE id=?`, serial).Scan(&sig)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func loadEvent(db *sql.DB, serial uint64) (*Event, error) {
	var ev Event

	row := db.QueryRow(`SELECT * FROM events WHERE id=?`, serial)
	err := row.Scan(&ev.Serial, &ev.When, &ev.Received, &ev.Level,
		&ev.Actor, &ev.Event, &ev.Signature)
	if err != nil {
		return nil, err
	}

	err = loadAttributes(db, &ev)
	if err != nil {
		return nil, err
	}

	return &ev, nil
}

func (l *Logger) verifyEvent(serial uint64) error {
	var prev []byte
	err := begin(l.db)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			rollback(l.db)
		} else {
			commit(l.db)
		}
	}()

	if serial > 0 {
		prev, err = getSignature(l.db, serial-1)
		if err != nil {
			return err
		}
	}

	ev, err := loadEvent(l.db, serial)
	if err != nil {
		return err
	}

	if !ev.Verify(&l.signer.PublicKey, prev) {
		err = errAuditFailure
		return err
	}

	return nil
}

func (l *Logger) verifyAuditChain() error {
	var err error
	for i := uint64(0); i < l.counter; i++ {
		err = l.verifyEvent(i)
		if err != nil {
			return err
		}
	}

	l.lastSignature, err = getSignature(l.db, l.counter)

	return nil
}

func loadErrorAttributes(db *sql.DB, ev *Event) error {
	rows, err := db.Query(`SELECT name, value FROM error_attributes
			      WHERE event = ? ORDER BY position`,
		ev.Serial)
	if err != nil {
		return err
	}

	for rows.Next() {
		var attr Attribute
		err = rows.Scan(&attr.Name, &attr.Value)
		if err != nil {
			return err
		}

		ev.Attributes = append(ev.Attributes, attr)
	}
	return nil
}

func loadErrors(db *sql.DB, start, end uint64) (events []*ErrorEvent, err error) {
	rows, err := db.Query(`SELECT * FROM error_events WHERE serial >= ? AND serial <= ?`, start, end)
	if err != nil {
		return
	}

	for rows.Next() {
		var ev Event
		var errEv ErrorEvent
		var eventID uint64

		err = rows.Scan(&eventID, &ev.Serial, &ev.When, &ev.Received, &ev.Level, &ev.Actor, &ev.Event)
		if err != nil {
			events = nil
			return
		}

		err = loadErrorAttributes(db, &ev)
		if err != nil {
			events = nil
			return
		}

		err = db.QueryRow(`SELECT timestamp, message FROM errors WHERE event=?`, eventID).Scan(&errEv.When, &errEv.Message)
		if err != nil {
			events = nil
			return
		}

		errEv.Event = &ev
		events = append(events, &errEv)
	}

	return
}
