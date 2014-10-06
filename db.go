package auditlog

import (
	"database/sql"
	"fmt"

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
		fmt.Printf("\t[+] table %s updated\n", tableName)
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
		(id, timestamp, received, level, actor, event)
		values (?, ?, ?, ?, ?, ?)`,
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
