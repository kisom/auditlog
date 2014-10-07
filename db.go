package auditlog

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

// DBConnDetails contains the connection parameters for the database.
type DBConnDetails struct {
	Name, User, Password, Host, Port string
	SSL                              bool
}

func (cd DBConnDetails) String() string {
	var sslmode string = "verify-full"
	if !cd.SSL {
		sslmode = "disable"
	}

	return fmt.Sprintf("dbname=%s user=%s password=%s host=%s port=%s sslmode=%s",
		cd.Name, cd.User, cd.Password, cd.Host, cd.Port, sslmode)
}

func (l *Logger) setupDB(cd *DBConnDetails) (err error) {
	l.db, err = sql.Open("postgres", cd.String())
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
	return nil
}

func storeEvent(tx *sql.Tx, ev *Event) error {
	_, err := tx.Exec(`INSERT INTO events
		(id, timestamp, received, level, actor, event, signature)
		values ($1, $2, $3, $4, $5, $6, $7)`,
		ev.Serial, ev.When, ev.Received, ev.Level, ev.Actor, ev.Event, ev.Signature)
	if err != nil {
		return err
	}

	for i, attr := range ev.Attributes {
		_, err = tx.Exec(`INSERT INTO attributes (name, value, event, position) values ($1, $2, $3, $4)`,
			attr.Name, attr.Value, ev.Serial, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func storeError(tx *sql.Tx, ev *ErrorEvent) error {
	var eventID int64

	log.Println("store error")
	err := tx.QueryRow(`INSERT INTO error_events
		(serial, timestamp, received, level, actor, event)
		values ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		ev.Event.Serial, ev.Event.When, ev.Event.Received,
		ev.Event.Level, ev.Event.Actor, ev.Event.Event).Scan(&eventID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`INSERT INTO errors (timestamp, event, message)
		values ($1, $2, $3)`,
		ev.When, eventID, ev.Message)
	if err != nil {
		return err
	}

	for i, attr := range ev.Event.Attributes {
		_, err = tx.Exec(`INSERT INTO error_attributes (name, value, event, position) values ($1, $2, $3, $4)`,
			attr.Name, attr.Value, eventID, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func loadEvents(tx *sql.Tx, start, end uint64) (events []*Event, err error) {
	rows, err := tx.Query(`SELECT * FROM events WHERE id >= $1 AND id <= $2`,
		start, end)
	if err != nil {
		return
	}

	defer rows.Close()

	for rows.Next() {
		var ev Event
		err = rows.Scan(&ev.Serial, &ev.When, &ev.Received, &ev.Level,
			&ev.Actor, &ev.Event, &ev.Signature)
		if err != nil {
			return
		}

		events = append(events, &ev)
	}

	for i := range events {
		err = loadAttributes(tx, events[i])
	}

	return
}

func loadAttributes(tx *sql.Tx, ev *Event) error {
	rows, err := tx.Query(`SELECT name, value FROM attributes
			      WHERE event = $1 ORDER BY position`,
		ev.Serial)
	if err != nil {
		return err
	}

	defer rows.Close()

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

func getSignature(tx *sql.Tx, serial uint64) ([]byte, error) {
	var sig []byte
	err := tx.QueryRow(`SELECT signature FROM events WHERE id=$1`,
		serial).Scan(&sig)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func loadEvent(tx *sql.Tx, serial uint64) (*Event, error) {
	var ev Event

	row := tx.QueryRow(`SELECT * FROM events WHERE id=$1`, serial)
	err := row.Scan(&ev.Serial, &ev.When, &ev.Received, &ev.Level,
		&ev.Actor, &ev.Event, &ev.Signature)
	if err != nil {
		return nil, err
	}

	err = loadAttributes(tx, &ev)
	if err != nil {
		return nil, err
	}

	return &ev, nil
}

func (l *Logger) verifyEvent(tx *sql.Tx, serial uint64) error {
	var prev []byte
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	if serial > 0 {
		prev, err = getSignature(tx, serial-1)
		if err != nil {
			return err
		}
	}

	ev, err := loadEvent(tx, serial)
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
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	for i := uint64(0); i < l.counter; i++ {
		err = l.verifyEvent(tx, i)
		if err != nil {
			log.Println("Signature failure on event", i)
			return err
		}
	}

	l.lastSignature, err = getSignature(tx, l.counter-1)

	return nil
}

func loadErrorAttributes(tx *sql.Tx, ev *Event) error {
	rows, err := tx.Query(`SELECT name, value FROM error_attributes
			      WHERE event = $1 ORDER BY position`,
		ev.Serial)
	if err != nil {
		return err
	}

	defer rows.Close()

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

func loadErrors(tx *sql.Tx, start, end uint64) (events []*ErrorEvent, err error) {
	rows, err := tx.Query(`SELECT * FROM error_events WHERE serial >= $1 AND serial <= $2`, start, end)
	if err != nil {
		return
	}

	defer rows.Close()

	for rows.Next() {
		var ev Event
		var errEv ErrorEvent
		var eventID uint64

		err = rows.Scan(&eventID, &ev.Serial, &ev.When, &ev.Received, &ev.Level, &ev.Actor, &ev.Event)
		if err != nil {
			events = nil
			return
		}

		err = loadErrorAttributes(tx, &ev)
		if err != nil {
			events = nil
			return
		}

		err = tx.QueryRow(`SELECT timestamp, message FROM errors WHERE event=$1`, eventID).Scan(&errEv.When, &errEv.Message)
		if err != nil {
			events = nil
			return
		}

		errEv.Event = &ev
		events = append(events, &errEv)
	}

	return
}
