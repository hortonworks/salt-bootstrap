package saltboot

import "log"

type closable interface {
	Close() error
}

func closeIt(target closable) {
	if err := target.Close(); err != nil {
		log.Printf("[Utils] [ERROR] couldn't close target: %s", err.Error())
	}
}
