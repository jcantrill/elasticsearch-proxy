package logging

import (
	"os"
	log "github.com/sirupsen/logrus"
)

func init() {
	logLevel := os.Getenv("LOGLEVEL")
	if logLevel == "" {
		logLevel = "warn"
	}
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		level = log.WarnLevel
		log.Infof("Setting loglevel to 'warn' as unable to parse %s", logLevel)
	}
	log.SetLevel(level)
}

func Printf(msg string, args...interface{}) {
	log.Printf(msg, args...)
}
func Debugf(msg string, args...interface{}) {
	log.Debugf(msg, args...)
}
func Debug(msg string) {
	log.Debug(msg)
}
func Errorf(msg string, args...interface{}) {
	log.Errorf(msg, args...)
}
func Fatalf(msg string, args...interface{}) {
	log.Fatalf(msg, args...)
}
func Trace(msg string) {
	log.Trace(msg)
}
func Tracef(msg string, args...interface{}) {
	log.Tracef(msg, args...)
}