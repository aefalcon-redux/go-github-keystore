package kslog

import (
	"log"
)

type KsLogger interface {
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Log(args ...interface{})
	Logf(format string, args ...interface{})
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
}

type TestLogger interface {
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Log(args ...interface{})
	Logf(format string, args ...interface{})
}

type KsTestLogger struct {
	TestLogger
}

var _ KsLogger = KsTestLogger{}

func (l KsTestLogger) Debug(args ...interface{}) {
	TestLogger(l).Log(args...)
}

func (l KsTestLogger) Debugf(format string, args ...interface{}) {
	TestLogger(l).Logf(format, args...)
}

type DefaultLogger struct{}

var _ KsLogger = DefaultLogger{}

func (l DefaultLogger) Error(args ...interface{}) {
	log.Println(args...)
}

func (l DefaultLogger) Errorf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l DefaultLogger) Log(args ...interface{}) {
	log.Println(args...)
}

func (l DefaultLogger) Logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l DefaultLogger) Debug(args ...interface{}) {
	log.Println(args...)
}

func (l DefaultLogger) Debugf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

type LogLogger log.Logger

func (l *LogLogger) Error(args ...interface{}) {
	(*log.Logger)(l).Println(args...)
}

func (l *LogLogger) Errorf(format string, args ...interface{}) {
	(*log.Logger)(l).Printf(format, args...)
}

func (l *LogLogger) Log(args ...interface{}) {
	(*log.Logger)(l).Println(args...)
}

func (l *LogLogger) Logf(format string, args ...interface{}) {
	(*log.Logger)(l).Printf(format, args...)
}

func (l *LogLogger) Debug(args ...interface{}) {
	(*log.Logger)(l).Println(args...)
}

func (l *LogLogger) Debugf(format string, args ...interface{}) {
	(*log.Logger)(l).Printf(format, args...)
}
