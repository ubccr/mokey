package server

// This code was adopted from https://github.com/neko-neko/echo-logrus
//
// The MIT License (MIT)
//
// Copyright (c) 2017 neko-neko
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import (
	"encoding/json"
	"io"

	echolog "github.com/labstack/gommon/log"
	"github.com/sirupsen/logrus"
)

// MyLogger extend logrus.MyLogger
type MyLogger struct {
	*logrus.Logger
}

// Singleton logger
var singletonLogger = &MyLogger{
	Logger: logrus.New(),
}

// Logger return singleton logger
func EchoLogger() *MyLogger {
	return singletonLogger
}

// Print output message of print level
func Print(i ...interface{}) {
	singletonLogger.Print(i...)
}

// Printf output format message of print level
func Printf(format string, i ...interface{}) {
	singletonLogger.Printf(format, i...)
}

// Printj output json of print level
func Printj(j echolog.JSON) {
	singletonLogger.Printj(j)
}

// Debug output message of debug level
func Debug(i ...interface{}) {
	singletonLogger.Debug(i...)
}

// Debugf output format message of debug level
func Debugf(format string, args ...interface{}) {
	singletonLogger.Debugf(format, args...)
}

// Debugj output json of debug level
func Debugj(j echolog.JSON) {
	singletonLogger.Debugj(j)
}

// Info output message of info level
func Info(i ...interface{}) {
	singletonLogger.Info(i...)
}

// Infof output format message of info level
func Infof(format string, args ...interface{}) {
	singletonLogger.Infof(format, args...)
}

// Infoj output json of info level
func Infoj(j echolog.JSON) {
	singletonLogger.Infoj(j)
}

// Warn output message of warn level
func Warn(i ...interface{}) {
	singletonLogger.Warn(i...)
}

// Warnf output format message of warn level
func Warnf(format string, args ...interface{}) {
	singletonLogger.Warnf(format, args...)
}

// Warnj output json of warn level
func Warnj(j echolog.JSON) {
	singletonLogger.Warnj(j)
}

// Error output message of error level
func Error(i ...interface{}) {
	singletonLogger.Error(i...)
}

// Errorf output format message of error level
func Errorf(format string, args ...interface{}) {
	singletonLogger.Errorf(format, args...)
}

// Errorj output json of error level
func Errorj(j echolog.JSON) {
	singletonLogger.Errorj(j)
}

// Fatal output message of fatal level
func Fatal(i ...interface{}) {
	singletonLogger.Fatal(i...)
}

// Fatalf output format message of fatal level
func Fatalf(format string, args ...interface{}) {
	singletonLogger.Fatalf(format, args...)
}

// Fatalj output json of fatal level
func Fatalj(j echolog.JSON) {
	singletonLogger.Fatalj(j)
}

// Panic output message of panic level
func Panic(i ...interface{}) {
	singletonLogger.Panic(i...)
}

// Panicf output format message of panic level
func Panicf(format string, args ...interface{}) {
	singletonLogger.Panicf(format, args...)
}

// Panicj output json of panic level
func Panicj(j echolog.JSON) {
	singletonLogger.Panicj(j)
}

// To logrus.Level
func toLogrusLevel(level echolog.Lvl) logrus.Level {
	switch level {
	case echolog.DEBUG:
		return logrus.DebugLevel
	case echolog.INFO:
		return logrus.InfoLevel
	case echolog.WARN:
		return logrus.WarnLevel
	case echolog.ERROR:
		return logrus.ErrorLevel
	}

	return logrus.InfoLevel
}

// To Echo.log.lvl
func toEchoLevel(level logrus.Level) echolog.Lvl {
	switch level {
	case logrus.DebugLevel:
		return echolog.DEBUG
	case logrus.InfoLevel:
		return echolog.INFO
	case logrus.WarnLevel:
		return echolog.WARN
	case logrus.ErrorLevel:
		return echolog.ERROR
	}

	return echolog.OFF
}

// Output return logger io.Writer
func (l *MyLogger) Output() io.Writer {
	return l.Writer()
}

// SetOutput logger io.Writer
func (l *MyLogger) SetOutput(w io.Writer) {
}

// Level return logger level
func (l *MyLogger) Level() echolog.Lvl {
	return toEchoLevel(l.Logger.Level)
}

// SetLevel logger level
func (l *MyLogger) SetLevel(v echolog.Lvl) {
	l.Logger.Level = toLogrusLevel(v)
}

// SetHeader logger header
// Managed by Logrus itself
// This function do nothing
func (l *MyLogger) SetHeader(h string) {
	// do nothing
}

// Formatter return logger formatter
func (l *MyLogger) Formatter() logrus.Formatter {
	return l.Logger.Formatter
}

// SetFormatter logger formatter
// Only support logrus formatter
func (l *MyLogger) SetFormatter(formatter logrus.Formatter) {
	l.Logger.Formatter = formatter
}

// Prefix return logger prefix
// This function do nothing
func (l *MyLogger) Prefix() string {
	return ""
}

// SetPrefix logger prefix
// This function do nothing
func (l *MyLogger) SetPrefix(p string) {
	// do nothing
}

// Print output message of print level
func (l *MyLogger) Print(i ...interface{}) {
	l.Logger.Print(i...)
}

// Printf output format message of print level
func (l *MyLogger) Printf(format string, args ...interface{}) {
	l.Logger.Printf(format, args...)
}

// Printj output json of print level
func (l *MyLogger) Printj(j echolog.JSON) {
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	l.Logger.Println(string(b))
}

// Debug output message of debug level
func (l *MyLogger) Debug(i ...interface{}) {
	l.Logger.Debug(i...)
}

// Debugf output format message of debug level
func (l *MyLogger) Debugf(format string, args ...interface{}) {
	l.Logger.Debugf(format, args...)
}

// Debugj output message of debug level
func (l *MyLogger) Debugj(j echolog.JSON) {
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	l.Logger.Debugln(string(b))
}

// Info output message of info level
func (l *MyLogger) Info(i ...interface{}) {
	l.Logger.Info(i...)
}

// Infof output format message of info level
func (l *MyLogger) Infof(format string, args ...interface{}) {
	l.Logger.Infof(format, args...)
}

// Infoj output json of info level
func (l *MyLogger) Infoj(j echolog.JSON) {
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	l.Logger.Infoln(string(b))
}

// Warn output message of warn level
func (l *MyLogger) Warn(i ...interface{}) {
	l.Logger.Warn(i...)
}

// Warnf output format message of warn level
func (l *MyLogger) Warnf(format string, args ...interface{}) {
	l.Logger.Warnf(format, args...)
}

// Warnj output json of warn level
func (l *MyLogger) Warnj(j echolog.JSON) {
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	l.Logger.Warnln(string(b))
}

// Error output message of error level
func (l *MyLogger) Error(i ...interface{}) {
	l.Logger.Error(i...)
}

// Errorf output format message of error level
func (l *MyLogger) Errorf(format string, args ...interface{}) {
	l.Logger.Errorf(format, args...)
}

// Errorj output json of error level
func (l *MyLogger) Errorj(j echolog.JSON) {
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	l.Logger.Errorln(string(b))
}

// Fatal output message of fatal level
func (l *MyLogger) Fatal(i ...interface{}) {
	l.Logger.Fatal(i...)
}

// Fatalf output format message of fatal level
func (l *MyLogger) Fatalf(format string, args ...interface{}) {
	l.Logger.Fatalf(format, args...)
}

// Fatalj output json of fatal level
func (l *MyLogger) Fatalj(j echolog.JSON) {
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	l.Logger.Fatalln(string(b))
}

// Panic output message of panic level
func (l *MyLogger) Panic(i ...interface{}) {
	l.Logger.Panic(i...)
}

// Panicf output format message of panic level
func (l *MyLogger) Panicf(format string, args ...interface{}) {
	l.Logger.Panicf(format, args...)
}

// Panicj output json of panic level
func (l *MyLogger) Panicj(j echolog.JSON) {
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	l.Logger.Panicln(string(b))
}
