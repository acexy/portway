// Package logging provides the project's structured logging entry point.
package logging

import (
	"fmt"

	"github.com/acexy/golang-toolkit/logger"
	"github.com/acexy/portway/internal/config"
)

// Logger adds stable project fields to messages written through golang-toolkit.
type Logger struct {
	component string
	fields    map[string]any
}

// EnableConsole configures the process-wide console logger from project configuration.
func EnableConsole(level config.LogLevel) error {
	toolkitLevel, err := toolkitLogLevel(level)
	if err != nil {
		return err
	}
	logger.EnableConsole(toolkitLevel)
	return nil
}

// New creates a logger associated with one project component.
func New(component string) *Logger {
	return &Logger{component: component}
}

// WithField creates a logger that includes one additional stable field.
func (l *Logger) WithField(field string, value any) *Logger {
	return l.WithFields(map[string]any{field: value})
}

// WithFields creates a logger that includes additional stable fields.
func (l *Logger) WithFields(fields map[string]any) *Logger {
	combinedFields := make(map[string]any, len(l.fields)+len(fields))
	for field, value := range l.fields {
		combinedFields[field] = value
	}
	for field, value := range fields {
		combinedFields[field] = value
	}
	return &Logger{
		component: l.component,
		fields:    combinedFields,
	}
}

// Trace writes detailed protocol and lifecycle diagnostics.
func (l *Logger) Trace(message string) {
	entry := logger.Logrus().WithField("component", l.component)
	for field, value := range l.fields {
		entry = entry.WithField(field, value)
	}
	entry.Trace(message)
}

// TraceWithField writes a trace message with one event-specific field.
func (l *Logger) TraceWithField(message string, field string, value any) {
	entry := logger.Logrus().WithField("component", l.component)
	for stableField, stableValue := range l.fields {
		entry = entry.WithField(stableField, stableValue)
	}
	entry.WithField(field, value).Trace(message)
}

// TraceWithFields writes a trace message with event-specific fields.
func (l *Logger) TraceWithFields(message string, fields map[string]any) {
	entry := logger.Logrus().WithField("component", l.component)
	for stableField, stableValue := range l.fields {
		entry = entry.WithField(stableField, stableValue)
	}
	for field, value := range fields {
		entry = entry.WithField(field, value)
	}
	entry.Trace(message)
}

// Info writes an informational message.
func (l *Logger) Info(message string) {
	entry := logger.Logrus().WithField("component", l.component)
	for field, value := range l.fields {
		entry = entry.WithField(field, value)
	}
	entry.Info(message)
}

// InfoWithField writes an informational message with one structured field.
func (l *Logger) InfoWithField(message string, field string, value any) {
	entry := logger.Logrus().WithField("component", l.component)
	for stableField, stableValue := range l.fields {
		entry = entry.WithField(stableField, stableValue)
	}
	entry.WithField(field, value).Info(message)
}

// Error writes an error message with its cause.
func (l *Logger) Error(message string, cause error) {
	entry := logger.Logrus().WithField("component", l.component)
	for field, value := range l.fields {
		entry = entry.WithField(field, value)
	}
	entry.WithError(cause).Error(message)
}

func toolkitLogLevel(level config.LogLevel) (logger.Level, error) {
	switch level {
	case config.LogLevelTrace:
		return logger.TraceLevel, nil
	case config.LogLevelDebug:
		return logger.DebugLevel, nil
	case config.LogLevelInfo:
		return logger.InfoLevel, nil
	case config.LogLevelWarn:
		return logger.WarnLevel, nil
	case config.LogLevelError:
		return logger.ErrorLevel, nil
	default:
		return logger.InfoLevel, fmt.Errorf("unsupported log level %q", level)
	}
}
