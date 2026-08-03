// Package logging provides the project's structured logging entry point.
package logging

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/acexy/golang-toolkit/logger"
	"github.com/acexy/portway/internal/config"
	"github.com/sirupsen/logrus"
)

var consoleFieldPriority = []string{
	"event",
	"client_id",
	"session_id",
	"proxy_type",
	"proxy_name",
	"link_id",
	"remote_address",
	"local_address",
	"result",
	"reason",
	"error_code",
	"duration_ms",
	"error",
}

type consoleFormatter struct{}

func (consoleFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var output bytes.Buffer
	component, _ := entry.Data["component"].(string)
	_, _ = fmt.Fprintf(
		&output,
		"%s %-5s %-15s %s",
		entry.Time.Format("2006-01-02 15:04:05.000"),
		consoleLevel(entry.Level),
		component,
		entry.Message,
	)
	written := map[string]struct{}{"component": {}}
	for _, field := range consoleFieldPriority {
		value, exists := entry.Data[field]
		if !exists {
			continue
		}
		writeConsoleField(&output, field, value)
		written[field] = struct{}{}
	}
	remaining := make([]string, 0, len(entry.Data))
	for field := range entry.Data {
		if _, exists := written[field]; !exists {
			remaining = append(remaining, field)
		}
	}
	sort.Strings(remaining)
	for _, field := range remaining {
		writeConsoleField(&output, field, entry.Data[field])
	}
	output.WriteByte('\n')
	return output.Bytes(), nil
}

func consoleLevel(level logrus.Level) string {
	switch level {
	case logrus.TraceLevel:
		return "TRACE"
	case logrus.DebugLevel:
		return "DEBUG"
	case logrus.InfoLevel:
		return "INFO"
	case logrus.WarnLevel:
		return "WARN"
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		return "ERROR"
	default:
		return strings.ToUpper(level.String())
	}
}

func writeConsoleField(output *bytes.Buffer, field string, value any) {
	text := fmt.Sprint(value)
	if text == "" || strings.ContainsAny(text, " \t\r\n\"=") {
		text = strconv.Quote(text)
	}
	_, _ = fmt.Fprintf(output, " %s=%s", field, text)
}

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
	logger.Logrus().SetFormatter(consoleFormatter{})
	return nil
}

// New creates a logger associated with one project component.
func New(component string) *Logger {
	return &Logger{component: component}
}

// WithComponent creates a logger for a child responsibility while preserving context fields.
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{component: component, fields: l.fields}
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

// Debug writes low-frequency request or connection diagnostics.
func (l *Logger) Debug(message string) {
	entry := logger.Logrus().WithField("component", l.component)
	for field, value := range l.fields {
		entry = entry.WithField(field, value)
	}
	entry.Debug(message)
}

// DebugWithFields writes debug diagnostics with event-specific fields.
func (l *Logger) DebugWithFields(message string, fields map[string]any) {
	entry := logger.Logrus().WithField("component", l.component)
	for stableField, stableValue := range l.fields {
		entry = entry.WithField(stableField, stableValue)
	}
	for field, value := range fields {
		entry = entry.WithField(field, value)
	}
	entry.Debug(message)
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

// InfoWithFields writes an informational event with structured fields.
func (l *Logger) InfoWithFields(message string, fields map[string]any) {
	entry := logger.Logrus().WithField("component", l.component)
	for stableField, stableValue := range l.fields {
		entry = entry.WithField(stableField, stableValue)
	}
	for field, value := range fields {
		entry = entry.WithField(field, value)
	}
	entry.Info(message)
}

// Warn writes a recoverable failure or rejection with its cause.
func (l *Logger) Warn(message string, cause error) {
	entry := logger.Logrus().WithField("component", l.component)
	for field, value := range l.fields {
		entry = entry.WithField(field, value)
	}
	if cause != nil {
		entry = entry.WithError(cause)
	}
	entry.Warn(message)
}

// WarnWithFields writes a recoverable failure with structured fields.
func (l *Logger) WarnWithFields(message string, cause error, fields map[string]any) {
	entry := logger.Logrus().WithField("component", l.component)
	for stableField, stableValue := range l.fields {
		entry = entry.WithField(stableField, stableValue)
	}
	for field, value := range fields {
		entry = entry.WithField(field, value)
	}
	if cause != nil {
		entry = entry.WithError(cause)
	}
	entry.Warn(message)
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
