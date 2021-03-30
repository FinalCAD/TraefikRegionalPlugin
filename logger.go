package TraefikRegionalPlugin

import (
	"log"
	"os"
)

type Logger struct {
	level          int
	debugLog       *log.Logger
	informationLog *log.Logger
	warningLog     *log.Logger
	errorLog       *log.Logger
}

const (
	Debug       = "Debug"
	Information = "Information"
	Warning     = "Warning"
	Error       = "Error"
)

func (logger *Logger) SetLevel(level string) {
	switch level {
	case Debug:
		logger.level = 0
		break
	case Information:
		logger.level = 1
		break
	case Warning:
		logger.level = 2
		break
	case Error:
		logger.level = 3
		break
	}
}
func (logger *Logger) LogDebug(message string) {
	if !(logger.level <= 0) {
		return
	}
	logger.debugLog.Println(message)
}
func (logger *Logger) LogInformation(message string) {
	if !(logger.level <= 1) {
		return
	}
	logger.informationLog.Println(message)
}
func (logger *Logger) LogWarning(message string) {
	if !(logger.level <= 2) {
		return
	}
	logger.warningLog.Println(message)
}
func (logger *Logger) LogError(message string) {
	if !(logger.level <= 3) {
		return
	}
	logger.errorLog.Println(message)
}

var Log *Logger = &Logger{
	level:          1,
	debugLog:       log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime),
	informationLog: log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime),
	warningLog:     log.New(os.Stdout, "WARN: ", log.Ldate|log.Ltime),
	errorLog:       log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime),
}
