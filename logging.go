package istio_debug

import (
	"io"
	"log"
	"os"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

func setupLogger(logFile *os.File, logLevel string) {
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	infoLogger = log.New(multiWriter, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLogger = log.New(multiWriter, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	if logLevel == "debug" {
		log.SetOutput(multiWriter)
	} else {
		log.SetOutput(io.Discard)
	}
}

func logInfo(format string, v ...interface{}) {
	infoLogger.Printf(format, v...)
}

func logError(format string, v ...interface{}) {
	errorLogger.Printf(format, v...)
}
