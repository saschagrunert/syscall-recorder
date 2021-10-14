package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/syslog"
	"os"
	"os/exec"

	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
)

const hookAnnotation = "io.containers.trace-syscall"

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	if hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, ""); err == nil {
		logrus.AddHook(hook)
	}

	logrus.Info("Decoding state from stdin")
	state := &spec.State{}
	reader := bufio.NewReader(os.Stdin)
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("unable to decode spec JSON: %w", err)
	}

	logrus.Infof("Checking PID %d", state.Pid)
	if state.Pid <= 0 {
		return fmt.Errorf("invalid PID %d (must be greater than 0)", state.Pid)
	}

	outputFile, present := state.Annotations[hookAnnotation]
	if !present {
		logrus.Info("Hook annotation not present, doing nothing")
		return nil
	}
	logrus.Infof("Hook points to output file: %s", outputFile)

	output, err := exec.Command(
		"/usr/bin/systemd-run",
		"/usr/local/bin/syscallrecorder",
		"-p", fmt.Sprint(state.Pid),
		"-o", outputFile,
	).Output()
	if err != nil {
		return fmt.Errorf("unable to run hook: %w", err)
	}

	logrus.Infof("Started hook via systemd-run: %s", string(output))
	return nil
}
