package safeurl

import (
	"strconv"
)

func checkPortAllowed(port string, allowedPorts []int) error {
	porti, err := strconv.Atoi(port)
	if err != nil {
		return &AllowedPortError{port: port}
	}
	if !_isPortAllowed(porti, allowedPorts) {
		return &AllowedPortError{port: port}
	}
	return nil
}

func _isPortAllowed(port int, allowedPorts []int) bool {
	for _, blockedPort := range allowedPorts {
		if port == blockedPort {
			return true
		}
	}
	return false
}
