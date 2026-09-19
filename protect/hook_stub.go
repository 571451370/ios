//go:build !android && !ios

package protect

func hookInstall(tcpPort, udpPort int) error {
	_ = tcpPort
	_ = udpPort
	return nil
}

func hookUninstall() {}

func hookRescanLoop(done <-chan struct{}) {
	<-done
}
