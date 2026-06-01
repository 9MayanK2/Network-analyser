import socket
import threading

class Sniffer:

    def __init__(self, interface, on_packet):
        self.interface = interface
        self.on_packet = on_packet
        self.running = False
        self._sock = None

    def _open_socket(self):
        ETH_P_ALL = 0x0003
        sock =socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(ETH_P_ALL)
        )
        sock.bind((self.interface, 0))
        return sock

    def _capture_loop(self):
        while self.running:
            try:
                raw_dat, _ = self._sock.recvfrom(65535)
                parsed = self.on_packet(raw_dat)
            except OSError:
                break
            except Exception:
                continue

    def start(self):
        self.running = True
        self._sock = self._open_socket()
        t = threading.Thread(target=self._capture_loop, daemon=True)
        t.start()
        return t

    def stop(self):
        self.running = False
        if self._sock:
            self._sock.close()

