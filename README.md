# Cyber Toolbox

Kumpulan alat cybersecurity harian dalam satu halaman web statis. Dibuat dengan HTML, Tailwind CDN, dan vanilla JavaScript: tanpa backend, tanpa database, tanpa login, tanpa API key. Semua proses berjalan di browser Anda.

> 100% client-side. Tool 1–5 bekerja sepenuhnya offline (setelah halaman termuat). Tool 6–9 memerlukan koneksi internet dan hanya menghubungi layanan publik gratis yang tercantum di bawah.

## Daftar tool

| # | Tool | Fungsi | Internet |
|---|------|--------|----------|
| 1 | **IOC Extractor** | Ekstrak IPv4, IPv6, URL, domain, email, MD5, SHA1, SHA256, dan CVE dari teks bebas. Opsi refang input, exclude private IP, defang output. Copy per baris, copy all, export CSV/JSON. | – |
| 2 | **Hash & Encode** | SHA-1 dan SHA-256 via `crypto.subtle`, Base64 encode/decode (UTF-8 & URL-safe), URL encode/decode. | – |
| 3 | **JWT Decoder** | Tampilkan header & payload dalam JSON rapi, cek klaim `exp`/`nbf`, status valid/expired, peringatan `alg: none`. Signature tidak diverifikasi. | – |
| 4 | **Password** | Generator password (8–64 karakter, uppercase/lowercase/digits/symbols, exclude ambiguous) dan passphrase. Estimasi entropi, label kekuatan, estimasi waktu tebak. | – |
| 5 | **URL Inspector** | Urai scheme, hostname, port, path, query, fragment. Deteksi punycode/IDN, karakter non-ASCII, campuran skrip (homograph), kredensial di URL, dan cek HTTPS. | – |
| 6 | **Subdomain Finder** | Cek ±180 subdomain umum via DNS-over-HTTPS Cloudflare. Maks 10 request paralel, progress bar, tombol stop, deteksi wildcard DNS, export CSV/JSON. | ✔ |
| 7 | **Website Crawler** | Ambil satu halaman via CORS proxy, parse dengan `DOMParser`, tampilkan title, meta description, link internal/eksternal, script, stylesheet, gambar, form, dan email. Kedalaman 1 level. | ✔ |
| 8 | **Is It Down** | Tiga cek paralel (DNS DoH, HTTP HEAD via proxy, koneksi langsung `no-cors`), status Online / Down / DNS-only / Unknown, waktu respons, riwayat 10 cek terakhir di localStorage. | ✔ |
| 9 | **Network Check** | IP publik, estimasi lokasi & ISP, info `navigator.connection`, status online, user agent, bahasa, timezone, dan latency ke Cloudflare, Google DNS, GitHub. Tombol copy semua. | ✔ |

### Layanan eksternal yang dipakai

| Layanan | Dipakai oleh | Data yang terkirim |
|---------|--------------|--------------------|
| `cdn.tailwindcss.com` | Semua (styling) | Request standar pemuatan script |
| `cloudflare-dns.com` (DoH JSON) | Tool 6, 8 | Nama domain yang dicek |
| `api.allorigins.win` (CORS proxy) | Tool 7, 8 | URL target |
| Target yang Anda masukkan | Tool 8 (koneksi langsung) | Request `no-cors` tanpa cookie |
| `api.ipify.org`, `ipapi.co` | Tool 9 | IP Anda (otomatis terlihat oleh server) |
| `1.1.1.1`, `dns.google`, `github.com` | Tool 9 (latency) | Request kecil tanpa cookie |

Tidak ada telemetry, analytics, atau server milik aplikasi. Semua request memakai `credentials: 'omit'`, `referrerPolicy: 'no-referrer'`, dan timeout maksimal 8 detik. Yang disimpan di `localStorage` hanya preferensi tema, tab terakhir, dan riwayat Is It Down.

## Cara pakai

**Langsung di komputer:** unduh/clone repo ini lalu buka `index.html` di browser modern (Chrome, Edge, Firefox, Safari terbaru). Tidak perlu build atau install apa pun.

```bash
git clone https://github.com/pakhrurrozif/cyber-toolbox.git
cd cyber-toolbox
# buka index.html dengan double-click, atau jalankan server lokal:
python3 -m http.server 8000   # lalu buka http://localhost:8000
```

Catatan:

- Tailwind dimuat dari CDN, jadi tampilan penuh membutuhkan internet saat halaman pertama dibuka. Tanpa CDN, `styles.css` tetap menyediakan warna dan komponen dasar.
- Sebagian browser menonaktifkan `crypto.subtle` atau clipboard pada `file://`. Jika hash tidak muncul, gunakan server lokal (`localhost`) atau GitHub Pages.
- Tekan panah kiri/kanan pada tab bar untuk berpindah tool dengan keyboard.

## Cara deploy ke GitHub Pages

Workflow `.github/workflows/deploy.yml` men-deploy otomatis setiap ada push ke branch `main`.

1. Pastikan kode ada di branch `main`.
2. Buka **Settings → Pages** di repo GitHub.
3. Pada **Build and deployment → Source**, pilih **GitHub Actions** (wajib, dilakukan sekali).
4. Push ke `main`, atau jalankan workflow secara manual dari tab **Actions → Deploy to GitHub Pages → Run workflow**.
5. Situs tersedia di `https://<username>.github.io/cyber-toolbox/`.

## Struktur file

```
index.html                    # markup & layout 9 tool
styles.css                    # tema terang/gelap & komponen
app.js                        # seluruh logika (vanilla JS)
.github/workflows/deploy.yml  # deploy GitHub Pages
README.md
LICENSE
```

## Disclaimer etika

- Gunakan tool ini **hanya pada domain, sistem, dan jaringan yang Anda miliki atau yang Anda punya izin tertulis untuk diuji**.
- Subdomain Finder dan Website Crawler sengaja dibatasi (maks 10 request paralel, kedalaman 1 halaman) agar tidak membebani target. Jangan memodifikasinya untuk scanning massal.
- Website Crawler dan Is It Down memakai proxy publik pihak ketiga. URL yang Anda masukkan terlihat oleh operator proxy. Jangan masukkan URL internal, token, atau data sensitif.
- Network Check mengirim request ke layanan pihak ketiga yang otomatis melihat IP Anda. Jangan gunakan di jaringan sensitif.
- Hasil (status, lokasi IP, entropi password, dsb.) bersifat estimasi dan bukan pengganti audit keamanan profesional.
- Penulis tidak bertanggung jawab atas penyalahgunaan alat ini.

## Lisensi

[MIT](LICENSE)
