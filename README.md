# kumpulan Script

Konten khusus meliputi:

- Modifikasi zona waktu
- Akselerasi BBR
- Warp
- trojan-go build
- konstruksi kotak-sing (mendukung Shadowsocks, ShadowTLS, konfigurasi sekali klik Trojan)
- Deteksi streaming
- Tes garis backhaul
- Tes unduhan jaringan

### Penggunaan skrip koleksi

```
wget -N --no-check-certificate https://raw.githubusercontent.com/DhimasArbi/scripts/main/main.sh && chmod +x main.sh && bash main.sh
```

Setelah sing-box terinstal, Anda dapat menggunakan perintah sing-box secara langsung

### penggunaan skrip onekey sing-box

Skrip ini menggunakan nginx prepend untuk vmess dan trojan shunting, dan secara otomatis membuat situs web statis untuk kamuflase.

- vmess+ws+tls
- trojan+ws+tls
- shadowsocks

```
bash <(curl -s -L https://raw.githubusercontent.com/DhimasArbi/scripts/main/onekey.sh)
```

0. Keluar dari skrip
1. Instal layanan kotak bernyanyi
2. Perbarui layanan kotak bernyanyi
3. Copot layanan sing-box
4. Mulai layanan kotak-bernyanyi
5. Hentikan layanan kotak-bernyanyi
6. Mulai ulang layanan kotak-bernyanyi
7. Periksa konfigurasi sing-box
8. Lihat konfigurasi kotak bernyanyi

# terima kasih

[FranzKafkaYu/sing-box-yes](https://github.com/FranzKafkaYu/sing-box-yes)
<br/>
[SagerNet/sing-box](https://github.com/SagerNet/sing-box)
