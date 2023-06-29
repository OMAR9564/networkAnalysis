# Network Analysis

Bu proje, ağ trafiğini yakalayıp analiz etmek için C programlama dili kullanılarak geliştirilmiştir.

## Özellikler

- Ağ cihazlarından paket boyutlarını kontrol etme
- Ağ trafiğini yakalama
- SSH, FTP, HTTP, ICMP, DNS ve NTP trafiğini tespit etme

## Kurulum

1. Bu projeyi bilgisayarınıza indirin:

```bash
  git clone https://github.com/OMAR9564/networkAnalysis.git

2. Projeye giriş yapın:

```bash
cd networkAnalysis

3. Derleyin:

```bash
gcc -o networkA networkA.c -lpcap

4. Çalıştırın:

```bash
./networkA

## Kullanım

Program çalıştırıldığında, bir menü görüntülenecektir. İstenen işlemi seçebilirsiniz:

- Check Input Package Size (Giriş Paketi Boyutunu Kontrol Et): Bu seçenek, gelen paketin boyutunu kontrol eder ve ekrana yazdırır.
- Capture Network Traffic (Ağ Trafik Yakalama): Bu seçenek, ağ trafiğini yakalar ve çeşitli protokollerin tespitini gerçekleştirir.

## Bağımlılıklar

Proje, pcap kütüphanesini kullanır. Bu kütüphane, ağ trafiği yakalamak için kullanılır. Projenin düzgün çalışması için libpcap paketinin yüklü olması gerekmektedir.
