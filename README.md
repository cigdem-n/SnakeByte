# SnakeByte 🐍
**SnakeByte** — Güvenlik araştırmacıları ve pentesterlar için geliştirilmiş güçlü bir WAF Bypass Kodlama ve Kod Çözme aracıdır.

---

## Özellikler

- Birçok kodlama ve kod çözme yöntemi destekler:
  - URL Kodlama / Kod Çözme
  - Base64 Kodlama / Kod Çözme
  - HTML Entity Kodlama / Kod Çözme
  - Unicode Kodlama / Kod Çözme
  - Hex Kodlama / Kod Çözme
  - ROT13 Kodlama / Kod Çözme
  - Çift URL Kodlama / Kod Çözme
  - Karma Kodlama (URL + Base64) / Kod Çözme
  - Yaygın kodlamalar için otomatik tahmini kod çözme
- Kullanıcı dostu komut satırı arayüzü, çoklu dil desteği (İngilizce & Türkçe)
- Dosyalardan payload okuyabilir ve kodlanmış/çözülmüş sonuçları kaydedebilir
- Hafif ve kullanımı kolay

---

## Kurulum

1. Depoyu klonlayın:
```bash
git clone https://github.com/cigdem-n/SnakeByte.git
cd SnakeByte
--
--
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
--
Gerekli Python modülleri varsa yükleyin (bu projede standart kütüphaneler kullanılmıştır, ekstra modül gerekmez).


Kullanım
--
python waf_bypass.py
--
Öncelikle dil seçimi yapın (Türkçe veya İngilizce).

Ardından kodlama (Encode) veya kod çözme (Decode) modunu seçin.

İlgili menüden yapmak istediğiniz işlemi seçin ve payload girin.

Dosyadan işlem yapmak istiyorsanız, dosya yolunu belirtin ve talimatları takip edin.

Bu proje MIT Lisansı altında lisanslanmıştır.
