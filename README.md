# 🛡️ Sıfır Güven (Zero Trust) DevSecOps Masaüstü Tüneli (V2)

Bu proje, dışarıdan veya ekiplerden gelen kodları şirket ağına sokmadan önce **Sıfır Güven (Zero Trust)** felsefesiyle yerel makinede analiz eden, dilden bağımsız (evrensel) ve kapalı devre çalışan kurumsal bir siber güvenlik tünelidir.

## 🚀 Projenin Amacı
Geleneksel virüs tarayıcıların aksine, bu sistem doğrudan kaynak koddaki mimari hataları, sızdırılmış (hardcoded) kimlik bilgilerini ve enjeksiyon zafiyetlerini arar. Kodun canlı sisteme veya şirketin iç ağına (örneğin bir iç web portalına) girmeden önce %100 izole bir şekilde masaüstünde taranmasını sağlar.

---

## 🧠 6 Katmanlı Güvenlik Mimarisi

Sistem, kodu körü körüne taramaz; aşağıdaki 6 katmanlı güvenlik süzgecinden geçirir:

1. **Sözdizimi ve Çökme Kontrolü:** Kodun çalışabilirliğini ve ölü kodları (unreachable code) denetler.
2. **Veri Akışı ve Enjeksiyon:** Kullanıcı girdisinin tehlikeli fonksiyonlara ulaşıp ulaşmadığını AST (Abstract Syntax Tree) üzerinden takip eder (SQLi, Command Injection).
3. **Yüksek Entropi ve Sızıntı Avı:** Kod içine gizlenmiş gerçek veritabanı şifreleri ve bulut anahtarlarını, matematiksel Shannon Entropisi ile analiz ederek sahte/gerçek ayrımı yapar.
4. **Tedarik Zinciri (SCA):** Projedeki dış kütüphanelerin (Örn: `npm`, `pip` paketleri) güncel bir **CVE** (bilinen zafiyet) barındırıp barındırmadığını Google OSV veritabanından denetler.
5. **Zayıf Yapılandırma:** Kırılmış algoritmaların (MD5 vb.) kullanımını engeller.
6. **Mantıksal Hatalar ve Anti-Kalıplar:** Zafiyet olmasa bile, eksik güvenlik katmanlarını (Örn: Express.js'te unutulmuş CSRF middleware'leri) mimari düzeyde yakalar.

---

## 🛠️ Kullanılan Kurumsal Teknolojiler (Motorlar)

Sistemin arkasında dünyanın en büyük teknoloji şirketlerinin CI/CD süreçlerinde kullandığı üç farklı siber güvenlik motoru (AI ve Kural tabanlı) orkestre edilmektedir:

*   **[Semgrep](https://semgrep.dev/):** Kodun metnine değil, çalışma ağacına (AST) odaklanan, siber güvenlik dünyasının en güçlü ve hafif SAST aracıdır.
*   **[Detect-Secrets](https://github.com/Yelp/detect-secrets):** Yelp mühendisleri tarafından geliştirilmiş, yüksek karakter karmaşıklığı analizleriyle sızıntıları yakalayan savunma modülü.
*   **[OSV-Scanner](https://osv.dev/):** Google'ın "Open Source Vulnerability" veritabanını kullanarak tedarik zinciri (bağımlılık) güvenliğini sağlayan araç.
*   **Arayüz & Raporlama:** `CustomTkinter` (Modern UI) ve `Jinja2` (HTML Şablon Motoru).

---

## ⚙️ Güvenlik ve Kararlılık (Stability) Kalkanları

Bu araç bir yöneticinin makinesinde çalışırken asla çökmemesi için özel kalkanlarla donatılmıştır:
*   **UTF-8 ve Yabancı Dil Koruması:** Bozuk formatlı veya Çince karakterler içeren bir kod tarandığında, işletim sisteminin `UnicodeDecodeError` vermesi engellenir.
*   **İnternet Kesintisi Kalkanı (Offline Mod):** `Semgrep` ve `Detect-Secrets` tamamen çevrimdışı (internetsiz) çalışır. İnternet yoksa sistem çökmez, yalnızca OSV-Scanner atlanır.
*   **Windows Klasör Yolu Koruması (Absolute Path Bypass):** Motorların uzun Windows klasör yollarında boğulmasını veya 0 dosya taramasını engellemek için, motorlar hedefin bulunduğu dizinin doğrudan kalbine yerleştirilerek çalıştırılır.

---

## 💻 Kullanım (Yöneticiler İçin)

1. `SifirGuvenTuneli.exe` dosyasını çalıştırın.
2. Arayüzden **"Tek Dosya Seç"** veya **"Klasör (Proje) Seç"** butonuna tıklayın.
3. Hedefi belirledikten sonra **"TÜNELİ BAŞLAT"** butonuna basın.
4. Sistem `node_modules` veya `.venv` dahil en gizli klasörlere bile inerek derin tarama yapar.
5. Tarama bittiğinde, sonuçlar şık bir **HTML Özet Panosu (Dashboard)** halinde varsayılan web tarayıcınızda otomatik olarak açılır. Kırmızı (Kritik) ve Sarı (Uyarı) renklere göre önceliklendirme yapabilirsiniz.

---

## 📜 Lisans & Sorumluluk
Bu yazılım kurum içi kullanım için özel olarak, "Zero-Trust" ilkelerine bağlı kalarak tasarlanmıştır.

*Developed & Architected for Maximum Security.*
