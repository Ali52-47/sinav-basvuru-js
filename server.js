require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const xss = require('xss');
const cors = require('cors');
const app = express();
const port = 3000;
const session = require('express-session');
const rateLimit = require('express-rate-limit');
// Gelen JSON verilerini okumak için
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Gelen verilerdeki zararlı HTML/JS kodlarını temizler (Yeni XSS Koruması)
app.use((req, res, next) => {
    if (req.body) {
        // Formdan gelen tüm verileri tek tek kontrol et
        for (let key in req.body) {
            if (typeof req.body[key] === 'string') {
                // Eğer metin içeriyorsa, xss paketi ile zararlı kodlardan arındır
                req.body[key] = xss(req.body[key]);
            }
        }
    }
    next(); // İşlem bitince diğer aşamaya geç
});
// CORS Koruması: Sadece yetkili adreslerden gelen isteklere izin ver
app.use(cors({
    origin: 'http://localhost:3000', // Şu an kendi bilgisayarından test ettiğin için localhost. Sunucuya yüklediğinde buraya gerçek site adresini (örn: https://basvuru.balikesir.edu.tr) yazmalısın.
    methods: ['GET', 'POST', 'DELETE'], // Sadece bu işlemlere izin ver
    credentials: true // Az önce kurduğumuz session (oturum) çerezlerinin sorunsuz çalışmasına izin verir
}));
// Arayüz dosyalarının bulunduğu public klasörünü dışarı açma
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// Güvenli Oturum (Session) Yönetimi
app.use(session({
    secret: process.env.SESSION_SECRET, // Şifrelemeyi .env'den alır
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // Çerezlere tarayıcıdaki JavaScript(F12) ile erişilmesini engeller (XSS korumasını destekler)
        secure: false, // Şu an kendi bilgisayarında (http) çalıştığın için false. Gerçek sunucuya (https) yüklediğinde bunu true yapmalısın!
        sameSite: 'strict', // Başka sitelerden gelen sahte istekleri (CSRF) engeller
        maxAge: 1000 * 60 * 60 * 2 // Oturum 2 saat sonra otomatik kapanır
    }
    
}));
// Genel API İstek Sınırı (Başvuru formunun spamlanmasını engeller)
const genelLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 100, // Aynı IP'den 15 dakikada en fazla 100 işlem yapılabilir
    message: "Çok fazla işlem yaptınız, lütfen daha sonra tekrar deneyin."
});

// Tüm /api ile başlayan rotalara genel limiti uygula
app.use('/api/', genelLimit);

// Sadece Admin Girişi İçin Özel Sınır (Brute-Force Koruması)
const adminGirisLimiti = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 10, // 15 dakikada maksimum 10 hatalı şifre denemesi
    message: { basarili: false, error: "Çok fazla hatalı giriş denemesi yaptınız. Lütfen 15 dakika sonra tekrar deneyin." }
});
// --- VERİTABANI BAĞLANTISI (PostgreSQL) ---
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'postgres', 
    password: 'Unutma47', 
    port: 5432,
});
// --- EXCEL/CSV ENJEKSİYON KORUMASI ---
const excelVeriTemizle = (veri) => {
    // Eğer veri bir metinse ve tehlikeli karakterlerle (=, +, -, @) başlıyorsa
    if (typeof veri === 'string' && /^[=+\-@]/.test(veri)) {
        // Excel'in formül olarak algılamaması için başına tek tırnak ekle
        return "'" + veri; 
    }
    return veri;
};
pool.connect()
    .then(() => console.log('Veritabanına başarıyla bağlanıldı!'))
    .catch(err => console.error('Veritabanı bağlantı hatası:', err.stack));

// --- DOSYA YÜKLEME AYARLARI (Multer) ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); 
    },
    filename: function (req, file, cb) {
        // Türkçe karakter ve boşluk sorununu kökten çözmek için:
        // Orijinal dosyanın sadece uzantısını (.jpg, .png vb.) alıyoruz
        const uzanti = path.extname(file.originalname);
        
        // Örn: kimlikDosya-1708630998513.jpg şeklinde güvenli ve benzersiz isim oluşturuyoruz
        const guvenliIsim = file.fieldname + '-' + Date.now() + uzanti;
        
        cb(null, guvenliIsim);
    }
});

// Güvenli dosya filtresi
const guvenliDosyaFiltresi = (req, file, cb) => {
    const izinVerilenTipler = ['image/jpeg', 'image/png', 'application/pdf'];
    if (izinVerilenTipler.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('GEÇERSİZ_DOSYA'), false);
    }
};

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5 MB sınır
    }
});
// --- BAŞVURU DURUMU (Açık / Kapalı Kontrolü) ---
let basvurularAcikMi = true;

// --- API ROTALARI ---
// adminGirisLimiti değişkenini (req, res) öncesine ekliyoruz
app.post('/api/admin-giris', adminGirisLimiti, (req, res) => {
    const { kullanici, sifre } = req.body;
    
    // Şifreler .env dosyasından okunuyor
    if (kullanici === process.env.ADMIN_KULLANICI && sifre === process.env.ADMIN_SIFRE) {
        req.session.adminGirisYapti = true; // Oturumu başlat
        res.json({ basarili: true });
    } else {
        res.json({ basarili: false });
    }
});
// Tabloyu canlı güncellemek için başvuruları JSON olarak döndüren API
app.get('/api/basvurular', async (req, res) => {
    // Sadece giriş yapmış admin erişebilir
    if (!req.session.adminGirisYapti) {
        return res.status(403).json({ error: "Yetkisiz erişim!" });
    }

    try {
        // Tüm başvuruları en yeniden en eskiye doğru çek
        const sonuc = await pool.query('SELECT * FROM basvurular ORDER BY basvuru_tarihi DESC');
        
        // Verileri ön yüze (frontend) gönder
        res.json(sonuc.rows);
    } catch (error) {
        console.error("Veri çekme hatası:", error);
        res.status(500).json({ error: 'Veriler alınamadı' });
    }
});
// Örnek Kullanım:
app.get('/api/excel-indir', async (req, res) => {
    // Sadece admin erişebilir kontrolü (daha önce eklemiştik)
    if (!req.session.adminGirisYapti) {
        return res.status(403).json({ error: "Yetkisiz erişim!" });
    }

    try {
        const sonuc = await pool.query('SELECT * FROM basvurular ORDER BY basvuru_tarihi DESC');
        
        // Veritabanından gelen verileri Excel'e göndermeden önce temizle
        const guvenliVeriler = sonuc.rows.map(satir => {
            const temizSatir = {};
            for (let anahtar in satir) {
                temizSatir[anahtar] = excelVeriTemizle(satir[anahtar]);
            }
            return temizSatir;
        });

        // Burada guvenliVeriler değişkenini kullanarak Excel dosyanı oluşturabilirsin...
        
    } catch (error) {
        console.error("Excel veri çekme hatası:", error);
        res.status(500).json({ error: 'İşlem başarısız' });
    }
});
// Ana Sayfa Yönlendirmesi
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Başvuru durumunu öğrenme API'si
app.get('/api/durum', (req, res) => {
    res.json({ acikMi: basvurularAcikMi });
});

// Admin panelinden başvuru durumunu değiştirme API'si
app.post('/api/durum-degistir', (req, res) => {
    basvurularAcikMi = !basvurularAcikMi;
    res.json({ acikMi: basvurularAcikMi });
});
// --- Sınav Dilleri API İşlemleri ---

// 1. Tüm dilleri getir (Öğrenci ve Admin formu için)
app.get('/api/diller', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM sinav_dilleri ORDER BY id ASC');
        res.json(result.rows);
    } catch (err) {
        console.error("Dil getirme hatası:", err);
        res.status(500).send("Sunucu hatası");
    }
});

// 2. Yeni dil ekle (Admin Paneli için)
app.post('/api/diller', async (req, res) => {
    try {
        const { dil_adi } = req.body;
        if (!dil_adi) {
            return res.status(400).json({ basarili: false, mesaj: "Dil adı boş olamaz" });
        }
        await pool.query('INSERT INTO sinav_dilleri (dil_adi) VALUES ($1)', [dil_adi]);
        res.json({ basarili: true, mesaj: "Dil başarıyla eklendi" });
    } catch (err) {
        console.error("Dil ekleme hatası:", err);
        res.status(500).json({ basarili: false });
    }
});

// 3. Dil sil (Admin Paneli için)
app.delete('/api/diller/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('DELETE FROM sinav_dilleri WHERE id = $1', [id]);
        res.json({ basarili: true, mesaj: "Dil silindi" });
    } catch (err) {
        console.error("Dil silme hatası:", err);
        res.status(500).json({ basarili: false });
    }
});
// Yeni Başvuru Kaydetme (Güvenlik Filtreli)
app.post('/api/basvuru', function (req, res) {
    // Multer ile dosya yükleme işlemini bir fonksiyon olarak çalıştırıyoruz
    upload.fields([{ name: 'kimlikDosya', maxCount: 1 }, { name: 'fotograf', maxCount: 1 }])(req, res, async function (err) {
        
        // --- 1. GÜVENLİK VE HATA KONTROLÜ ---
        if (err) {
            if (err.message === 'GEÇERSİZ_DOSYA') {
                return res.send("<script>alert('Güvenlik uyarısı: Sadece JPG, PNG veya PDF dosyaları yükleyebilirsiniz!'); window.history.back();</script>");
            }
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.send("<script>alert('Dosya boyutu 5MB\\'dan büyük olamaz!'); window.history.back();</script>");
            }
            return res.send("<script>alert('Dosya yüklenirken bir hata oluştu.'); window.history.back();</script>");
        }

        // --- 2. BAŞVURU SİSTEMİ AÇIK/KAPALI KONTROLÜ ---
        if (!basvurularAcikMi) {
            return res.send("<script>alert('Şu anda yeni başvuru alınmamaktadır, sistem kapatılmıştır!'); window.location.href='/index.html';</script>");
        }

        // --- 3. VERİTABANI KAYIT İŞLEMLERİ ---
        try {
            const d = req.body;
            
            // req.files üzerinden gelen dosyaların yollarını güvenli bir şekilde alıyoruz
            const kimlikYolu = (req.files && req.files['kimlikDosya']) ? '/uploads/' + req.files['kimlikDosya'][0].filename : '';
            const fotografYolu = (req.files && req.files['fotograf']) ? '/uploads/' + req.files['fotograf'][0].filename : '';

            const sql = `
                INSERT INTO basvurular 
                (ad_soyad, tc_no, dogum_tarihi, dogum_yeri, eposta, sinav_dili, ogrenim_durumu, ogrenci_no, fakulte, bolum, mezuniyet, adres, telefon, kimlik_dosya_yolu, fotograf_yolu) 
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) 
                RETURNING id
            `;
            const veriler = [
                d.adSoyad, d.tcNo, d.dogumTarihi, d.dogumYeri, d.eposta, d.sinavDili, 
                d.ogrenimDurumu, d.ogrenciNo, d.fakulte, d.bolum, d.mezuniyet, 
                d.adres, d.telefon, kimlikYolu, fotografYolu
            ];

            await pool.query(sql, veriler);
            
            res.send("<script>alert('Başvurunuz başarıyla alındı!'); window.location.href='/index.html';</script>");
        } catch (error) {
            console.error("Kayıt Hatası:", error);
            res.status(500).send("Sunucu hatası oluştu, başvuru kaydedilemedi.");
        }
    });
});

// Başvuruları Listeleme
app.get('/api/basvurular', async (req, res) => {
    // Giriş yapmamış kişilerin verilere erişmesini engeller
    if (!req.session.adminGirisYapti) {
        return res.status(403).json({ error: "Yetkisiz erişim!" });
    }

    try {
        const sonuc = await pool.query('SELECT * FROM basvurular ORDER BY basvuru_tarihi DESC');
        res.json(sonuc.rows);
    } catch (error) {
        console.error("Veri çekme hatası:", error);
        res.status(500).json({ error: 'Veriler getirilemedi' });
    }
});

// Başvuru Silme
app.delete('/api/basvurular/:id', async (req, res) => {
    try {
        const id = req.params.id;
        await pool.query('DELETE FROM basvurular WHERE id = $1', [id]);
        res.json({ message: 'Kayıt başarıyla silindi' });
    } catch (error) {
        console.error("Silme hatası:", error);
        res.status(500).json({ error: 'Kayıt silinemedi' });
    }
});

// --- SUNUCUYU BAŞLATMA ---
app.listen(port, () => {
    console.log(`Sunucu http://localhost:${port} adresinde çalışıyor...`);
});
// Başvuru Durumu Güncelleme API'si (Onay/Red)
app.post('/api/basvuru-durum', async (req, res) => {
    try {
        const { id, yeniDurum, redSebebi } = req.body;
        
        // Veritabanını güncelle
        await pool.query(
            'UPDATE basvurular SET durum = $1, red_sebebi = $2 WHERE id = $3', 
            [yeniDurum, redSebebi || null, id]
        );
        
        // Not: İleride buraya "Eğer yeniDurum 'Reddedildi' ise öğrenciye redSebebi'ni içeren bir mail at" kodu eklenecek.
        
        res.json({ basarili: true });
    } catch (err) {
        console.error("Durum güncelleme hatası:", err);
        res.status(500).json({ basarili: false });
    }
});