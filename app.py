import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# --- A. Uygulama ve Veritabanı Yapılandırması ---
app = Flask(__name__)
# Gizli anahtar (Çok önemli! Gerçek projede bunu gizli tutun.)
app.config['SECRET_KEY'] = 'sizin_cok_gizli_anahtariniz_burada_olmali' 
# SQLite Veritabanı Yolu
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login' # Giriş yapılmamışsa bu sayfaya yönlendir

# ----------------------------------------------------
# *** B. Veritabanı Modelleri (Tablolar) - YENİ KONUM ***
# ----------------------------------------------------

class User(UserMixin, db.Model):
    """Admin Kullanıcısı için Model"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Version(db.Model):
    """Sürüm Bilgileri ve Yama Notları (2)"""
    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(20), unique=True, nullable=False)
    release_date = db.Column(db.DateTime, default=datetime.utcnow)
    patch_notes = db.Column(db.Text, nullable=False) # Yama notları (2)
    download_url = db.Column(db.String(500), nullable=False) # Drive/Github URL (3)
    is_active = db.Column(db.Boolean, default=True) # Uygulama hizmet durumu (4)
    download_count = db.Column(db.Integer, default=0) # İndirme istatistikleri (10)

# app.py dosyasında, Version modelinden hemen sonra ekleyin:

class Feedback(db.Model):
    """Kullanıcı Geri Bildirimleri için Model"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False) # Adminin okuyup okumadığını takip etmek için
# --- C. Kullanıcı Yükleyici ve Uygulama Oluşturucu ---

@login_manager.user_loader
def load_user(user_id):
    # Modeli artık gördüğü için hata vermez
    return User.query.get(int(user_id))

# İlk çalışmada veritabanını oluşturur ve varsayılan Admin kullanıcısını ekler
with app.app_context():
    db.create_all()
    # Eğer hiç admin yoksa, bir tane oluştur: (SİZ BU ŞİFREYİ KESİNLİKLE DEĞİŞTİRİN!)
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin')
        admin_user.set_password('cokgizlisifre') # ŞİFRENİZİ BURAYA YAZIN
        db.session.add(admin_user)
        db.session.commit()
        print("!!! Admin kullanıcı oluşturuldu: Kullanıcı Adı: admin, Şifre: cokgizlisifre !!!")

# --- D. Site Rotası (index.html'i göster) ---

@app.route('/')
def index():
    # Modeli artık gördüğü için hata vermez
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    all_versions = Version.query.order_by(Version.release_date.desc()).all()

    # index.html'e dinamik verileri gönderir
    return render_template('index.html', latest_version=latest_version, all_versions=all_versions)

# --- E. İndirme Rotası (İstatistik Tutma - 10) ---

@app.route('/indir/son-surum')
def download_file():
    # Modeli artık gördüğü için hata vermez
    latest_version = Version.query.order_by(Version.release_date.desc()).first()
    
    if not latest_version:
        flash("Hata: İndirilecek aktif bir sürüm bulunamadı.", 'error')
        return redirect(url_for('index'))

    # 1. İndirme sayacını artır (İstatistik - 10)
    latest_version.download_count += 1
    db.session.commit()
    
    # 2. Kullanıcıyı Drive/GitHub linkine yönlendir (3)
    return redirect(latest_version.download_url)

# --- F. Admin Giriş Rotası ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Modeli artık gördüğü için hata vermez
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Kullanıcı adı veya şifre hatalı.', 'error')
            
    # app.py dosyasına yeni rota ekleyin

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    email = request.form.get('email')
    message = request.form.get('message')

    if not message:
        flash("Lütfen bir mesaj yazın.", 'error')
        return redirect(url_for('index') + '#feedback') # Hata durumunda formu göster

    try:
        new_feedback = Feedback(email=email, message=message)
        db.session.add(new_feedback)
        db.session.commit()
        flash('Geri bildiriminiz başarıyla iletildi. Teşekkür ederiz!', 'success')
    except Exception as e:
        flash('Geri bildirim gönderilirken bir hata oluştu.', 'error')
        db.session.rollback()
        
    return redirect(url_for('index') + '#feedback')
    
    # (NOT: Admin girişi için şimdilik sade bir HTML yazalım.)
    return '''
        <h1 style="text-align:center;">Admin Girişi</h1>
        <form method="POST" style="max-width:300px; margin: 0 auto; padding:20px; border:1px solid #ccc;">
            <label>Kullanıcı Adı:</label><br>
            <input type="text" name="username" required><br><br>
            <label>Şifre:</label><br>
            <input type="password" name="password" required><br><br>
            <button type="submit">Giriş Yap</button>
        </form>
    '''

# --- G. Admin Dashboard Rotası (YENİ: Şablonu kullanır) ---

# app.py dosyasında @app.route('/admin/dashboard') fonksiyonunu bulun ve güncelleyin:

@app.route('/admin/dashboard')
@login_required 
def admin_dashboard():
    # ... (Mevcut kod) ...
    all_versions = Version.query.order_by(Version.release_date.desc()).all()
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    total_downloads = sum([v.download_count for v in all_versions])
    
    # YENİ: Okunmamış geri bildirimleri çek
    unprocessed_feedback = Feedback.query.filter_by(is_read=False).order_by(Feedback.timestamp.desc()).all() 
    
    return render_template('admin_dashboard.html', 
                           all_versions=all_versions,
                           latest_version=latest_version,
                           total_downloads=total_downloads,
                           unprocessed_feedback=unprocessed_feedback) # Yeni veriyi gönder
    
# --- I. Yeni Sürüm Ekleme Rotası (Admin Paneli'nin Ana İşlevi) ---
# app.py dosyasına yeni rota ekleyin

from flask import jsonify # Bu import'u en üste eklediğinizden emin olun

@app.route('/api/v1/latest_version')
def latest_version_api():
    """10. Uygulamanın Sürüm Kontrolü İçin API"""
    
    # Sadece aktif ve en son yayınlanmış sürümü çekiyoruz.
    latest = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()

    if latest:
        # Uygulamanızın ihtiyacı olan verileri JSON formatında sunuyoruz.
        # patch_notes'u temiz metin olarak veya liste olarak gönderebilirsiniz.
        return jsonify({
            'status': 'ok',
            'version': latest.version_number,
            'release_date': latest.release_date.isoformat(),
            'notes': latest.patch_notes, # Uygulama içinde gösterilecek notlar
            'download_url': url_for('download_file', _external=True) # İndirme linkini doğrudan ver
        })
    else:
        return jsonify({
            'status': 'error',
            'message': 'No active version available.'
        }), 404 # 404 Not Found durum kodu
# app.py dosyasına yeni rota ekleyin

@app.route('/feed')
def rss_feed():
    """6. Yeni Sürümleri Bildiren RSS Feed Rotası"""
    # Tüm sürümleri yayın tarihine göre çekiyoruz
    all_versions = Version.query.order_by(Version.release_date.desc()).all()
    
    # XML içeriği gönderiyoruz
    response = render_template('rss_feed.xml', all_versions=all_versions)
    
    # Tarayıcıya/Okuyucuya içeriğin XML olduğunu bildiririz.
    return response, 200, {'Content-Type': 'application/rss+xml; charset=utf-8'}
        
@app.route('/admin/versions/add', methods=['POST'])
@login_required
def admin_add_version():
    try:
        version_number = request.form.get('version_number')
        download_url = request.form.get('download_url')
        patch_notes = request.form.get('patch_notes')
        is_active = request.form.get('is_active') is not None 

        if not version_number or not download_url:
            flash("Sürüm Numarası ve İndirme Linki zorunludur.", 'error')
            return redirect(url_for('admin_dashboard'))

        # Eğer yeni sürüm aktif olarak işaretlendiyse, diğer tüm aktif sürümleri pasif yap
        if is_active:
            # Modeli artık gördüğü için hata vermez
            Version.query.update({Version.is_active: False})
        
        # Yeni sürüm nesnesini oluştur
        new_version = Version(
            version_number=version_number,
            download_url=download_url,
            patch_notes=patch_notes,
            is_active=is_active,
            release_date=datetime.utcnow()
        )
        
        db.session.add(new_version)
        db.session.commit()
        flash(f'Sürüm **v{version_number}** başarıyla yayınlandı!', 'success')
        
    except Exception as e:
        db.session.rollback()
        # Genellikle tekillik (UNIQUE) hatası burada yakalanır
        flash(f'Sürüm eklenirken bir hata oluştu: {str(e)}', 'error')
        
    return redirect(url_for('admin_dashboard'))

# --- H. Çıkış Rotası ---

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('index'))


# app.py dosyasının en alt kısmı:

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # YEREL GELİŞTİRME ORTAMI İÇİN
    app.run(debug=True)

# ----------------------------------------------------------------------
# PYTHONANYWHERE İÇİN NOT: 
# Bu blok PythonAnywhere'da çalışmayacaktır. PythonAnywhere, uygulamanızı 
# WSGI dosyası üzerinden çalıştırır ve 'application' adında bir değişkene 
# ihtiyacı vardır. app.py'nin en üstündeki 'app = Flask(__name__)' değişkeni 
# PythonAnywhere için yeterlidir. Ancak, dosya adı app.py değilse, 
# app.py içinden Flask uygulamasını (app değişkenini) dışa aktarmanız gerekir.
# ----------------------------------------------------------------------