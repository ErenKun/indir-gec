import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz
from babel.dates import format_datetime # pip install Babel

# --- A. Uygulama ve Veritabanı Yapılandırması ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sizin_cok_gizli_anahtariniz_burada_olmali' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login' 

# --- B. Yardımcı Fonksiyonlar ve Filtreler ---
ISTANBUL_TZ = pytz.timezone('Europe/Istanbul')

@app.template_filter('ist_time')
def ist_time_filter(dt, format='medium'):
    """Tarih-saati UTC'den İstanbul saatine çevirir ve Türkçe formatlar."""
    if dt is None:
        return ""
    try:
        dt_ist = pytz.utc.localize(dt).astimezone(ISTANBUL_TZ)
        return format_datetime(dt_ist, format='dd MMMM yyyy HH:mm', locale='tr')
    except Exception:
        return dt.strftime('%Y-%m-%d %H:%M') # Hata durumunda standart format

# --- C. Veritabanı Modelleri ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Version(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(20), unique=True, nullable=False)
    release_date = db.Column(db.DateTime, default=datetime.utcnow)
    patch_notes = db.Column(db.Text, nullable=False)
    download_url = db.Column(db.String(500), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    download_count = db.Column(db.Integer, default=0)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False) # Zorunlu hale getirildi
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class SiteContent(db.Model):
    """Admin tarafından yönetilen site başlıkları ve metinleri."""
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(100), unique=True, nullable=False) # örn: 'hero_title'
    content = db.Column(db.Text, nullable=False)

class ServiceStatus(db.Model):
    """Uygulama hizmet durumunu yönetir."""
    id = db.Column(db.Integer, primary_key=True)
    status_level = db.Column(db.String(20), default='OK') # OK, MAINTENANCE, MINOR_ISSUE
    message = db.Column(db.String(500), default='Her şey yolunda.')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    
# --- D. Kullanıcı Yükleyici ve Uygulama Oluşturucu ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def initialize_db():
    """Veritabanını oluşturur ve varsayılan verileri ekler."""
    with app.app_context():
        db.create_all()

        # Varsayılan Admin Kullanıcısı
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin')
            admin_user.set_password('cokgizlisifre') # ŞİFRENİZİ BURAYA YAZIN
            db.session.add(admin_user)
        
        # Varsayılan Site İçeriği
        default_contents = {
            'site_title': 'İndirGeç - Hızlı ve Güvenilir Video İndirici',
            'hero_title': 'Tüm Videoları Tek Tıkla İndir',
            'hero_subtitle': 'Gelişmiş özellikler, yüksek hız, Eren KÜN güvencesiyle!',
            'footer_info': '© 2024 İndirGeç. Geliştirici: Eren KÜN.',
            'support_link': 'https://linktr.ee/erennkun',
        }
        for key, value in default_contents.items():
            if not SiteContent.query.filter_by(key_name=key).first():
                db.session.add(SiteContent(key_name=key, content=value))

        # Varsayılan Hizmet Durumu
        if not ServiceStatus.query.first():
            db.session.add(ServiceStatus())

        db.session.commit()

# Veritabanını başlat
initialize_db()

@app.context_processor
def inject_global_data():
    """Tüm şablonlara global site içeriğini enjekte eder."""
    content_map = {c.key_name: c.content for c in SiteContent.query.all()}
    status = ServiceStatus.query.first()
    return {
        'site_content': content_map,
        'service_status': status
    }

# --- E. Site Rotası (index.html'i göster) ---

@app.route('/')
def index():
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    all_versions = Version.query.order_by(Version.release_date.desc()).all()
    return render_template('index.html', latest_version=latest_version, all_versions=all_versions)

# --- F. İndirme Rotası (İstatistik Tutma) ---

@app.route('/indir/son-surum')
def download_file():
    latest_version = Version.query.order_by(Version.release_date.desc()).first()
    
    if not latest_version:
        flash("Hata: İndirilecek aktif bir sürüm bulunamadı.", 'error')
        return redirect(url_for('index'))

    # İndirme sayacını artır
    latest_version.download_count += 1
    db.session.commit()
    
    # Kullanıcıyı Drive/GitHub linkine yönlendir
    return redirect(latest_version.download_url)

# --- G. Geri Bildirim Rotası ---

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    email = request.form.get('email')
    message = request.form.get('message')

    # DEĞİŞİKLİK: Email ve Mesaj zorunlu
    if not email or not message:
        flash("Lütfen hem e-posta adresinizi hem de mesajınızı yazın.", 'error')
        return redirect(url_for('index') + '#feedback') 

    try:
        new_feedback = Feedback(email=email, message=message)
        db.session.add(new_feedback)
        db.session.commit()
        flash('Geri bildiriminiz başarıyla iletildi. Teşekkür ederiz!', 'success')
    except Exception:
        flash('Geri bildirim gönderilirken bir hata oluştu.', 'error')
        db.session.rollback()
        
    return redirect(url_for('index') + '#feedback')

# --- H. Sürüm Kontrol API'sı ---

@app.route('/api/v1/latest_version')
def latest_version_api():
    latest = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    if latest:
        return jsonify({
            'status': 'ok',
            'version': latest.version_number,
            'release_date': latest.release_date.isoformat(),
            'notes': latest.patch_notes,
            'download_url': url_for('download_file', _external=True)
        })
    else:
        return jsonify({'status': 'error', 'message': 'No active version available.'}), 404

# --- I. RSS Feed Rotası ---
@app.route('/feed')
def rss_feed():
    all_versions = Version.query.order_by(Version.release_date.desc()).all()
    response = render_template('rss_feed.xml', all_versions=all_versions)
    return response, 200, {'Content-Type': 'application/rss+xml; charset=utf-8'}

# --- J. Admin Giriş Rotası ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Kullanıcı adı veya şifre hatalı.', 'error')
            
    # DEĞİŞTİ: Artık render_template('admin_login.html') kullanılıyor
    return render_template('admin_login.html')

# --- K. Admin Dashboard Rotası ---

@app.route('/admin/dashboard')
@login_required 
def admin_dashboard():
    all_versions = Version.query.order_by(Version.release_date.desc()).all()
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    total_downloads = sum([v.download_count for v in all_versions])
    unprocessed_feedback = Feedback.query.filter_by(is_read=False).order_by(Feedback.timestamp.desc()).all() 
    
    return render_template('admin_dashboard.html', 
                           all_versions=all_versions,
                           latest_version=latest_version,
                           total_downloads=total_downloads,
                           unprocessed_feedback=unprocessed_feedback)

# --- L. Admin İşlem Rotası: Sürüm Ekleme ---

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
            Version.query.update({Version.is_active: False})
        
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
        flash(f'Sürüm eklenirken bir hata oluştu: {str(e)}', 'error')
        
    return redirect(url_for('admin_dashboard'))

# --- M. Admin İşlem Rotası: Geri Bildirim Yönetimi ---

# Okundu Olarak İşaretle
@app.route('/admin/feedback/mark_read/<int:feedback_id>', methods=['POST'])
@login_required
def admin_mark_read(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    feedback.is_read = True
    db.session.commit()
    flash(f'Geri bildirim #{feedback_id} okundu olarak işaretlendi.', 'success')
    return redirect(url_for('admin_dashboard'))

# Geri Bildirim Silme
@app.route('/admin/feedback/delete/<int:feedback_id>', methods=['POST'])
@login_required
def admin_delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    flash(f'Geri bildirim #{feedback_id} başarıyla silindi.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- N. Admin İşlem Rotası: Site İçerik Yönetimi ---

@app.route('/admin/content', methods=['GET', 'POST'])
@login_required
def admin_content():
    if request.method == 'POST':
        for key, value in request.form.items():
            content_item = SiteContent.query.filter_by(key_name=key).first()
            if content_item:
                content_item.content = value
        
        # Hizmet Durumu Güncellemesi
        status_level = request.form.get('status_level')
        status_message = request.form.get('status_message')
        service_status = ServiceStatus.query.first()
        if service_status:
            service_status.status_level = status_level
            service_status.message = status_message
            service_status.updated_at = datetime.utcnow() # Güncel zaman damgası

        try:
            db.session.commit()
            flash('Site içeriği ve hizmet durumu başarıyla güncellendi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Güncelleme hatası: {str(e)}', 'error')
        
        return redirect(url_for('admin_content'))

    content_items = SiteContent.query.all()
    service_status = ServiceStatus.query.first()
    return render_template('admin_content.html', content_items=content_items, service_status=service_status)

# --- O. Admin Çıkış Rotası ---

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('index'))

# --- P. Sürüm Arşiv Sayfası ---
@app.route('/surum-arsivi')
def version_archive():
    # En son aktif sürüm hariç tüm sürümler
    latest_active = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    
    if latest_active:
        archive_versions = Version.query.filter(Version.id != latest_active.id).order_by(Version.release_date.desc()).all()
    else:
        archive_versions = Version.query.order_by(Version.release_date.desc()).all()

    return render_template('version_archive.html', archive_versions=archive_versions)


if __name__ == '__main__':
    # initialize_db() artık bu blokun dışında çalışıyor
    app.run(debug=True)