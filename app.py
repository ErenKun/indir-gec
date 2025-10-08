import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import pytz
from babel.dates import format_datetime
import click

# --- A. Uygulama ve Veritabanı Yapılandırması ---

app = Flask(__name__)
# Güvenlik için secret key'i daha karmaşık hale getirdik.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# Resim yükleme için klasör ayarı
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

DB_PATH = os.environ.get('DATABASE_URL', f"sqlite:///{os.path.join(app.instance_path, 'database.db')}")
app.config['SQLALCHEMY_DATABASE_URI'] = DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'
login_manager.login_message = "Bu sayfayı görüntülemek için lütfen giriş yapın."
login_manager.login_message_category = "info"

# --- B. Yardımcı Fonksiyonlar ve Filtreler ---
ISTANBUL_TZ = pytz.timezone('Europe/Istanbul')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.template_filter('ist_time')
def ist_time_filter(dt):
    if dt is None:
        return "N/A"
    try:
        # Tarih zaten zaman dilimi bilgisine sahipse doğrudan dönüştür
        if dt.tzinfo is not None:
             dt_ist = dt.astimezone(ISTANBUL_TZ)
        else:
             # UTC olarak kabul edip dönüştür
             dt_ist = pytz.utc.localize(dt).astimezone(ISTANBUL_TZ)
        return format_datetime(dt_ist, format='dd MMMM yyyy HH:mm', locale='tr')
    except Exception:
        # Hata durumunda basit formatlama yap
        return dt.strftime('%Y-%m-%d %H:%M')

# --- C. Veritabanı Modelleri ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

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
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class SiteContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(100), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)

class AppFeature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(255), nullable=True) # URL yerine dosya adı tutulacak
    order = db.Column(db.Integer, default=0)
    css_class = db.Column(db.String(50), nullable=True, default='accent-text')

class ServiceStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status_level = db.Column(db.String(20), default='OK')
    message = db.Column(db.String(500), default='Tüm servisler normal çalışıyor.')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# --- D. Veritabanı Kurulum Komutu ---

@app.cli.command('init-db')
def init_db_command():
    """Tüm veritabanı tablolarını ve varsayılan verileri oluşturur."""
    db.create_all()
    print("Veritabanı tabloları oluşturuldu.")

    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin')
        admin_user.set_password('admin123') # UYARI: BU ŞİFREYİ İLK GİRİŞTE DEĞİŞTİRİN!
        db.session.add(admin_user)
        print("Varsayılan 'admin' kullanıcısı (şifre: admin123) oluşturuldu.")

    default_contents = {
        'site_title': 'İndirGeç - Hızlı ve Güvenilir Video İndirici', 'hero_title': 'Tüm Videoları Tek Tıkla İndir',
        'hero_subtitle': 'Gelişmiş özellikler, yüksek hız, Eren KÜN güvencesiyle!', 'features_section_title': 'Uygulama Özellikleri',
        'features_section_subtitle': 'Hız, güvenlik ve kullanım kolaylığı ön planda.', 'download_section_title': 'Hemen Başlayın!',
        'download_section_subtitle': 'Uygulamayı indirin ve yüksek hızlı video indirme deneyimine adım atın.', 'developer_section_title': 'Geliştirici',
        'developer_name': 'Eren KÜN', 'developer_bio': 'Bu proje, yazılım geliştiricisi Eren KÜN tarafından yönetilmekte ve aktif olarak güncellenmektedir.',
        'developer_button_text': 'Destek ve Bağlantılar', 'feedback_section_title': 'Geri Bildirim',
        'feedback_section_subtitle': 'Uygulama hakkındaki görüş, öneri ve hataları bize bildirin.',
        'footer_info': '© 2024 İndirGeç. Geliştirici: Eren KÜN.', 'support_link': 'https://linktr.ee/erennkun',
    }
    for key, value in default_contents.items():
        if not SiteContent.query.filter_by(key_name=key).first():
            db.session.add(SiteContent(key_name=key, content=value))

    if not AppFeature.query.first():
        db.session.add(AppFeature(title='Kolay Kullanım Arayüzü', description='Karmaşık ayarlarla uğraşmayın. Linki yapıştırın ve indirme butonuna basın.', order=1))

    if not ServiceStatus.query.first():
        db.session.add(ServiceStatus())

    db.session.commit()
    print("Varsayılan site içeriği, özellik ve servis durumu eklendi.")

# --- E. Genel Site Rotaları ---

@app.context_processor
def inject_global_data():
    """Tüm şablonlara genel verileri enjekte eder."""
    content_map = {c.key_name: c.content for c in SiteContent.query.all()}
    status = ServiceStatus.query.first()
    app_features = AppFeature.query.order_by(AppFeature.order).all()
    total_downloads = db.session.query(db.func.sum(Version.download_count)).scalar() or 0
    return dict(
        site_content=content_map,
        service_status=status,
        app_features=app_features,
        total_downloads=total_downloads
    )

@app.route('/')
def index():
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    return render_template('index.html', latest_version=latest_version)

# ... (Diğer genel rotalarınız - submit_feedback, download_file, version_archive - aynı kalabilir) ...

# --- F. Admin Rotaları ---

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
        flash('Geçersiz kullanıcı adı veya şifre.', 'error')
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin')
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    all_versions = Version.query.order_by(Version.release_date.desc()).all()
    unprocessed_feedback_count = Feedback.query.filter_by(is_read=False).count()
    return render_template('admin_dashboard.html',
                           all_versions=all_versions,
                           unprocessed_feedback_count=unprocessed_feedback_count)

# ... (Sürüm ekleme/silme rotalarınız aynı kalabilir) ...

@app.route('/admin/content', methods=['GET', 'POST'])
@login_required
def admin_content():
    if request.method == 'POST':
        # Site içeriklerini güncelle
        for key, value in request.form.items():
            if key.startswith('content_'):
                key_name = key.split('_', 1)[1]
                item = SiteContent.query.filter_by(key_name=key_name).first()
                if item: item.content = value
        
        # Servis durumunu güncelle
        status = ServiceStatus.query.first()
        if not status: # Eğer hiç status yoksa oluştur
            status = ServiceStatus()
            db.session.add(status)
        status.status_level = request.form.get('status_level')
        status.message = request.form.get('status_message')
        status.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('Site içeriği ve hizmet durumu güncellendi.', 'success')
        return redirect(url_for('admin_content'))

    content_items = SiteContent.query.order_by(SiteContent.id).all()
    service_status = ServiceStatus.query.first()
    return render_template('admin_content.html', content_items=content_items, service_status=service_status)


@app.route('/admin/features', methods=['GET', 'POST'])
@login_required
def admin_features():
    if request.method == 'POST':
        action = request.form.get('action', 'add')
        try:
            if action == 'add':
                title = request.form.get('title')
                description = request.form.get('description')
                if not title or not description:
                    flash('Başlık ve açıklama alanları zorunludur.', 'error')
                    return redirect(url_for('admin_features'))

                new_feature = AppFeature(
                    title=title,
                    description=description,
                    order=int(request.form.get('order', 0)),
                    css_class=request.form.get('css_class')
                )
                
                # Resim yükleme
                if 'image_file' in request.files:
                    file = request.files['image_file']
                    if file and file.filename != '' and allowed_file(file.filename):
                        filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        new_feature.image_filename = filename

                db.session.add(new_feature)
                flash('Yeni özellik eklendi.', 'success')

            elif action == 'edit':
                feature_id = request.form.get('feature_id')
                feature = AppFeature.query.get_or_404(feature_id)
                feature.title = request.form.get('title')
                feature.description = request.form.get('description')
                feature.order = int(request.form.get('order', 0))
                feature.css_class = request.form.get('css_class')

                # Resim yükleme (düzenleme)
                if 'image_file' in request.files:
                    file = request.files['image_file']
                    if file and file.filename != '' and allowed_file(file.filename):
                        # Eski resmi sil (isteğe bağlı ama önerilir)
                        if feature.image_filename:
                            old_path = os.path.join(app.config['UPLOAD_FOLDER'], feature.image_filename)
                            if os.path.exists(old_path): os.remove(old_path)

                        filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        feature.image_filename = filename
                
                flash('Özellik güncellendi.', 'success')

            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Bir hata oluştu: {e}', 'error')
        return redirect(url_for('admin_features'))

    all_features = AppFeature.query.order_by(AppFeature.order).all()
    return render_template('admin_features.html', all_features=all_features)


@app.route('/admin/features/delete/<int:feature_id>', methods=['POST'])
@login_required
def admin_delete_feature(feature_id):
    feature = AppFeature.query.get_or_404(feature_id)
    # Resim dosyasını da sunucudan sil
    if feature.image_filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], feature.image_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    db.session.delete(feature)
    db.session.commit()
    flash('Özellik başarıyla silindi.', 'success')
    return redirect(url_for('admin_features'))

# YENİ: Geri Bildirim Yönetim Sayfası
@app.route('/admin/feedback')
@login_required
def admin_feedback():
    all_feedback = Feedback.query.order_by(Feedback.is_read.asc(), Feedback.timestamp.desc()).all()
    return render_template('admin_feedback.html', all_feedback=all_feedback)

# YENİ: Profilim ve Şifre Değiştirme
@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not current_user.check_password(current_password):
            flash('Mevcut şifreniz yanlış.', 'error')
        elif new_password != confirm_password:
            flash('Yeni şifreler eşleşmiyor.', 'error')
        elif len(new_password) < 6:
            flash('Yeni şifre en az 6 karakter olmalıdır.', 'error')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Şifreniz başarıyla güncellendi.', 'success')
            return redirect(url_for('admin_profile'))
            
    return render_template('admin_profile.html')


if __name__ == '__main__':
    # 'flask init-db' komutunu kullanmak daha iyi bir pratik
    app.run(debug=True, port=5001)