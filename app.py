import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz
from babel.dates import format_datetime

# --- A. Uygulama ve Veritabanı Yapılandırması ---

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cok_gizli_ve_uzun_bir_anahtar_olmalidir')

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

@app.template_filter('ist_time')
def ist_time_filter(dt, format='medium'):
    if dt is None:
        return ""
    try:
        dt_ist = pytz.utc.localize(dt).astimezone(ISTANBUL_TZ)
        return format_datetime(dt_ist, format='dd MMMM yyyy HH:mm', locale='tr')
    except Exception:
        return dt.strftime('%Y-%m-%d %H:%M')

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
    image_url = db.Column(db.String(500), nullable=True)
    order = db.Column(db.Integer, default=0)
    css_class = db.Column(db.String(50), nullable=True)

class ServiceStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status_level = db.Column(db.String(20), default='OK')
    message = db.Column(db.String(500), default='Her şey yolunda.')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- D. Kullanıcı Yükleyici ve Uygulama Oluşturucu ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def initialize_db():
    with app.app_context():
        os.makedirs(app.instance_path, exist_ok=True)
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin')
            admin_user.set_password('cokgizlisifre') # UYARI: BU ŞİFRENİZİ GÜNCELLEYİN!
            db.session.add(admin_user)

        default_contents = {
            'site_title': 'İndirGeç - Hızlı ve Güvenilir Video İndirici',
            'hero_title': 'Tüm Videoları Tek Tıkla İndir',
            'hero_subtitle': 'Gelişmiş özellikler, yüksek hız, Eren KÜN güvencesiyle!',
            'features_section_title': 'Uygulama Özellikleri',
            'features_section_subtitle': 'Hız, güvenlik ve kullanım kolaylığı ön planda.',
            'download_section_title': 'Hemen Başlayın!',
            'download_section_subtitle': 'Uygulamayı indirin ve yüksek hızlı video indirme deneyimine adım atın.',
            'developer_section_title': 'Geliştirici',
            'developer_name': 'Eren KÜN',
            'developer_bio': 'Bu proje, yazılım geliştiricisi Eren KÜN tarafından yönetilmekte ve aktif olarak güncellenmektedir. Destek ve diğer projeler için aşağıdaki bağlantıyı kullanabilirsiniz.',
            'developer_button_text': 'Destek ve Bağlantılar',
            'feedback_section_title': 'Geri Bildirim',
            'feedback_section_subtitle': 'Uygulama hakkındaki görüş, öneri ve hataları bize bildirin.',
            'footer_info': '© 2024 İndirGeç. Geliştirici: Eren KÜN.',
            'support_link': 'https://linktr.ee/erennkun',
        }
        for key, value in default_contents.items():
            if not SiteContent.query.filter_by(key_name=key).first():
                db.session.add(SiteContent(key_name=key, content=value))

        if not AppFeature.query.first():
            db.session.add_all([
                AppFeature(title='Kolay Kullanım Arayüzü', description='Karmaşık ayarlarla uğraşmayın. Linki yapıştırın ve indirme butonuna basın. İndirGeç, işi sizin için saniyeler içinde halleder.', image_url='[Uygulama Ekran Görüntüsü 1]', order=1, css_class='accent-text'),
                AppFeature(title='Yüksek İndirme Hızı', description='Sunucularımız optimize edilmiştir. İnternet hızınızın izin verdiği maksimum hızda videoları cihazınıza aktarın.', image_url='[Uygulama Ekran Görüntüsü 2]', order=2, css_class='text-green-500'),
                AppFeature(title='Aktif Destek ve Güncellemeler', description='Geliştirici **Eren KÜN** tarafından aktif olarak güncellenen ve desteklenen bir yazılımdır. Sorunlar hızla çözülür.', image_url='[Uygulama Ekran Görüntüsü 3]', order=3, css_class='text-blue-500'),
            ])

        if not ServiceStatus.query.first():
            db.session.add(ServiceStatus())

        db.session.commit()

@app.context_processor
def inject_global_data():
    content_map = {c.key_name: c.content for c in SiteContent.query.all()}
    status = ServiceStatus.query.first()
    app_features = AppFeature.query.order_by(AppFeature.order).all()
    total_downloads = db.session.query(db.func.sum(Version.download_count)).scalar() or 0
    return {
        'site_content': content_map,
        'service_status': status,
        'app_features': app_features,
        'total_downloads': total_downloads
    }

# --- E. Genel Site Rotaları ---

@app.route('/')
def index():
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    return render_template('index.html', latest_version=latest_version)

@app.route('/indir/son-surum')
def download_file():
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    if not latest_version:
        flash("Hata: İndirilecek aktif bir sürüm bulunamadı.", 'error')
        return redirect(url_for('index'))
    latest_version.download_count += 1
    db.session.commit()
    return redirect(latest_version.download_url)

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    email = request.form.get('email')
    message = request.form.get('message')
    if not email or not message:
        flash('Lütfen tüm alanları doldurun.', 'error')
        return redirect(url_for('index') + '#feedback')
    new_feedback = Feedback(email=email, message=message)
    db.session.add(new_feedback)
    db.session.commit()
    flash('Geri bildiriminiz için teşekkürler! En kısa sürede incelenecektir.', 'success')
    return redirect(url_for('index') + '#feedback')

@app.route('/surum-arsivi')
def version_archive():
    archive_versions = Version.query.order_by(Version.release_date.desc()).all()
    return render_template('version_archive.html', archive_versions=archive_versions)

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
        else:
            flash('Geçersiz kullanıcı adı veya şifre.', 'error')
    return render_template('admin_login.html') # Ayrı bir login şablonu oluşturmanız gerekir.

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))

@app.route('/admin')
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    all_versions = Version.query.order_by(Version.release_date.desc()).all()
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    total_downloads_val = db.session.query(db.func.sum(Version.download_count)).scalar() or 0
    unprocessed_feedback = Feedback.query.filter_by(is_read=False).order_by(Feedback.timestamp.desc()).all()
    return render_template('admin_dashboard.html',
                           all_versions=all_versions,
                           latest_version=latest_version,
                           total_downloads=total_downloads_val,
                           unprocessed_feedback=unprocessed_feedback)

@app.route('/admin/versions/add', methods=['POST'])
@login_required
def admin_add_version():
    version_number = request.form.get('version_number')
    download_url = request.form.get('download_url')
    patch_notes = request.form.get('patch_notes')
    is_active = 'is_active' in request.form

    if not all([version_number, download_url, patch_notes]):
        flash('Lütfen tüm sürüm alanlarını doldurun.', 'error')
        return redirect(url_for('admin_dashboard'))

    if is_active:
        Version.query.update({Version.is_active: False})

    new_version = Version(
        version_number=version_number,
        download_url=download_url,
        patch_notes=patch_notes,
        is_active=is_active
    )
    db.session.add(new_version)
    db.session.commit()
    flash(f'Sürüm v{version_number} başarıyla yayınlandı.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/versions/delete/<int:version_id>', methods=['POST'])
@login_required
def admin_delete_version(version_id):
    version_to_delete = Version.query.get_or_404(version_id)
    db.session.delete(version_to_delete)
    db.session.commit()
    flash(f'Sürüm v{version_to_delete.version_number} kalıcı olarak silindi.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/feedback/read/<int:feedback_id>', methods=['POST'])
@login_required
def admin_mark_read(feedback_id):
    feedback_item = Feedback.query.get_or_404(feedback_id)
    feedback_item.is_read = True
    db.session.commit()
    flash('Geri bildirim okundu olarak işaretlendi.', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/feedback/delete/<int:feedback_id>', methods=['POST'])
@login_required
def admin_delete_feedback(feedback_id):
    feedback_item = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback_item)
    db.session.commit()
    flash('Geri bildirim kalıcı olarak silindi.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/content', methods=['GET', 'POST'])
@login_required
def admin_content():
    if request.method == 'POST':
        for key, value in request.form.items():
            if key in ['status_level', 'status_message']:
                continue
            content_item = SiteContent.query.filter_by(key_name=key).first()
            if content_item:
                content_item.content = value

        service_status = ServiceStatus.query.first()
        service_status.status_level = request.form.get('status_level')
        service_status.message = request.form.get('status_message')
        service_status.updated_at = datetime.utcnow()

        db.session.commit()
        flash('Site içeriği ve hizmet durumu başarıyla güncellendi.', 'success')
        return redirect(url_for('admin_content'))

    content_items = SiteContent.query.order_by(SiteContent.key_name).all()
    service_status = ServiceStatus.query.first()
    return render_template('admin_content.html', content_items=content_items, service_status=service_status)

@app.route('/admin/features', methods=['GET', 'POST'])
@login_required
def admin_features():
    if request.method == 'POST':
        action = request.form.get('action', 'add')
        try:
            if action == 'add':
                new_feature = AppFeature(
                    title=request.form.get('title'),
                    description=request.form.get('description'),
                    image_url=request.form.get('image_url'),
                    order=int(request.form.get('order', 0)),
                    css_class=request.form.get('css_class')
                )
                db.session.add(new_feature)
                flash('Yeni özellik başarıyla eklendi.', 'success')
            elif action == 'edit':
                feature_id = request.form.get('feature_id')
                feature = AppFeature.query.get_or_404(feature_id)
                feature.title = request.form.get('title')
                feature.description = request.form.get('description')
                feature.image_url = request.form.get('image_url')
                feature.order = int(request.form.get('order', 0))
                feature.css_class = request.form.get('css_class')
                flash('Özellik başarıyla güncellendi.', 'success')
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'İşlem sırasında bir hata oluştu: {e}', 'error')
        return redirect(url_for('admin_features'))

    all_features = AppFeature.query.order_by(AppFeature.order).all()
    return render_template('admin_features.html', all_features=all_features)

@app.route('/admin/features/delete/<int:feature_id>', methods=['POST'])
@login_required
def admin_delete_feature(feature_id):
    feature = AppFeature.query.get_or_404(feature_id)
    db.session.delete(feature)
    db.session.commit()
    flash('Özellik başarıyla silindi.', 'success')
    return redirect(url_for('admin_features'))

if __name__ == '__main__':
    with app.app_context():
        initialize_db()
    app.run(debug=True, port=5001)