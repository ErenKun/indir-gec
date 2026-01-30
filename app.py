import os
import secrets
import uuid
import requests  # NTFY bildirimi için
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, send_from_directory, make_response
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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# Yükleme klasörleri
UPLOAD_FOLDER_IMAGES = os.path.join(app.root_path, 'static', 'uploads')
UPLOAD_FOLDER_VERSIONS = os.path.join(app.instance_path, 'uploads', 'versions')
ALLOWED_EXTENSIONS_IMAGES = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

app.config['UPLOAD_FOLDER_IMAGES'] = UPLOAD_FOLDER_IMAGES
app.config['UPLOAD_FOLDER_VERSIONS'] = UPLOAD_FOLDER_VERSIONS

DB_PATH = os.environ.get('DATABASE_URL', f"sqlite:///{os.path.join(app.instance_path, 'database.db')}")
app.config['SQLALCHEMY_DATABASE_URI'] = DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'
login_manager.login_message = "Bu sayfayı görüntülemek için lütfen giriş yapın."
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- B. Yardımcı Fonksiyonlar ve Filtreler ---
ISTANBUL_TZ = pytz.timezone('Europe/Istanbul')

def allowed_file_image(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_IMAGES

@app.template_filter('ist_time')
def ist_time_filter(dt):
    if dt is None: return "N/A"
    try:
        dt_ist = pytz.utc.localize(dt).astimezone(ISTANBUL_TZ) if dt.tzinfo is None else dt.astimezone(ISTANBUL_TZ)
        return format_datetime(dt_ist, format='dd MMMM yyyy HH:mm', locale='tr')
    except Exception:
        return dt.strftime('%Y-%m-%d %H:%M')

# --- C. Veritabanı Modelleri ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Version(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(20), unique=True, nullable=False)
    release_date = db.Column(db.DateTime, default=datetime.utcnow)
    patch_notes = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    download_count = db.Column(db.Integer, default=0)
    filename = db.Column(db.String(255), nullable=True)
    original_filename = db.Column(db.String(255), nullable=True)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    # Dedektif Modu Verileri
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    cookie_id = db.Column(db.String(100), nullable=True)

class SiteContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(100), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)

class AppFeature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(255), nullable=True)
    order = db.Column(db.Integer, default=0)
    css_class = db.Column(db.String(50), nullable=True, default='accent-text')

class ServiceStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status_level = db.Column(db.String(20), default='OK') # OK, MINOR_ISSUE, MAINTENANCE
    message = db.Column(db.String(500), default='Tüm servisler normal çalışıyor.')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SystemMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='info') # info, warning, danger
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- D. Veritabanı Kurulum Komutu ---

@app.cli.command('init-db')
def init_db_command():
    """Tüm veritabanı tablolarını ve varsayılan verileri oluşturur."""
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER_IMAGES'], exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER_VERSIONS'], exist_ok=True)
    db.create_all()
    print("Veritabanı tabloları oluşturuldu.")

    if not User.query.filter_by(username='admin').first():
        db.session.add(User(username='admin', password_hash=generate_password_hash('admin123')))
        print("Varsayılan 'admin' kullanıcısı (şifre: admin123) oluşturuldu.")

    default_contents = {
        'site_title': 'İndirGeç - Hızlı ve Güvenilir Video İndirici', 'hero_title': 'Tüm Videoları Tek Tıkla İndir',
        'hero_subtitle': 'Gelişmiş özellikler, yüksek hız, Eren KÜN güvencesiyle!', 'features_section_title': 'Uygulama Özellikleri',
        'features_section_subtitle': 'Hız, güvenlik ve kullanım kolaylığı ön planda.', 'download_section_title': 'Hemen Başlayın!',
        'download_section_subtitle': 'Uygulamayı indirin ve yüksek hızlı video indirme deneyimine adım atın.', 'developer_section_title': 'Geliştirici',
        'developer_name': 'Eren KÜN', 'developer_bio': 'Bu proje, yazılım geliştiricisi Eren KÜN tarafından yönetilmekte ve aktif olarak güncellenmektedir.',
        'developer_button_text': 'Destek ve Bağlantılar', 'feedback_section_title': 'Geri Bildirim',
        'feedback_section_subtitle': 'Uygulama hakkındaki görüş, öneri ve hataları bize bildirin.',
        'footer_info': '© 2025 İndirGeç. Geliştirici: Eren KÜN.', 'support_link': 'https://linktr.ee/erennkun',
        'download_button_text': 'Hemen İndir', 'archive_link_text': 'Tüm Sürüm Arşivi →',
        'logo_filename': '' # Logo için varsayılan boş
    }
    for key, value in default_contents.items():
        if not SiteContent.query.filter_by(key_name=key).first():
            db.session.add(SiteContent(key_name=key, content=value))

    if not ServiceStatus.query.first(): db.session.add(ServiceStatus())
    if not SystemMessage.query.first(): 
         # Varsayılan boş bir mesaj oluştur
         db.session.add(SystemMessage(title='Hoşgeldiniz', content='İndirGeç sistemine hoşgeldiniz.', is_active=False))

    db.session.commit()
    print("Varsayılan site içeriği ve servis durumu eklendi.")

# --- E. Genel Site Rotaları ---

@app.context_processor
def inject_global_data():
    logo_content = SiteContent.query.filter_by(key_name='logo_filename').first()
    return dict(
        site_content={c.key_name: c.content for c in SiteContent.query.all()},
        service_status=ServiceStatus.query.first(),
        system_message=SystemMessage.query.filter_by(is_active=True).first(),
        app_features=AppFeature.query.order_by(AppFeature.order).all(),
        total_downloads=db.session.query(db.func.sum(Version.download_count)).scalar() or 0,
        site_logo=logo_content.content if logo_content else None
    )

@app.route('/')
def index():
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    
    # Dedektif Modu - Cookie Kontrolü (Sayfa her açıldığında)
    response = make_response(render_template('index.html', latest_version=latest_version))
    
    # Kullanıcının tarayıcısında 'user_tracking_id' çerezi yoksa, yeni bir tane oluşturup yapıştırıyoruz.
    if 'user_tracking_id' not in request.cookies:
        new_uuid = str(uuid.uuid4())
        # Çerez 1 yıl boyunca (365 gün) geçerli olacak şekilde ayarlanır.
        response.set_cookie('user_tracking_id', new_uuid, max_age=60*60*24*365)
    
    return response

@app.route('/version-archive')
def version_archive():
    archive_versions = Version.query.order_by(Version.release_date.desc()).all()
    return render_template('version_archive.html', archive_versions=archive_versions)

@app.route('/download/<int:version_id>')
def download_file(version_id):
    version = Version.query.get_or_404(version_id)
    version.download_count = (version.download_count or 0) + 1
    db.session.commit()
    return send_from_directory(app.config['UPLOAD_FOLDER_VERSIONS'], version.filename, as_attachment=True, download_name=version.original_filename)

@app.route('/feedback', methods=['POST'])
def submit_feedback():
    email = request.form.get('email')
    message = request.form.get('message')
    
    if email and message:
        # Dedektif Modu Verilerini Topla
        # 1. IP Adresi (PythonAnywhere proxy'si arkasında olduğu için X-Forwarded-For önce kontrol edilir)
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # 2. Cihaz Bilgisi (User Agent)
        user_agent = request.user_agent.string
        
        # 3. Cookie ID (Varsa al, yoksa None)
        cookie_id = request.cookies.get('user_tracking_id')

        # Veritabanına Kaydet
        db.session.add(Feedback(
            email=email, 
            message=message, 
            ip_address=ip_address, 
            user_agent=user_agent, 
            cookie_id=cookie_id
        ))
        db.session.commit()
        
        # --- NTFY Bildirimi Gönder (Proxy Ayarlı) ---
        try:
            ntfy_topic = "indirGec_geri_bildirim_admin_TR34" # Kullanıcının belirlediği kanal
            ntfy_url = f"https://ntfy.sh/{ntfy_topic}"
            
            notification_data = f"Gönderen: {email}\nMesaj: {message}\nIP: {ip_address}"
            
            # PythonAnywhere Ücretsiz Sürüm için Proxy Ayarı
            proxy_host = "proxy.server:3128"
            proxies = {
                "http": f"http://{proxy_host}",
                "https": f"http://{proxy_host}",
            }

            requests.post(ntfy_url,
                data=notification_data.encode('utf-8'),
                headers={
                    "Title": "📩 Yeni Geri Bildirim Var!",
                    "Priority": "high",
                    "Tags": "incoming_envelope,detective"
                },
                proxies=proxies, # ÖNEMLİ: Proxy burada devreye giriyor
                timeout=10 
            )
        except Exception as e:
            # Hata oluşursa konsola yaz (Site çalışmaya devam eder)
            print(f"NTFY Bildirim Hatası: {e}") 

        flash('Geri bildiriminiz için teşekkürler!', 'success')
    else:
        flash('Lütfen tüm alanları doldurun.', 'error')
    return redirect(url_for('index', _anchor='feedback'))
    
@app.route('/rss')
def rss_feed():
    all_versions = Version.query.order_by(Version.release_date.desc()).limit(10).all()
    return Response(render_template('rss_feed.xml', all_versions=all_versions), mimetype='application/rss+xml')

# --- API ROTASI (Masaüstü Uygulaması İçin) ---
@app.route('/api/app-data')
def api_app_data():
    """Masaüstü uygulaması için sürüm, durum ve mesaj bilgilerini JSON döner."""
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    sys_msg = SystemMessage.query.filter_by(is_active=True).first()
    status = ServiceStatus.query.first()
    
    response = {
        "version": {
            "number": latest_version.version_number if latest_version else None,
            "download_url": url_for('download_file', version_id=latest_version.id, _external=True) if latest_version else None,
            "patch_notes": latest_version.patch_notes if latest_version else None,
            "release_date": latest_version.release_date.isoformat() if latest_version else None
        },
        "system_status": {
            "level": status.status_level if status else "OK",
            "message": status.message if status else "OK"
        },
        "developer_message": {
            "active": True if sys_msg else False,
            "title": sys_msg.title if sys_msg else None,
            "content": sys_msg.content if sys_msg else None,
            "type": sys_msg.message_type if sys_msg else None,
            "created_at": sys_msg.created_at.isoformat() if sys_msg else None
        }
    }
    return jsonify(response)

# --- F. Admin Rotaları ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated: return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
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
    return render_template('admin_dashboard.html',
                           total_downloads=db.session.query(db.func.sum(Version.download_count)).scalar() or 0,
                           active_version=Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first(),
                           unprocessed_feedback_count=Feedback.query.filter_by(is_read=False).count())

@app.route('/admin/versions')
@login_required
def admin_versions():
    all_versions = Version.query.order_by(Version.release_date.desc()).all()
    return render_template('admin_versions.html', all_versions=all_versions)

@app.route('/admin/versions/add', methods=['GET', 'POST'])
@login_required
def admin_add_version():
    if request.method == 'POST':
        if 'version_file' not in request.files or not request.form.get('version_number') or not request.form.get('patch_notes'):
            flash('Sürüm numarası, yama notları ve dosya alanları zorunludur.', 'error')
            return redirect(request.url)
        
        file = request.files['version_file']
        if file.filename == '':
            flash('Lütfen bir sürüm dosyası seçin.', 'error')
            return redirect(request.url)
            
        filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER_VERSIONS'], filename))
        
        new_version = Version(
            version_number=request.form.get('version_number'),
            patch_notes=request.form.get('patch_notes'),
            is_active=request.form.get('is_active') == 'on',
            filename=filename,
            original_filename=file.filename
        )
        db.session.add(new_version)
        db.session.commit()
        flash('Yeni sürüm başarıyla eklendi.', 'success')
        return redirect(url_for('admin_versions'))
    return render_template('admin_versions.html', action='add')

@app.route('/admin/versions/edit/<int:version_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_version(version_id):
    version = Version.query.get_or_404(version_id)
    if request.method == 'POST':
        version.version_number = request.form.get('version_number')
        version.patch_notes = request.form.get('patch_notes')
        version.is_active = request.form.get('is_active') == 'on'
        
        if 'version_file' in request.files:
            file = request.files['version_file']
            if file and file.filename != '':
                if version.filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER_VERSIONS'], version.filename)):
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER_VERSIONS'], version.filename))
                
                filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER_VERSIONS'], filename))
                version.filename = filename
                version.original_filename = file.filename
        
        db.session.commit()
        flash('Sürüm başarıyla güncellendi.', 'success')
        return redirect(url_for('admin_versions'))

    return render_template('admin_versions.html', action='edit', version=version)

@app.route('/admin/versions/delete/<int:version_id>', methods=['POST'])
@login_required
def admin_delete_version(version_id):
    version = Version.query.get_or_404(version_id)
    if version.filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER_VERSIONS'], version.filename)):
        os.remove(os.path.join(app.config['UPLOAD_FOLDER_VERSIONS'], version.filename))
    db.session.delete(version)
    db.session.commit()
    flash('Sürüm kalıcı olarak silindi.', 'success')
    return redirect(url_for('admin_versions'))

@app.route('/admin/content', methods=['GET', 'POST'])
@login_required
def admin_content():
    if request.method == 'POST':
        # Metin içerikleri güncelle
        for key, value in request.form.items():
            if key.startswith('content_'):
                item = SiteContent.query.filter_by(key_name=key.split('_', 1)[1]).first()
                if item: item.content = value
        
        # Logo Yükleme İşlemi
        if 'logo_file' in request.files:
            file = request.files['logo_file']
            if file and file.filename != '' and allowed_file_image(file.filename):
                # Eski logoyu silme işlemi eklenebilir
                filename = secure_filename(f"logo_{secrets.token_hex(4)}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER_IMAGES'], filename))
                
                logo_item = SiteContent.query.filter_by(key_name='logo_filename').first()
                if not logo_item:
                    logo_item = SiteContent(key_name='logo_filename', content='')
                    db.session.add(logo_item)
                logo_item.content = filename

        db.session.commit()
        flash('Site içeriği güncellendi.', 'success')
        return redirect(url_for('admin_content'))

    return render_template('admin_content.html', 
                           content_items=SiteContent.query.filter(SiteContent.key_name != 'logo_filename').order_by(SiteContent.id).all())

@app.route('/admin/status', methods=['GET', 'POST'])
@login_required
def admin_status():
    status = ServiceStatus.query.first() or ServiceStatus()
    if request.method == 'POST':
        if not status.id: db.session.add(status)
        
        status.status_level = request.form.get('status_level')
        message = request.form.get('status_message')
        
        # Otomatik mesaj mantığı
        if status.status_level == 'OK' and not message.strip():
            message = 'Tüm servisler normal çalışıyor.'
            
        status.message = message
        status.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Hizmet durumu güncellendi.', 'success')
        return redirect(url_for('admin_status'))
        
    return render_template('admin_status.html', service_status=status)

@app.route('/admin/message', methods=['GET', 'POST'])
@login_required
def admin_message():
    message = SystemMessage.query.first()
    if not message:
        message = SystemMessage(title='', content='')
        db.session.add(message)
        db.session.commit()

    if request.method == 'POST':
        message.title = request.form.get('title')
        message.content = request.form.get('content')
        message.message_type = request.form.get('message_type')
        message.is_active = request.form.get('is_active') == 'on'
        message.created_at = datetime.utcnow()
        db.session.commit()
        flash('Geliştirici mesajı güncellendi.', 'success')
        return redirect(url_for('admin_message'))

    return render_template('admin_message.html', system_message=message)

@app.route('/admin/features', methods=['GET', 'POST'])
@login_required
def admin_features():
    if request.method == 'POST':
        action = request.form.get('action', 'add')
        try:
            if action == 'add':
                if not request.form.get('title') or not request.form.get('description'):
                    flash('Başlık ve açıklama alanları zorunludur.', 'error')
                    return redirect(url_for('admin_features'))

                new_feature = AppFeature(
                    title=request.form.get('title'), description=request.form.get('description'),
                    order=int(request.form.get('order', 0)), css_class=request.form.get('css_class'))
                
                if 'image_file' in request.files:
                    file = request.files['image_file']
                    if file and file.filename != '' and allowed_file_image(file.filename):
                        filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER_IMAGES'], filename))
                        new_feature.image_filename = filename
                db.session.add(new_feature)
                flash('Yeni özellik eklendi.', 'success')

            elif action == 'edit':
                feature = AppFeature.query.get_or_404(request.form.get('feature_id'))
                feature.title = request.form.get('title')
                feature.description = request.form.get('description')
                feature.order = int(request.form.get('order', 0))
                feature.css_class = request.form.get('css_class')

                if 'image_file' in request.files:
                    file = request.files['image_file']
                    if file and file.filename != '' and allowed_file_image(file.filename):
                        if feature.image_filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER_IMAGES'], feature.image_filename)):
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER_IMAGES'], feature.image_filename))
                        filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER_IMAGES'], filename))
                        feature.image_filename = filename
                flash('Özellik güncellendi.', 'success')

            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Bir hata oluştu: {e}', 'error')
        return redirect(url_for('admin_features'))

    return render_template('admin_features.html', all_features=AppFeature.query.order_by(AppFeature.order).all())

@app.route('/admin/features/delete/<int:feature_id>', methods=['POST'])
@login_required
def admin_delete_feature(feature_id):
    feature = AppFeature.query.get_or_404(feature_id)
    if feature.image_filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER_IMAGES'], feature.image_filename)):
        os.remove(os.path.join(app.config['UPLOAD_FOLDER_IMAGES'], feature.image_filename))
    db.session.delete(feature)
    db.session.commit()
    flash('Özellik başarıyla silindi.', 'success')
    return redirect(url_for('admin_features'))

@app.route('/admin/feedback')
@login_required
def admin_feedback():
    all_feedback = Feedback.query.order_by(Feedback.is_read.asc(), Feedback.timestamp.desc()).all()
    return render_template('admin_feedback.html', all_feedback=all_feedback)

@app.route('/admin/feedback/mark_read/<int:feedback_id>', methods=['POST'])
@login_required
def admin_mark_read(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    feedback.is_read = True
    db.session.commit()
    flash('Geri bildirim okundu olarak işaretlendi.', 'success')
    return redirect(url_for('admin_feedback'))

@app.route('/admin/feedback/delete/<int:feedback_id>', methods=['POST'])
@login_required
def admin_delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    flash('Geri bildirim silindi.', 'success')
    return redirect(url_for('admin_feedback'))

@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    if request.method == 'POST':
        current_password, new_password, confirm_password = request.form.get('current_password'), request.form.get('new_password'), request.form.get('confirm_password')
        if not current_user.check_password(current_password): flash('Mevcut şifreniz yanlış.', 'error')
        elif new_password != confirm_password: flash('Yeni şifreler eşleşmiyor.', 'error')
        elif len(new_password) < 6: flash('Yeni şifre en az 6 karakter olmalıdır.', 'error')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Şifreniz başarıyla güncellendi.', 'success')
            return redirect(url_for('admin_profile'))
    return render_template('admin_profile.html')

if __name__ == '__main__':
    app.run(debug=True)