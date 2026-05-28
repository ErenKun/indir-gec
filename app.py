import os
import secrets
import uuid
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import pytz
from babel.dates import format_datetime

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
    external_url = db.Column(db.String(500), nullable=True)

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
    status_level = db.Column(db.String(20), default='OK')
    message = db.Column(db.String(500), default='Tüm servisler normal çalışıyor.')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SystemMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='info')
    is_active = db.Column(db.Boolean, default=False)
    target = db.Column(db.String(20), default='both')  # 'site', 'app', 'both'
    frequency = db.Column(db.String(30), default='once')  # 'every_launch', 'daily', 'once', 'hourly'
    display_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(30), unique=True, nullable=False)
    owner_name = db.Column(db.String(100), nullable=True)
    hardware_id = db.Column(db.String(128), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    download_token = db.Column(db.String(64), nullable=True)
    download_count = db.Column(db.Integer, default=0)
    activation_count = db.Column(db.Integer, default=0)
    last_download_ip = db.Column(db.String(50), nullable=True)
    last_activation_ip = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    activated_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)


# --- D. Veritabanı Kurulum Komutu ---

@app.cli.command('init-db')
def init_db_command():
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER_IMAGES'], exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER_VERSIONS'], exist_ok=True)
    db.create_all()

    # Yeni sütunları güvenli şekilde ekle
    with app.app_context():
        try:
            db.session.execute(db.text("ALTER TABLE version ADD COLUMN external_url VARCHAR(500)"))
            db.session.commit()
        except Exception:
            db.session.rollback()
            
        try:
            db.session.execute(db.text("ALTER TABLE system_message ADD COLUMN target VARCHAR(20) DEFAULT 'both'"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        try:
            db.session.execute(db.text("ALTER TABLE system_message ADD COLUMN frequency VARCHAR(30) DEFAULT 'once'"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        try:
            db.session.execute(db.text("ALTER TABLE system_message ADD COLUMN display_order INTEGER DEFAULT 0"))
            db.session.commit()
        except Exception:
            db.session.rollback()

    if not User.query.filter_by(username='admin').first():
        db.session.add(User(username='admin', password_hash=generate_password_hash('admin123')))
    
    # Varsayılan içerikler (Tamir.py buradaki mantığı kullanır)
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
        'developer_bio': 'Bu proje, yazılım geliştiricisi Eren KÜN tarafından yönetilmekte.',
        'developer_button_text': 'Destek ve Bağlantılar',
        'feedback_section_title': 'Geri Bildirim',
        'feedback_section_subtitle': 'Uygulama hakkındaki görüşlerinizi bildirin.',
        'footer_info': '© 2026 İndirGeç. Geliştirici: Eren KÜN.',
        'support_link': 'https://linktr.ee/erennkun',
        'download_button_text': 'Hemen İndir',
        'archive_link_text': 'Tüm Sürüm Arşivi →',
        'logo_filename': ''
    }
    for key, value in default_contents.items():
        if not SiteContent.query.filter_by(key_name=key).first():
            db.session.add(SiteContent(key_name=key, content=value))

    if not ServiceStatus.query.first(): db.session.add(ServiceStatus())
    if not SystemMessage.query.first(): 
         db.session.add(SystemMessage(title='Hoşgeldiniz', content='Sisteme hoşgeldiniz.', is_active=False))

    db.session.commit()
    print("Veritabanı başlatıldı.")

# --- E. Genel Site Rotaları ---

@app.context_processor
def inject_global_data():
    logo_content = SiteContent.query.filter_by(key_name='logo_filename').first()
    
    site_msg = SystemMessage.query.filter(
        SystemMessage.is_active == True,
        SystemMessage.target.in_(['site', 'both'])
    ).order_by(SystemMessage.display_order.asc(), SystemMessage.created_at.desc()).first()
    
    return dict(
        site_content={c.key_name: c.content for c in SiteContent.query.all()},
        service_status=ServiceStatus.query.first(),
        system_message=site_msg,
        app_features=AppFeature.query.order_by(AppFeature.order).all(),
        total_downloads=db.session.query(db.func.sum(Version.download_count)).scalar() or 0,
        site_logo=logo_content.content if logo_content else None
    )

@app.route('/')
def index():
    latest_version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
    
    response = make_response(render_template('index.html', latest_version=latest_version))
    
    # Cookie (Dijital Kimlik)
    if 'user_tracking_id' not in request.cookies:
        new_uuid = str(uuid.uuid4())
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
    if version.external_url:
        return redirect(version.external_url)
    return send_from_directory(app.config['UPLOAD_FOLDER_VERSIONS'], version.filename, as_attachment=True, download_name=version.original_filename)

@app.route('/indir/on-kontrol', methods=['GET', 'POST'])
def license_check():
    version_id = request.args.get('vid') or request.form.get('vid')
    if request.method == 'POST':
        license_key = request.form.get('license_key')
        if not license_key:
            flash('Lütfen bir lisans anahtarı girin.', 'error')
            return redirect(url_for('license_check', vid=version_id))
            
        license_obj = License.query.filter_by(license_key=license_key, is_active=True).first()
        if not license_obj:
            flash('Geçersiz veya pasif bir lisans anahtarı.', 'error')
            return redirect(url_for('license_check', vid=version_id))
            
        token = secrets.token_urlsafe(32)
        license_obj.download_token = token
        db.session.commit()
        
        return redirect(url_for('download_with_token', token=token, vid=version_id))
        
    return render_template('license_check.html', vid=version_id)

@app.route('/indir/token/<token>')
def download_with_token(token):
    license_obj = License.query.filter_by(download_token=token, is_active=True).first()
    if not license_obj:
        flash('Geçersiz veya süresi dolmuş indirme bağlantısı.', 'error')
        return redirect(url_for('index'))
        
    version_id = request.args.get('vid')
    if version_id:
        version = Version.query.get(version_id)
    else:
        version = Version.query.filter_by(is_active=True).order_by(Version.release_date.desc()).first()
        
    if not version:
        flash('İndirilecek sürüm bulunamadı.', 'error')
        return redirect(url_for('index'))
        
    # Update stats
    license_obj.download_count = (license_obj.download_count or 0) + 1
    license_obj.last_download_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    license_obj.download_token = None
    
    version.download_count = (version.download_count or 0) + 1
    db.session.commit()
    
    if version.external_url:
        return redirect(version.external_url)
        
    return send_from_directory(app.config['UPLOAD_FOLDER_VERSIONS'], version.filename, as_attachment=True, download_name=version.original_filename)

@app.route('/feedback', methods=['POST'])
def submit_feedback():
    email = request.form.get('email')
    message = request.form.get('message')
    
    if email and message:
        # 1. Dedektif Bilgileri
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.user_agent.string
        cookie_id = request.cookies.get('user_tracking_id')

        # 2. Veritabanına Kayıt
        try:
            db.session.add(Feedback(
                email=email, 
                message=message, 
                ip_address=ip_address, 
                user_agent=user_agent, 
                cookie_id=cookie_id
            ))
            db.session.commit()
        except Exception as e:
            flash(f'Veritabanı Hatası: {str(e)}', 'error')
            return redirect(url_for('index', _anchor='feedback'))
        
        # 3. NTFY Bildirimi
        try:
            ntfy_topic = "indirGec_geri_bildirim_admin_TR34"
            notification_data = f"Gönderen: {email}\nMesaj: {message}\nIP: {ip_address}".encode('utf-8')
            
            # Proxy Ayarı (PythonAnywhere için gerekli)
            proxy_host = "proxy.server:3128"
            proxies = {
                "http": f"http://{proxy_host}",
                "https": f"http://{proxy_host}",
            }
            
            headers = {
                "Title": "Yeni Geri Bildirim",
                "Priority": "high",
                "Tags": "incoming_envelope,detective"
            }

            try:
                # Önce HTTPS dene
                requests.post(f"https://ntfy.sh/{ntfy_topic}",
                    data=notification_data,
                    headers=headers,
                    proxies=proxies,
                    timeout=15
                )
            except requests.exceptions.RequestException as e:
                print(f"NTFY HTTPS Hatası: {e}. HTTP deneniyor...")
                # HTTPS başarısız olursa HTTP dene
                requests.post(f"http://ntfy.sh/{ntfy_topic}",
                    data=notification_data,
                    headers=headers,
                    proxies=proxies,
                    timeout=15
                )

        except Exception as e:
            # Hata oluşsa bile kullanıcıya hissettirme, arka planda detaylı logla
            print(f"NTFY Bildirim Genel Hatası: {str(e)}")
            import traceback
            traceback.print_exc()

        flash('Geri bildiriminiz için teşekkürler!', 'success')
    else:
        flash('Lütfen tüm alanları doldurun.', 'error')
        
    return redirect(url_for('index', _anchor='feedback'))
    
@app.route('/rss')
def rss_feed():
    all_versions = Version.query.order_by(Version.release_date.desc()).limit(10).all()
    return Response(render_template('rss_feed.xml', all_versions=all_versions), mimetype='application/rss+xml')

@app.route('/api/v1/license/activate', methods=['POST'])
def api_license_activate():
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'JSON payload bekleniyor.'}), 400
        
    license_key = data.get('license_key')
    hardware_id = data.get('hardware_id')
    
    if not license_key or not hardware_id:
        return jsonify({'status': 'error', 'message': 'Eksik parametreler.'}), 400
        
    license_obj = License.query.filter_by(license_key=license_key).first()
    
    if not license_obj:
        return jsonify({'status': 'error', 'message': 'Geçersiz lisans anahtarı.'}), 404
        
    if not license_obj.is_active:
        return jsonify({'status': 'error', 'message': 'Bu lisans devre dışı bırakılmış.'}), 403
        
    if not license_obj.hardware_id:
        license_obj.hardware_id = hardware_id
        license_obj.activated_at = datetime.utcnow()
        license_obj.activation_count = 1
        license_obj.last_activation_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Lisans başarıyla bu cihaza kilitlendi ve etkinleştirildi.', 'valid': True}), 200
        
    if license_obj.hardware_id == hardware_id:
        license_obj.activation_count += 1
        license_obj.last_activation_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Lisans doğrulandı.', 'valid': True}), 200
        
    return jsonify({'status': 'error', 'message': 'Bu lisans başka bir cihazda kullanılıyor.', 'valid': False}), 403

@app.route('/api/v1/license/verify', methods=['POST'])
def api_license_verify():
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'valid': False, 'message': 'JSON payload bekleniyor.'}), 400
        
    license_key = data.get('license_key')
    hardware_id = data.get('hardware_id')
    
    if not license_key or not hardware_id:
        return jsonify({'status': 'error', 'valid': False, 'message': 'Eksik parametreler.'}), 400
        
    license_obj = License.query.filter_by(license_key=license_key).first()
    
    if not license_obj or not license_obj.is_active or license_obj.hardware_id != hardware_id:
        return jsonify({'status': 'error', 'valid': False, 'message': 'Geçersiz veya yetkisiz lisans.'}), 403
        
    return jsonify({'status': 'success', 'valid': True, 'message': 'Lisans geçerli.'}), 200

@app.route('/api/v1/messages', methods=['GET'])
def api_messages():
    messages = SystemMessage.query.filter(
        SystemMessage.is_active == True,
        SystemMessage.target.in_(['app', 'both'])
    ).order_by(SystemMessage.display_order.asc(), SystemMessage.created_at.desc()).all()
    
    msg_list = []
    for msg in messages:
        msg_list.append({
            'id': msg.id,
            'title': msg.title,
            'content': msg.content,
            'type': msg.message_type,
            'frequency': msg.frequency
        })
        
    return jsonify({'status': 'success', 'messages': msg_list})

@app.route('/api/v1/setup/manifest', methods=['GET'])
def api_setup_manifest():
    ffmpeg_url = SiteContent.query.filter_by(key_name='ffmpeg_url').first()
    ffmpeg_hash = SiteContent.query.filter_by(key_name='ffmpeg_hash').first()
    
    return jsonify({
        'status': 'success',
        'ffmpeg': {
            'url': ffmpeg_url.content if ffmpeg_url else 'https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip',
            'hash': ffmpeg_hash.content if ffmpeg_hash else ''
        }
    })

@app.route('/api/app-data')
def api_app_data():
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

# --- Admin Rotaları ---
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
        external_url = request.form.get('external_url')
        if not request.form.get('version_number') or not request.form.get('patch_notes'):
            flash('Zorunlu alanları doldurun.', 'error')
            return redirect(request.url)
            
        file = request.files.get('version_file')
        if not external_url and (not file or file.filename == ''):
            flash('Lütfen dosya seçin veya harici link girin.', 'error')
            return redirect(request.url)
            
        filename = None
        original_filename = None
        if file and file.filename != '':
            filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER_VERSIONS'], filename))
            original_filename = file.filename
        
        new_version = Version(
            version_number=request.form.get('version_number'),
            patch_notes=request.form.get('patch_notes'),
            is_active=request.form.get('is_active') == 'on',
            filename=filename,
            original_filename=original_filename,
            external_url=external_url
        )
        db.session.add(new_version)
        db.session.commit()
        flash('Sürüm eklendi.', 'success')
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
        version.external_url = request.form.get('external_url')
        
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
        flash('Sürüm güncellendi.', 'success')
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
    flash('Sürüm silindi.', 'success')
    return redirect(url_for('admin_versions'))

@app.route('/admin/licenses', methods=['GET'])
@login_required
def admin_licenses():
    licenses = License.query.order_by(License.created_at.desc()).all()
    total = len(licenses)
    active = sum(1 for l in licenses if l.is_active)
    locked = sum(1 for l in licenses if l.hardware_id)
    today = sum(1 for l in licenses if l.activated_at and l.activated_at.date() == datetime.utcnow().date())
    return render_template('admin_licenses.html', licenses=licenses, total=total, active=active, locked=locked, today=today)

def generate_license_key():
    import string
    import random
    while True:
        parts = ['INDIRGEC']
        for _ in range(2):
            parts.append(''.join(random.choices(string.ascii_uppercase + string.digits, k=4)))
        key = '-'.join(parts)
        if not License.query.filter_by(license_key=key).first():
            return key

@app.route('/admin/licenses/add', methods=['POST'])
@login_required
def admin_add_license():
    owner_name = request.form.get('owner_name')
    notes = request.form.get('notes')
    key = generate_license_key()
    new_license = License(license_key=key, owner_name=owner_name, notes=notes)
    db.session.add(new_license)
    db.session.commit()
    flash(f'Yeni lisans oluşturuldu: {key}', 'success')
    return redirect(url_for('admin_licenses'))

@app.route('/admin/licenses/bulk', methods=['POST'])
@login_required
def admin_generate_bulk_licenses():
    count = int(request.form.get('count', 1))
    if count > 100: count = 100
    generated = []
    for _ in range(count):
        key = generate_license_key()
        generated.append(License(license_key=key))
    db.session.add_all(generated)
    db.session.commit()
    flash(f'{count} adet lisans oluşturuldu.', 'success')
    return redirect(url_for('admin_licenses'))

@app.route('/admin/licenses/edit/<int:id>', methods=['POST'])
@login_required
def admin_edit_license(id):
    license_obj = License.query.get_or_404(id)
    license_obj.owner_name = request.form.get('owner_name')
    license_obj.notes = request.form.get('notes')
    db.session.commit()
    flash('Lisans güncellendi.', 'success')
    return redirect(url_for('admin_licenses'))

@app.route('/admin/licenses/reset/<int:id>', methods=['POST'])
@login_required
def admin_reset_hardware(id):
    license_obj = License.query.get_or_404(id)
    license_obj.hardware_id = None
    db.session.commit()
    flash('Donanım kilidi sıfırlandı.', 'success')
    return redirect(url_for('admin_licenses'))

@app.route('/admin/licenses/toggle/<int:id>', methods=['POST'])
@login_required
def admin_toggle_license(id):
    license_obj = License.query.get_or_404(id)
    license_obj.is_active = not license_obj.is_active
    db.session.commit()
    status = "aktif edildi" if license_obj.is_active else "devre dışı bırakıldı"
    flash(f'Lisans {status}.', 'success')
    return redirect(url_for('admin_licenses'))

@app.route('/admin/licenses/delete/<int:id>', methods=['POST'])
@login_required
def admin_delete_license(id):
    license_obj = License.query.get_or_404(id)
    db.session.delete(license_obj)
    db.session.commit()
    flash('Lisans silindi.', 'success')
    return redirect(url_for('admin_licenses'))

@app.route('/admin/content', methods=['GET', 'POST'])
@login_required
def admin_content():
    if request.method == 'POST':
        for key, value in request.form.items():
            if key.startswith('content_'):
                item = SiteContent.query.filter_by(key_name=key.split('_', 1)[1]).first()
                if item: item.content = value
        
        if 'logo_file' in request.files:
            file = request.files['logo_file']
            if file and file.filename != '' and allowed_file_image(file.filename):
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
        if status.status_level == 'OK' and not message.strip():
            message = 'Tüm servisler normal çalışıyor.'
        status.message = message
        status.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Durum güncellendi.', 'success')
        return redirect(url_for('admin_status'))
    return render_template('admin_status.html', service_status=status)

@app.route('/admin/message', methods=['GET'])
@login_required
def admin_message():
    messages = SystemMessage.query.order_by(SystemMessage.display_order.asc(), SystemMessage.created_at.desc()).all()
    return render_template('admin_message.html', messages=messages)

@app.route('/admin/message/add', methods=['POST'])
@login_required
def admin_add_message():
    new_message = SystemMessage(
        title=request.form.get('title'),
        content=request.form.get('content'),
        message_type=request.form.get('message_type'),
        target=request.form.get('target', 'both'),
        frequency=request.form.get('frequency', 'once'),
        display_order=int(request.form.get('display_order', 0)),
        is_active=request.form.get('is_active') == 'on'
    )
    db.session.add(new_message)
    db.session.commit()
    flash('Yeni mesaj eklendi.', 'success')
    return redirect(url_for('admin_message'))

@app.route('/admin/message/edit/<int:id>', methods=['POST'])
@login_required
def admin_edit_message(id):
    msg = SystemMessage.query.get_or_404(id)
    msg.title = request.form.get('title')
    msg.content = request.form.get('content')
    msg.message_type = request.form.get('message_type')
    msg.target = request.form.get('target', 'both')
    msg.frequency = request.form.get('frequency', 'once')
    msg.display_order = int(request.form.get('display_order', 0))
    msg.is_active = request.form.get('is_active') == 'on'
    db.session.commit()
    flash('Mesaj güncellendi.', 'success')
    return redirect(url_for('admin_message'))

@app.route('/admin/message/delete/<int:id>', methods=['POST'])
@login_required
def admin_delete_message(id):
    msg = SystemMessage.query.get_or_404(id)
    db.session.delete(msg)
    db.session.commit()
    flash('Mesaj silindi.', 'success')
    return redirect(url_for('admin_message'))

@app.route('/admin/message/toggle/<int:id>', methods=['POST'])
@login_required
def admin_toggle_message(id):
    msg = SystemMessage.query.get_or_404(id)
    msg.is_active = not msg.is_active
    db.session.commit()
    status = "aktif edildi" if msg.is_active else "devre dışı bırakıldı"
    flash(f'Mesaj {status}.', 'success')
    return redirect(url_for('admin_message'))

@app.route('/admin/features', methods=['GET', 'POST'])
@login_required
def admin_features():
    if request.method == 'POST':
        action = request.form.get('action', 'add')
        try:
            if action == 'add':
                if not request.form.get('title') or not request.form.get('description'):
                    flash('Başlık ve açıklama zorunlu.', 'error')
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
                flash('Eklendi.', 'success')

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
                flash('Güncellendi.', 'success')

            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Hata: {e}', 'error')
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
    flash('Silindi.', 'success')
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
    flash('Okundu.', 'success')
    return redirect(url_for('admin_feedback'))

@app.route('/admin/feedback/delete/<int:feedback_id>', methods=['POST'])
@login_required
def admin_delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    flash('Silindi.', 'success')
    return redirect(url_for('admin_feedback'))

@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not current_user.check_password(current_password): flash('Mevcut şifre yanlış.', 'error')
        elif new_password != confirm_password: flash('Şifreler uyuşmuyor.', 'error')
        elif len(new_password) < 6: flash('Şifre çok kısa.', 'error')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Şifre güncellendi.', 'success')
            return redirect(url_for('admin_profile'))
    return render_template('admin_profile.html')

if __name__ == "__main__":
    app.run(debug=True)