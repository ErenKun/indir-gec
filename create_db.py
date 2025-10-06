import os
import sys

# Flask uygulamanızın bulunduğu dosyadan (app.py) gerekli nesneleri içe aktarın
# Flask uygulaması nesneniz 'app', SQLAlchemy nesneniz 'db' olmalı.
# NOT: Kendi uygulamanızdaki import yapınıza göre bu satırı düzenleyin.
try:
    from app import app, db  # app.py dosyanızdaki uygulama ve db nesneleri
except ImportError as e:
    print(f"Hata: app.py dosyasından 'app' veya 'db' içe aktarılamadı. Hata: {e}")
    sys.exit(1)


# 1. 'instance' klasörünün var olduğundan emin olun (Render'a yazma izni verir).
instance_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
if not os.path.exists(instance_dir):
    try:
        os.makedirs(instance_dir)
        print(f"Klasör oluşturuldu: {instance_dir}")
    except OSError as e:
        print(f"Hata: 'instance' klasörü oluşturulamadı. {e}")
        sys.exit(1)

# 2. Uygulama bağlamını etkinleştirin ve veritabanı tablolarını oluşturun.
with app.app_context():
    try:
        db.create_all()
        print("Veritabanı tabloları başarıyla oluşturuldu.")
    except Exception as e:
        print(f"Hata: Veritabanı tabloları oluşturulamadı. {e}")
        sys.exit(1)