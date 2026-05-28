import sqlite3
import os
import sys

def migrate_database(old_db_path, new_db_path):
    if not os.path.exists(old_db_path):
        print(f"HATA: Eski veritabanı bulunamadı: {old_db_path}")
        print("Lütfen eski veritabanı dosyasının adını 'old_database.db' yapın ve bu scriptin yanına koyun.")
        return

    if not os.path.exists(new_db_path):
        print(f"HATA: Yeni veritabanı bulunamadı: {new_db_path}")
        print("Lütfen önce 'flask init-db' komutunu çalıştırarak yeni ve boş veritabanını oluşturun.")
        return

    try:
        old_conn = sqlite3.connect(old_db_path)
        new_conn = sqlite3.connect(new_db_path)
        
        old_conn.row_factory = sqlite3.Row
        old_cursor = old_conn.cursor()
        new_cursor = new_conn.cursor()

        # Taşınacak tablolar listesi
        tables = [
            'user', 
            'version', 
            'site_content', 
            'service_status', 
            'system_message', 
            'app_feature', 
            'feedback'
        ]

        print("--- Veri Aktarımı Başlıyor ---")

        for table in tables:
            try:
                # Eski tablodaki tüm sütunları ve verileri al
                old_cursor.execute(f"SELECT * FROM {table}")
                rows = old_cursor.fetchall()
                
                if not rows:
                    print(f"Tablo '{table}' boş veya yok, atlanıyor.")
                    continue

                # Sütun adlarını al ve rezerve kelimeler (order vb.) için tırnak içine al
                columns = rows[0].keys()
                cols_str = ", ".join([f'"{col}"' for col in columns])
                placeholders = ", ".join(["?" for _ in columns])
                
                # Yeni veritabanına ekle
                # Önce o tablodaki mevcut verileri silelim (çakışma olmasın)
                new_cursor.execute(f"DELETE FROM {table}")
                
                insert_query = f"INSERT INTO {table} ({cols_str}) VALUES ({placeholders})"
                
                for row in rows:
                    values = [row[col] for col in columns]
                    new_cursor.execute(insert_query, values)
                
                print(f"Başarılı: '{table}' tablosundan {len(rows)} kayıt aktarıldı.")
            
            except sqlite3.OperationalError as e:
                print(f"Uyarı: '{table}' tablosu aktarılırken hata oluştu: {e}")

        new_conn.commit()
        print("--- Veri Aktarımı Tamamlandı! ---")
        print("Şimdi 'instance/database.db' dosyanızı PythonAnywhere sunucusuna yükleyip eskisiyle değiştirebilirsiniz.")

    except Exception as e:
        print(f"Beklenmeyen bir hata oluştu: {e}")
    finally:
        if 'old_conn' in locals(): old_conn.close()
        if 'new_conn' in locals(): new_conn.close()

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    old_db = os.path.join(current_dir, 'old_database.db')
    new_db = os.path.join(current_dir, 'instance', 'database.db')
    
    migrate_database(old_db, new_db)
