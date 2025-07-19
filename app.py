# app.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import secrets # Benzersiz token üretmek için
from werkzeug.security import generate_password_hash, check_password_hash # Şifreleri güvenli saklamak için

app = Flask(__name__)

# Veritabanı yapılandırması
# Render'dan aldığın DATABASE_URL'yi buraya yapıştır veya Render'da Environment Variable olarak ayarla
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://YOUR_DB_USER:YOUR_DB_PASSWORD@YOUR_DB_HOST:YOUR_DB_PORT/YOUR_DB_NAME')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Veritabanı Modelleri ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    device_id = db.Column(db.String(255), unique=True, nullable=False) # Telefon UUID'si
    role = db.Column(db.String(50), default='pending', nullable=False) # pending, technician, manager, admin
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Admin kullanıcıları için şifre alanı (nullable çünkü tüm kullanıcılar şifre kullanmayacak)
    password_hash = db.Column(db.String(255), nullable=True)

    machines = db.relationship('Machine', secondary='user_machines', backref=db.backref('assigned_users', lazy=True))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'device_id': self.device_id,
            'role': self.role,
            'is_approved': self.is_approved,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'machines': [m.to_dict() for m in self.machines] if self.role == 'technician' else []
        }

class Machine(db.Model):
    __tablename__ = 'machines'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False) # Örneğin: "855-4", "Lavuk"
    mac_address = db.Column(db.String(17), unique=True, nullable=False) # XX:XX:XX:XX:XX:XX formatında
    is_active = db.Column(db.Boolean, default=True, nullable=False) # Makine aktif mi?
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'mac_address': self.mac_address,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

# Kullanıcılar ve Makineler arasında Many-to-Many ilişki için ara tablo
user_machines = db.Table('user_machines',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('machine_id', db.Integer, db.ForeignKey('machines.id'), primary_key=True)
)

class UsageLog(db.Model):
    __tablename__ = 'usage_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    machine_id = db.Column(db.Integer, db.ForeignKey('machines.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True) # Makine durduğunda güncellenecek
    duration_minutes = db.Column(db.Integer, nullable=True) # Kullanım süresi dakika cinsinden
    status = db.Column(db.String(50), nullable=False) # 'started', 'stopped'

    user = db.relationship('User', backref=db.backref('usage_logs', lazy=True))
    machine = db.relationship('Machine', backref=db.backref('usage_logs', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'machine_id': self.machine_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_minutes': self.duration_minutes,
            'status': self.status
        }

# --- API Endpointleri ---

# Cihaz kaydı/kimlik doğrulama endpointi
@app.route('/api/auth/device', methods=['POST'])
def auth_device():
    data = request.get_json()
    device_id = data.get('device_id')
    first_name = data.get('first_name')
    last_name = data.get('last_name')

    if not device_id:
        return jsonify({'message': 'Device ID is required'}), 400

    user = User.query.filter_by(device_id=device_id).first()

    if user:
        # Kullanıcı zaten kayıtlıysa
        if user.is_approved:
            # Onaylanmış kullanıcı
            return jsonify({
                'message': 'Authenticated',
                'user': user.to_dict()
            }), 200
        else:
            # Onay bekleyen kullanıcı
            return jsonify({
                'message': 'Pending approval',
                'user': user.to_dict()
            }), 202 # Accepted (işlem devam ediyor)
    else:
        # Yeni kayıt isteği
        if not (first_name and last_name):
            return jsonify({'message': 'First name and last name are required for new registration'}), 400

        new_user = User(first_name=first_name, last_name=last_name, device_id=device_id, role='pending', is_approved=False)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            'message': 'Registration request sent. Waiting for admin approval.',
            'user': new_user.to_dict()
        }), 201 # Created

# Admin girişi için endpoint (Web Admin Paneli kullanacak)
@app.route('/api/auth/admin_login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # admin_user = User.query.filter_by(role='admin').first() # Dinamik admin bulma
    # Sabit admin kullanıcı kontrolü (şimdilik)
    admin_user = User.query.filter_by(first_name='Admin', role='admin').first()


    if admin_user and admin_user.check_password(password):
        return jsonify({
            'message': 'Admin login successful',
            'user': admin_user.to_dict()
        }), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Makineciler için atanmış makineleri getirme
@app.route('/api/user/<string:device_id>/machines', methods=['GET'])
def get_user_machines(device_id):
    user = User.query.filter_by(device_id=device_id).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    if user.role != 'technician' or not user.is_approved:
        return jsonify({'message': 'Unauthorized access or user not approved'}), 403

    machines_data = [m.to_dict() for m in user.machines]
    return jsonify({'machines': machines_data}), 200


# Makine kullanım logu başlatma
@app.route('/api/usage_log/start', methods=['POST'])
def start_usage_log():
    data = request.get_json()
    user_device_id = data.get('user_device_id')
    mac_address = data.get('mac_address')

    user = User.query.filter_by(device_id=user_device_id).first()
    machine = Machine.query.filter_by(mac_address=mac_address).first()

    if not user or not machine:
        return jsonify({'message': 'User or Machine not found'}), 404
    if not user.is_approved:
        return jsonify({'message': 'User not approved'}), 403

    # Aynı makine için devam eden bir log var mı kontrol et (önceki logu bitirmediyse)
    # Bu senaryo yerine, mobil uygulama "DURDUR" komutunu göndermezse, 
    # API'nin bu durumu bir hata olarak işlemesi daha iyi olabilir.
    # Basitlik adına, şimdilik sadece yeni log oluşturuyoruz.

    new_log = UsageLog(user_id=user.id, machine_id=machine.id, start_time=datetime.utcnow(), status='started')
    db.session.add(new_log)
    db.session.commit()
    return jsonify({'message': 'Usage log started', 'log': new_log.to_dict()}), 201

# Makine kullanım logu bitirme
@app.route('/api/usage_log/stop', methods=['POST'])
def stop_usage_log():
    data = request.get_json()
    user_device_id = data.get('user_device_id')
    mac_address = data.get('mac_address')

    user = User.query.filter_by(device_id=user_device_id).first()
    machine = Machine.query.filter_by(mac_address=mac_address).first()

    if not user or not machine:
        return jsonify({'message': 'User or Machine not found'}), 404
    if not user.is_approved:
        return jsonify({'message': 'User not approved'}), 403

    # En son başlayan ve henüz bitmeyen logu bul
    latest_log = UsageLog.query.filter_by(user_id=user.id, machine_id=machine.id, status='started').order_by(UsageLog.start_time.desc()).first()

    if latest_log:
        latest_log.end_time = datetime.utcnow()
        duration = (latest_log.end_time - latest_log.start_time).total_seconds() / 60
        latest_log.duration_minutes = int(duration)
        latest_log.status = 'stopped'
        db.session.commit()
        return jsonify({'message': 'Usage log stopped', 'log': latest_log.to_dict()}), 200
    else:
        return jsonify({'message': 'No active usage log found for this user and machine'}), 404

# Admin ve Yönetici paneli endpointleri (Web Admin Paneli tarafından kullanılacak)
@app.route('/api/admin/users', methods=['GET', 'POST'])
def manage_users():
    # TODO: Burada admin/manager rol kontrolü yapılmalı
    if request.method == 'POST':
        data = request.get_json()
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        device_id = data.get('device_id')
        role = data.get('role', 'pending')
        is_approved = data.get('is_approved', False)
        password = data.get('password') # Sadece admin rolü için gelebilir

        if not (first_name and last_name and device_id):
            return jsonify({'message': 'Missing data'}), 400

        if User.query.filter_by(device_id=device_id).first():
            return jsonify({'message': 'User with this device ID already exists'}), 409

        new_user = User(first_name=first_name, last_name=last_name, device_id=device_id, role=role, is_approved=is_approved)
        if role == 'admin' and password:
            new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created', 'user': new_user.to_dict()}), 201

    # GET metodu
    users = User.query.all()
    return jsonify([user.to_dict() for user in users]), 200

@app.route('/api/admin/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
def manage_single_user(user_id):
    # TODO: Admin/manager rol kontrolü
    user = User.query.get_or_404(user_id)

    if request.method == 'GET':
        return jsonify(user.to_dict()), 200

    elif request.method == 'PUT':
        data = request.get_json()
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        user.role = data.get('role', user.role)
        user.is_approved = data.get('is_approved', user.is_approved)

        if user.role == 'admin' and 'password' in data and data['password']:
            user.set_password(data['password'])

        # Kullanıcıya makine atama/kaldırma
        if 'machines' in data and user.role == 'technician':
            machine_ids = data['machines'] # machines: [id1, id2] şeklinde liste
            user.machines = [] # Mevcut atamaları temizle
            for mid in machine_ids:
                machine = Machine.query.get(mid)
                if machine:
                    user.machines.append(machine)

        db.session.commit()
        return jsonify({'message': 'User updated', 'user': user.to_dict()}), 200

    elif request.method == 'DELETE':
        # Önce bu makineye atanan kullanıcıların atamasını kaldır
        # Bu, user_machines tablosundaki ilgili kayıtları siler.
        # CASCADE DELETE kullanmak da bir seçenek olabilir ancak manuel yönetim daha güvenli olabilir.
        # SQLAlchemy ORM ile direkt ilişkili kayıtları silmek
        # user_machines ilişkisini yönetmek için ekstra bir yaklaşım gerekebilir,
        # basitleştirilmiş olarak user_machines tablosundan direkt silme yapabiliriz

        # Öncelikle, bu makineye atanmış tüm user_machine kayıtlarını bulup siliyoruz
        for user in machine.assigned_users:
            user.machines.remove(machine) # İlişkiyi kaldır

        # Kullanım loglarını da sil (veya statüsünü güncelle)
        # Daha önce başlayan ve bitmeyen logları 'cancelled' yapabiliriz
        UsageLog.query.filter_by(machine_id=machine.id, status='started').update({'status': 'cancelled', 'end_time': datetime.utcnow()})
        db.session.delete(machine)
        db.session.commit()
        return jsonify({'message': 'Machine deleted'}), 204

@app.route('/api/admin/usage_logs', methods=['GET'])
def get_all_usage_logs():
    # TODO: Admin/manager rol kontrolü
    logs = UsageLog.query.order_by(UsageLog.start_time.desc()).all()
    return jsonify([log.to_dict() for log in logs]), 200

@app.route('/api/admin/create_admin_user', methods=['POST'])
def create_initial_admin():
    # Sadece ilk admin kullanıcısını oluşturmak için geçici endpoint
    # Production'da bu endpointi devre dışı bırakmak veya çok sıkı yetkilendirmek gerekir.
    # Amacımız, projenin başında senin için bir admin hesabı oluşturmak.
    admin_user_exists = User.query.filter_by(role='admin').first()
    if admin_user_exists:
        return jsonify({'message': 'Admin user already exists'}), 409

    data = request.get_json()
    password = data.get('password')
    if not password:
        return jsonify({'message': 'Password is required'}), 400

    # Kendi admin kullanıcın için:
    # Kullanıcı Adı: admin (first_name'i 'Admin' olarak kullandık)
    # Şifre: adminpass (bunu istekle göndereceğiz)
    new_admin = User(first_name='Admin', last_name='User', device_id='admin_device_id_placeholder', role='admin', is_approved=True)
    new_admin.set_password(password)
    db.session.add(new_admin)
    db.session.commit()
    return jsonify({'message': 'Initial admin user created'}), 201

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Tüm tabloları oluştur
        # İlk admin kullanıcısını burada oluşturmayacağız,
        # bunu /api/admin/create_admin_user endpointi üzerinden yapacağız.
        # Güvenlik nedeniyle bunu manuel tetiklemek daha iyi.

    app.run(debug=True) # debug=True sadece geliştirme ortamında kullanılmalı