from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
from config import config
import os
from werkzeug.utils import secure_filename
from datetime import datetime

# Models:
from models.ModelUser import ModelUser

# Entities
from models.entities.User import User

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Cambia esto por una clave segura

# Configuración de seguridad y base de datos
csrf = CSRFProtect(app)
db = MySQL(app)
login_manager_app = LoginManager(app)
login_manager_app.login_view = 'login'

# Configuración para subida de imágenes
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager_app.user_loader
def load_user(user_id):
    return ModelUser.get_by_id(db, user_id)

def crear_admin_fijo():
    """Crea el usuario admin fijo al iniciar la aplicación"""
    try:
        cursor = db.connection.cursor()
        # Verificar si el admin ya existe
        cursor.execute("SELECT id FROM users WHERE username = 'Elton' AND role = 'admin'")
        if not cursor.fetchone():
            hashed_pwd = generate_password_hash('188')
            cursor.execute(
                "INSERT INTO users (fullname, username, password, role) VALUES (%s, %s, %s, %s)",
                ('Elton Admin', 'Elton', hashed_pwd, 'admin')
            )
            db.connection.commit()
            print("✅ Admin fijo creado: Usuario: Elton / Contraseña: 188")
        cursor.close()
    except Exception as e:
        print(f"❌ Error creando admin fijo: {str(e)}")

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Verificación especial para el admin Elton
        if username == 'Elton' and password == '188':
            cursor = db.connection.cursor()
            cursor.execute("SELECT id, fullname, username, password, role FROM users WHERE username = 'Elton'")
            user = cursor.fetchone()
            
            if user:
                if check_password_hash(user[3], '188'):
                    user_obj = User(user[0], user[2], user[3], user[1], user[4])
                    login_user(user_obj)
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash("Contraseña de administrador incorrecta", "danger")
            else:
                flash("Admin no registrado en la base de datos", "danger")
            return redirect(url_for('login'))

        # Lógica normal para otros usuarios
        cursor = db.connection.cursor()
        cursor.execute("SELECT id, fullname, username, password, role FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[3], password):
            user_obj = User(user[0], user[2], user[3], user[1], user[4])
            login_user(user_obj)

            if user[4] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))

        flash("Usuario o contraseña incorrectos.", "danger")
        return redirect(url_for('login'))
    
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('carrito', None)
    flash('Has cerrado sesión correctamente.', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        role = 'cliente'

        if username.lower() == 'elton':
            flash("Este nombre de usuario no está disponible", "danger")
            return redirect(url_for('register'))

        cursor = db.connection.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash("Este usuario ya existe.", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        cursor.execute(
            "INSERT INTO users (fullname, username, password, role) VALUES (%s, %s, %s, %s)", 
            (fullname, username, hashed_password, role)
        )
        db.connection.commit()
        cursor.close()

        flash("Usuario creado exitosamente.", "success")
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    if not (current_user.role == 'admin' and current_user.username == 'Elton'):
        flash("Acceso denegado. Solo el administrador principal puede acceder", "danger")
        return redirect(url_for('home'))

    # Obtener estadísticas
    cursor = db.connection.cursor()
    
    # Total de productos
    cursor.execute("SELECT COUNT(*) FROM medicamentos")
    total_productos = cursor.fetchone()[0]
    
    # Total de usuarios
    cursor.execute("SELECT COUNT(*) FROM users")
    total_usuarios = cursor.fetchone()[0]
    
    # Total de pedidos
    cursor.execute("SELECT COUNT(*) FROM pedidos")
    total_pedidos = cursor.fetchone()[0]
    
    # Ventas totales
    cursor.execute("SELECT SUM(total) FROM pedidos")
    ventas_totales = cursor.fetchone()[0] or 0
    
    cursor.close()

    return render_template('admin/admin_dashboard.html', 
                         total_productos=total_productos,
                         total_usuarios=total_usuarios,
                         total_pedidos=total_pedidos,
                         ventas_totales=ventas_totales)

@app.route('/users')
@login_required
def users():
    if not (current_user.role == 'admin' and current_user.username == 'Elton'):
        flash("Acceso denegado. Solo el administrador principal puede acceder", "danger")
        return redirect(url_for('home'))

    cursor = db.connection.cursor()
    cursor.execute("SELECT id, fullname, username, role FROM users")
    users = cursor.fetchall()
    cursor.close()
    
    return render_template('users/users.html', users=users)

@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    if not (current_user.role == 'admin' and current_user.username == 'Elton'):
        flash("Acceso denegado. Solo el administrador principal puede acceder", "danger")
        return redirect(url_for('users'))

    cursor = db.connection.cursor()
    cursor.execute("SELECT username FROM users WHERE id = %s", (id,))
    user = cursor.fetchone()
    
    if user and user[0] == 'Elton':
        flash("No puedes eliminar al administrador principal", "danger")
        return redirect(url_for('users'))

    cursor.execute("DELETE FROM users WHERE id = %s", (id,))
    db.connection.commit()
    cursor.close()

    flash("Usuario eliminado correctamente.", "success")
    return redirect(url_for('users'))

# ===========================================
# CRUD de Medicamentos (ADMIN ONLY)
# ===========================================

@app.route('/admin/medicamentos')
@login_required
def base_admin():
    if not (current_user.role == 'admin' and current_user.username == 'Elton'):
        flash("Acceso denegado. Solo el administrador principal puede acceder", "danger")
        return redirect(url_for('home'))

    cursor = db.connection.cursor()
    cursor.execute("SELECT * FROM medicamentos")
    medicamentos = cursor.fetchall()
    cursor.close()
    
    return render_template('admin/medicamentosadmin.html', medicamentos=medicamentos)

@app.route('/admin/medicamentos/crear', methods=['GET', 'POST'])
@login_required
def crear_medicamento():
    if not (current_user.role == 'admin' and current_user.username == 'Elton'):
        flash("Acceso denegado. Solo el administrador principal puede acceder", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        nombre = request.form['nombre']
        descripcion = request.form['descripcion']
        precio = float(request.form['precio'])
        categoria = request.form.get('categoria', 'general')
        stock = int(request.form['stock'])
        fecha_caducidad = request.form['fecha_caducidad']
        
        if not nombre or not precio:
            flash('Nombre y precio son obligatorios', 'error')
            return redirect(request.url)
        
        if precio <= 0:
            flash('El precio debe ser mayor a 0', 'error')
            return redirect(request.url)
        
        if stock < 0:
            flash('El stock no puede ser negativo', 'error')
            return redirect(request.url)
        
        imagen = None
        if 'imagen' in request.files:
            file = request.files['imagen']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                imagen = filename

        try:
            cursor = db.connection.cursor()
            cursor.execute(
                """INSERT INTO medicamentos 
                (nombre, descripcion, precio, categoria, stock, fecha_caducidad, imagen) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (nombre, descripcion, precio, categoria, stock, fecha_caducidad, imagen)
            )
            db.connection.commit()
            cursor.close()
            flash('Medicamento creado correctamente!', 'success')
            return redirect(url_for('base_admin'))
        except Exception as e:
            flash(f'Error al crear medicamento: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('admin/crear_medicamento.html')

@app.route('/admin/medicamentos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_medicamento(id):
    if not (current_user.role == 'admin' and current_user.username == 'Elton'):
        flash("Acceso denegado. Solo el administrador principal puede acceder", "danger")
        return redirect(url_for('home'))

    cursor = db.connection.cursor()
    cursor.execute("SELECT * FROM medicamentos WHERE id = %s", (id,))
    medicamento = cursor.fetchone()
    
    if not medicamento:
        flash('Medicamento no encontrado', 'error')
        return redirect(url_for('base_admin'))

    if request.method == 'POST':
        nombre = request.form['nombre']
        descripcion = request.form['descripcion']
        precio = float(request.form['precio'])
        categoria = request.form.get('categoria', 'general')
        stock = int(request.form['stock'])
        fecha_caducidad = request.form['fecha_caducidad']
        
        if precio <= 0:
            flash('El precio debe ser mayor a 0', 'error')
            return redirect(request.url)
        
        if stock < 0:
            flash('El stock no puede ser negativo', 'error')
            return redirect(request.url)
        
        imagen = medicamento[6]
        if 'imagen' in request.files:
            file = request.files['imagen']
            if file.filename != '' and allowed_file(file.filename):
                if imagen and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], imagen)):
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], imagen))
                
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                imagen = filename

        try:
            cursor.execute(
                """UPDATE medicamentos SET 
                nombre=%s, descripcion=%s, precio=%s, categoria=%s, 
                stock=%s, fecha_caducidad=%s, imagen=%s 
                WHERE id=%s""",
                (nombre, descripcion, precio, categoria, stock, fecha_caducidad, imagen, id)
            )
            db.connection.commit()
            flash('Medicamento actualizado!', 'success')
            return redirect(url_for('base_admin'))
        except Exception as e:
            flash(f'Error al actualizar: {str(e)}', 'error')
    
    cursor.close()
    return render_template('admin/editar_medicamento.html', medicamento=medicamento)

@app.route('/admin/medicamentos/eliminar/<int:id>')
@login_required
def eliminar_medicamento(id):
    if not (current_user.role == 'admin' and current_user.username == 'Elton'):
        flash("Acceso denegado. Solo el administrador principal puede acceder", "danger")
        return redirect(url_for('home'))

    cursor = db.connection.cursor()
    cursor.execute("SELECT imagen FROM medicamentos WHERE id = %s", (id,))
    resultado = cursor.fetchone()
    
    try:
        if resultado and resultado[0]:
            imagen_path = os.path.join(app.config['UPLOAD_FOLDER'], resultado[0])
            if os.path.exists(imagen_path):
                os.remove(imagen_path)
        
        cursor.execute("DELETE FROM medicamentos WHERE id = %s", (id,))
        db.connection.commit()
        flash('Medicamento eliminado', 'success')
    except Exception as e:
        flash(f'Error al eliminar: {str(e)}', 'error')
    finally:
        cursor.close()
    
    return redirect(url_for('base_admin'))

# ===========================================
# Rutas para el carrito de compras (MEJORADAS)
# ===========================================

@app.route('/agregar_al_carrito/<int:producto_id>', methods=['POST'])
@login_required
def agregar_al_carrito(producto_id):
    if current_user.role == 'admin':
        flash("Los administradores no pueden realizar compras", "warning")
        return redirect(url_for('home'))

    try:
        cantidad = int(request.form.get('cantidad', 1))
        
        if cantidad < 1:
            flash('La cantidad debe ser al menos 1', 'error')
            return redirect(url_for('ver_productos'))

        cursor = db.connection.cursor()
        cursor.execute("""
            SELECT id, nombre, precio, imagen, stock 
            FROM medicamentos 
            WHERE id = %s
        """, (producto_id,))
        producto = cursor.fetchone()
        cursor.close()
        
        if not producto:
            flash('Producto no encontrado', 'error')
            return redirect(url_for('ver_productos'))
        
        if producto[4] < cantidad:
            flash(f'No hay suficiente stock. Solo quedan {producto[4]} unidades', 'error')
            return redirect(url_for('ver_productos'))
        
        # Estructura del producto para el carrito
        producto_dict = {
            'id': producto[0],
            'nombre': producto[1],
            'precio': float(producto[2]),
            'imagen': producto[3],
            'cantidad': cantidad
        }
        
        # Inicializar carrito si no existe
        if 'carrito' not in session:
            session['carrito'] = {}
        
        # Si el producto ya está en el carrito, sumar la cantidad
        if str(producto_id) in session['carrito']:
            nueva_cantidad = session['carrito'][str(producto_id)]['cantidad'] + cantidad
            if nueva_cantidad > producto[4]:
                flash(f'No hay suficiente stock. Solo quedan {producto[4]} unidades', 'error')
                return redirect(url_for('ver_productos'))
            session['carrito'][str(producto_id)]['cantidad'] = nueva_cantidad
        else:
            session['carrito'][str(producto_id)] = producto_dict
        
        session.modified = True
        flash(f'{producto[1]} agregado al carrito', 'success')
        return redirect(url_for('ver_productos'))
            
    except Exception as e:
        flash('Error al agregar producto al carrito', 'error')
        return redirect(url_for('ver_productos'))

@app.route('/eliminar_del_carrito/<int:producto_id>')
@login_required
def eliminar_del_carrito(producto_id):
    if current_user.role == 'admin':
        flash("Los administradores no pueden realizar compras", "warning")
        return redirect(url_for('home'))

    if 'carrito' in session and str(producto_id) in session['carrito']:
        del session['carrito'][str(producto_id)]
        session.modified = True
        flash('Producto eliminado del carrito', 'success')
    return redirect(url_for('ver_carrito'))

@app.route('/actualizar_carrito', methods=['POST'])
@login_required
def actualizar_carrito():
    if current_user.role == 'admin':
        flash("Los administradores no pueden realizar compras", "warning")
        return redirect(url_for('home'))

    if 'carrito' in session:
        try:
            cursor = db.connection.cursor()
            
            for producto_id, item in session['carrito'].items():
                nueva_cantidad = int(request.form.get(f'cantidad_{producto_id}', 1))
                
                if nueva_cantidad < 1:
                    del session['carrito'][producto_id]
                    continue
                
                # Verificar stock disponible
                cursor.execute("SELECT stock FROM medicamentos WHERE id = %s", (producto_id,))
                stock = cursor.fetchone()[0]
                
                if nueva_cantidad > stock:
                    flash(f'No hay suficiente stock para {item["nombre"]}. Máximo disponible: {stock}', 'error')
                    session['carrito'][producto_id]['cantidad'] = stock
                else:
                    session['carrito'][producto_id]['cantidad'] = nueva_cantidad
            
            cursor.close()
            session.modified = True
            flash('Carrito actualizado', 'success')
        except Exception as e:
            flash('Error al actualizar el carrito', 'error')
    
    return redirect(url_for('ver_carrito'))

@app.route('/carrito')
@login_required
def ver_carrito():
    if current_user.role == 'admin':
        flash("Los administradores no pueden realizar compras", "warning")
        return redirect(url_for('home'))

    carrito = session.get('carrito', {})
    
    # Calcular total
    total = 0
    for item in carrito.values():
        total += item['precio'] * item['cantidad']
    
    return render_template('carrito.html', carrito=carrito, total=total)

@app.route('/vaciar_carrito')
@login_required
def vaciar_carrito():
    if current_user.role == 'admin':
        flash("Los administradores no pueden realizar compras", "warning")
        return redirect(url_for('home'))

    if 'carrito' in session:
        session.pop('carrito')
        flash('Carrito vaciado', 'success')
    return redirect(url_for('ver_carrito'))

@app.route('/checkout')
@login_required
def checkout():
    if current_user.role == 'admin':
        flash("Los administradores no pueden realizar compras", "warning")
        return redirect(url_for('home'))

    carrito = session.get('carrito', {})
    if not carrito:
        flash('Tu carrito está vacío', 'error')
        return redirect(url_for('ver_carrito'))
    
    # Verificar stock antes de proceder al pago
    try:
        cursor = db.connection.cursor()
        productos_sin_stock = []
        
        for producto_id, item in carrito.items():
            cursor.execute("""
                SELECT nombre, stock 
                FROM medicamentos 
                WHERE id = %s AND stock >= %s
            """, (producto_id, item['cantidad']))
            
            if not cursor.fetchone():
                cursor.execute("SELECT nombre, stock FROM medicamentos WHERE id = %s", (producto_id,))
                producto = cursor.fetchone()
                productos_sin_stock.append({
                    'nombre': producto[0],
                    'stock': producto[1],
                    'solicitado': item['cantidad']
                })
        
        if productos_sin_stock:
            mensaje = "Algunos productos no tienen suficiente stock:<br>"
            for prod in productos_sin_stock:
                mensaje += f"- {prod['nombre']}: Stock {prod['stock']} (Solicitado: {prod['solicitado']})<br>"
            flash(mensaje, 'error')
            return redirect(url_for('ver_carrito'))
        
        # Calcular total
        total = sum(item['precio'] * item['cantidad'] for item in carrito.values())
        
        cursor.close()
        return render_template('checkout.html', carrito=carrito, total=total)
    
    except Exception as e:
        flash(f'Error al verificar stock: {str(e)}', 'error')
        return redirect(url_for('ver_carrito'))

@app.route('/procesar_pedido', methods=['POST'])
@login_required
def procesar_pedido():
    if current_user.role == 'admin':
        flash("Los administradores no pueden realizar compras", "warning")
        return redirect(url_for('home'))

    if 'carrito' not in session or not session['carrito']:
        flash('No hay productos en el carrito', 'error')
        return redirect(url_for('ver_carrito'))
    
    try:
        cursor = db.connection.cursor()
        
        # Verificar stock nuevamente (por si cambió desde el checkout)
        productos_sin_stock = []
        
        for producto_id, item in session['carrito'].items():
            cursor.execute("""
                SELECT nombre, stock 
                FROM medicamentos 
                WHERE id = %s AND stock >= %s
            """, (producto_id, item['cantidad']))
            
            if not cursor.fetchone():
                cursor.execute("SELECT nombre, stock FROM medicamentos WHERE id = %s", (producto_id,))
                producto = cursor.fetchone()
                productos_sin_stock.append({
                    'nombre': producto[0],
                    'stock': producto[1],
                    'solicitado': item['cantidad']
                })
        
        if productos_sin_stock:
            mensaje = "Algunos productos no tienen suficiente stock:<br>"
            for prod in productos_sin_stock:
                mensaje += f"- {prod['nombre']}: Stock {prod['stock']} (Solicitado: {prod['solicitado']})<br>"
            flash(mensaje, 'error')
            return redirect(url_for('ver_carrito'))
        
        # Calcular total
        total = sum(item['precio'] * item['cantidad'] for item in session['carrito'].values())
        
        # Crear pedido
        cursor.execute(
            "INSERT INTO pedidos (user_id, total, estado, fecha) VALUES (%s, %s, %s, %s)",
            (current_user.id, total, 'pendiente', datetime.now())
        )
        pedido_id = cursor.lastrowid
        
        # Crear detalles del pedido y actualizar stock
        for producto_id, item in session['carrito'].items():
            cursor.execute(
                "INSERT INTO detalles_pedido (pedido_id, producto_id, cantidad, precio_unitario) VALUES (%s, %s, %s, %s)",
                (pedido_id, producto_id, item['cantidad'], item['precio'])
            )
            
            # Actualizar stock
            cursor.execute(
                "UPDATE medicamentos SET stock = stock - %s WHERE id = %s",
                (item['cantidad'], producto_id)
            )
        
        db.connection.commit()
        session.pop('carrito')
        flash(f'Pedido realizado con éxito! Número: #{pedido_id}', 'success')
        return redirect(url_for('mis_pedidos'))
    
    except Exception as e:
        db.connection.rollback()
        flash(f'Error al procesar pedido: {str(e)}', 'error')
        return redirect(url_for('checkout'))

@app.route('/mis_pedidos')
@login_required
def mis_pedidos():
    if current_user.role == 'admin':
        return redirect(url_for('admin_pedidos'))

    cursor = db.connection.cursor()
    cursor.execute("""
        SELECT p.id, p.total, p.estado, p.fecha 
        FROM pedidos p 
        WHERE p.user_id = %s 
        ORDER BY p.fecha DESC
    """, (current_user.id,))
    pedidos = cursor.fetchall()
    
    # Obtener detalles para cada pedido
    pedidos_con_detalles = []
    for pedido in pedidos:
        cursor.execute("""
            SELECT m.nombre, dp.cantidad, dp.precio_unitario 
            FROM detalles_pedido dp
            JOIN medicamentos m ON dp.producto_id = m.id
            WHERE dp.pedido_id = %s
        """, (pedido[0],))
        detalles = cursor.fetchall()
        pedidos_con_detalles.append((pedido, detalles))
    
    cursor.close()
    return render_template('mis_pedidos.html', pedidos=pedidos_con_detalles)

@app.route('/admin/pedidos')
@login_required
def admin_pedidos():
    if not (current_user.role == 'admin' and current_user.username == 'Elton'):
        flash("Acceso denegado. Solo el administrador principal puede acceder", "danger")
        return redirect(url_for('home'))

    cursor = db.connection.cursor()
    cursor.execute("""
        SELECT p.id, u.fullname, p.total, p.estado, p.fecha 
        FROM pedidos p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.fecha DESC
    """)
    pedidos = cursor.fetchall()
    
    # Obtener detalles para cada pedido
    pedidos_con_detalles = []
    for pedido in pedidos:
        cursor.execute("""
            SELECT m.nombre, dp.cantidad, dp.precio_unitario 
            FROM detalles_pedido dp
            JOIN medicamentos m ON dp.producto_id = m.id
            WHERE dp.pedido_id = %s
        """, (pedido[0],))
        detalles = cursor.fetchall()
        pedidos_con_detalles.append((pedido, detalles))
    
    cursor.close()
    return render_template('admin/pedidos.html', pedidos=pedidos_con_detalles)

@app.route('/admin/pedidos/actualizar/<int:pedido_id>', methods=['POST'])
@login_required
def actualizar_estado_pedido(pedido_id):
    if not (current_user.role == 'admin' and current_user.username == 'Elton'):
        flash("Acceso denegado. Solo el administrador principal puede acceder", "danger")
        return redirect(url_for('home'))

    nuevo_estado = request.form.get('estado')
    if nuevo_estado not in ['pendiente', 'en_proceso', 'completado', 'cancelado']:
        flash('Estado no válido', 'error')
        return redirect(url_for('admin_pedidos'))

    try:
        cursor = db.connection.cursor()
        cursor.execute(
            "UPDATE pedidos SET estado = %s WHERE id = %s",
            (nuevo_estado, pedido_id)
        )
        db.connection.commit()
        flash('Estado del pedido actualizado', 'success')
    except Exception as e:
        db.connection.rollback()
        flash(f'Error al actualizar estado: {str(e)}', 'error')
    finally:
        cursor.close()
    
    return redirect(url_for('admin_pedidos'))

# ===========================================
# Rutas para productos (CLIENTES)
# ===========================================

@app.route('/home')
@login_required
def home():
    cursor = db.connection.cursor()
    cursor.execute("SELECT * FROM medicamentos WHERE stock > 0 ORDER BY RAND() LIMIT 4")
    productos_destacados = cursor.fetchall()
    cursor.close()
    return render_template('home.html', productos_destacados=productos_destacados)

@app.route('/productos')
@login_required
def ver_productos():
    if current_user.role == 'admin':
        return redirect(url_for('base_admin'))

    categoria = request.args.get('categoria', 'todos')
    
    cursor = db.connection.cursor()
    
    if categoria == 'todos':
        cursor.execute("SELECT * FROM medicamentos WHERE stock > 0")
    else:
        cursor.execute("SELECT * FROM medicamentos WHERE categoria = %s AND stock > 0", (categoria,))
    
    productos = cursor.fetchall()
    cursor.close()
    
    return render_template('productos.html', productos=productos, categoria_actual=categoria)

@app.route('/producto/<int:id>')
@login_required
def ver_producto(id):
    if current_user.role == 'admin':
        return redirect(url_for('base_admin'))

    cursor = db.connection.cursor()
    cursor.execute("SELECT * FROM medicamentos WHERE id = %s", (id,))
    producto = cursor.fetchone()
    cursor.close()
    
    if not producto:
        flash('Producto no encontrado', 'error')
        return redirect(url_for('ver_productos'))
    
    return render_template('detalle_producto.html', producto=producto)

# ===========================================
# Otras rutas
# ===========================================

@app.route('/eventos')
@login_required
def eventos():
    return render_template('eventos.html')

@app.route('/contacto', methods=['GET', 'POST'])
@login_required
def contacto():
    if request.method == 'POST':
        flash('Mensaje enviado correctamente', 'success')
        return redirect(url_for('contacto'))
    return render_template('contacto.html')

# ===========================================
# Manejo de errores
# ===========================================

@app.errorhandler(401)
def status_401(error):
    flash("Acceso no autorizado.", "danger")
    return redirect(url_for('login'))

@app.errorhandler(404)
def status_404(error):
    return render_template('errors/404.html'), 404

# ===========================================
# Inicialización de la aplicación
# ===========================================

def inicializar_base_de_datos():
    try:
        cursor = db.connection.cursor()
        
        # Verificar existencia de tabla medicamentos
        cursor.execute("SHOW TABLES LIKE 'medicamentos'")
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE medicamentos (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    nombre VARCHAR(100) NOT NULL,
                    descripcion TEXT,
                    precio DECIMAL(10,2) NOT NULL,
                    categoria VARCHAR(50) DEFAULT 'general',
                    stock INT NOT NULL DEFAULT 0,
                    fecha_caducidad DATE,
                    imagen VARCHAR(255),
                    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            db.connection.commit()
            print("✅ Tabla 'medicamentos' creada")
        
        # Verificar existencia de tabla pedidos
        cursor.execute("SHOW TABLES LIKE 'pedidos'")
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE pedidos (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    total DECIMAL(10,2) NOT NULL,
                    estado ENUM('pendiente', 'en_proceso', 'completado', 'cancelado') DEFAULT 'pendiente',
                    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            db.connection.commit()
            print("✅ Tabla 'pedidos' creada")
        
        # Verificar existencia de tabla detalles_pedido
        cursor.execute("SHOW TABLES LIKE 'detalles_pedido'")
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE detalles_pedido (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    pedido_id INT NOT NULL,
                    producto_id INT NOT NULL,
                    cantidad INT NOT NULL,
                    precio_unitario DECIMAL(10,2) NOT NULL,
                    FOREIGN KEY (pedido_id) REFERENCES pedidos(id),
                    FOREIGN KEY (producto_id) REFERENCES medicamentos(id)
                )
            """)
            db.connection.commit()
            print("✅ Tabla 'detalles_pedido' creada")
        
        # Verificar existencia de columna categoria en medicamentos
        cursor.execute("SHOW COLUMNS FROM medicamentos LIKE 'categoria'")
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE medicamentos ADD COLUMN categoria VARCHAR(50) DEFAULT 'general'")
            db.connection.commit()
            print("✅ Columna 'categoria' añadida a medicamentos")
        
        # Crear admin fijo
        crear_admin_fijo()
        
        cursor.close()
    except Exception as e:
        print(f"❌ Error inicializando base de datos: {str(e)}")

if __name__ == '__main__':
    app.config.from_object(config['development'])
    csrf.init_app(app)
    
    # Crear carpeta de uploads si no existe
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    # Inicializar base de datos
    with app.app_context():
        inicializar_base_de_datos()
    
    app.run(debug=True)