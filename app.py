from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import re
from datetime import datetime, timedelta
import os
from bson import ObjectId
import uuid
import logging

app = Flask(__name__)

# Configure logging based on environment
ENV = os.getenv('ENVIRONMENT', 'development')
if ENV == 'production':
    # Production logging - minimal output
    logging.basicConfig(level=logging.WARNING)
    app.logger.setLevel(logging.WARNING)
else:
    # Development logging
    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)

# Production CORS configuration
CORS(app, origins=[
    os.getenv('FRONTEND_URL', 'https://tutorial-7-frontend.onrender.com'),
    "http://localhost:3000",  # For local development
    "http://localhost:5173",  # For Vite dev server
])

# Environment-based configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key-change-in-production')

# MongoDB connection with secure error handling
MONGO_URI = os.getenv('MONGO_URI', 'xxxxxxxxxxxxxxxxxxxxxxxxxxx')

def init_database():
    """Initialize database connection with secure error handling"""
    try:
        client = MongoClient(MONGO_URI)
        # Test connection without exposing URI
        client.admin.command('ping')
        
        if ENV == 'development':
            app.logger.info("✅ Database connection successful")
        
        db = client['registration_db']
        users_collection = db['users']
        products_collection = db['products']
        
        # Create indexes safely
        try:
            users_collection.create_index("email", unique=True)
            products_collection.create_index([("title", "text"), ("description", "text")])
            if ENV == 'development':
                app.logger.info("✅ Database indexes created")
        except Exception as e:
            if ENV == 'development':
                app.logger.warning(f"⚠️ Index creation warning: {str(e)[:50]}...")
        
        return db, users_collection, products_collection
        
    except Exception as e:
        if ENV == 'development':
            app.logger.error(f"❌ Database connection failed: {str(e)[:50]}...")
        else:
            app.logger.error("Database connection failed")
        # Return None values to handle gracefully
        return None, None, None

# Initialize database
db, users_collection, products_collection = init_database()

def auth_middleware(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not users_collection:
            return jsonify({'error': 'Database unavailable'}), 503
            
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_collection.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
        except Exception as e:
            app.logger.error(f"Token validation error: {str(e)[:50]}...")
            return jsonify({'error': 'Token validation failed'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def validate_auth_data(data, is_login=False):
    errors = {}

    if not is_login:
        name = data.get('name', '').strip()
        if not name:
            errors['name'] = 'Name is required'
        elif len(name) < 2:
            errors['name'] = 'Name must be at least 2 characters long'

    email = data.get('email', '').strip().lower()
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not email:
        errors['email'] = 'Email is required'
    elif not re.match(email_pattern, email):
        errors['email'] = 'Must be a valid email format'

    password = data.get('password', '')
    if not password:
        errors['password'] = 'Password is required'
    elif len(password) < 6:
        errors['password'] = 'Password must be at least 6 characters long'

    return errors

def validate_registration_data(data):
    errors = {}

    full_name = data.get('fullName', '').strip()
    if not full_name:
        errors['fullName'] = 'Full Name is required'
    elif len(full_name) < 2:
        errors['fullName'] = 'Full Name must be at least 2 characters long'

    email = data.get('email', '').strip().lower()
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not email:
        errors['email'] = 'Email is required'
    elif not re.match(email_pattern, email):
        errors['email'] = 'Must be a valid email format'

    phone = data.get('phone', '').strip()
    phone_digits = re.sub(r'\D', '', phone)
    if not phone:
        errors['phone'] = 'Phone number is required'
    elif len(phone_digits) < 10 or len(phone_digits) > 15:
        errors['phone'] = 'Phone must contain 10 to 15 digits only'
    elif not phone_digits.isdigit():
        errors['phone'] = 'Phone must contain digits only'

    password = data.get('password', '')
    if not password:
        errors['password'] = 'Password is required'
    elif len(password) < 6:
        errors['password'] = 'Password must be at least 6 characters long'

    confirm_password = data.get('confirmPassword', '')
    if not confirm_password:
        errors['confirmPassword'] = 'Confirm Password is required'
    elif password != confirm_password:
        errors['confirmPassword'] = 'Passwords do not match'

    return errors

@app.route('/api/auth/register', methods=['POST'])
def register_jwt():
    if not users_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        validation_errors = validate_auth_data(data)
        if validation_errors:
            return jsonify({
                'error': 'Validation failed',
                'errors': validation_errors
            }), 400

        existing_user = users_collection.find_one({'email': data['email'].strip().lower()})
        if existing_user:
            return jsonify({
                'error': 'Validation failed',
                'errors': {'email': 'Email already registered'}
            }), 400

        hashed_password = generate_password_hash(data['password'])

        user_data = {
            'name': data['name'].strip(),
            'email': data['email'].strip().lower(),
            'password': hashed_password,
            'createdAt': datetime.utcnow(),
            'isActive': True
        }

        result = users_collection.insert_one(user_data)
        user_id = str(result.inserted_id)

        token = jwt.encode({
            'user_id': user_id,
            'email': user_data['email'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': {
                'id': user_id,
                'name': user_data['name'],
                'email': user_data['email'],
                'createdAt': user_data['createdAt'].isoformat()
            }
        }), 201

    except Exception as e:
        app.logger.error(f"Registration error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/auth/login', methods=['POST'])
def login_jwt():
    if not users_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        validation_errors = validate_auth_data(data, is_login=True)
        if validation_errors:
            return jsonify({
                'error': 'Validation failed',
                'errors': validation_errors
            }), 400

        user = users_collection.find_one({'email': data['email'].strip().lower()})

        if not user or not check_password_hash(user['password'], data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401

        token = jwt.encode({
            'user_id': str(user['_id']),
            'email': user['email'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': str(user['_id']),
                'name': user.get('name', user.get('fullName', '')),
                'email': user['email']
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Login error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/auth/verify', methods=['GET'])
@auth_middleware
def verify_token(current_user):
    return jsonify({
        'message': 'Token is valid',
        'user': {
            'id': str(current_user['_id']),
            'name': current_user.get('name', current_user.get('fullName', '')),
            'email': current_user['email']
        }
    }), 200

@app.route('/api/products', methods=['GET'])
@auth_middleware
def get_products(current_user):
    if not products_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        sort_param = request.args.get('sort', '-createdAt')
        keyword = request.args.get('keyword', '')

        if page < 1:
            page = 1
        if limit < 1 or limit > 100:
            limit = 10

        query_filter = {}
        if keyword:
            query_filter['$text'] = {'$search': keyword}

        sort_criteria = []
        if sort_param:
            if sort_param.startswith('-'):
                field = sort_param[1:]
                direction = -1
            else:
                field = sort_param
                direction = 1
            sort_criteria.append((field, direction))

        skip = (page - 1) * limit

        cursor = products_collection.find(query_filter)

        if sort_criteria:
            cursor = cursor.sort(sort_criteria)

        cursor = cursor.skip(skip).limit(limit)

        products = list(cursor)

        for product in products:
            product['_id'] = str(product['_id'])
            if 'createdAt' in product:
                product['createdAt'] = product['createdAt'].isoformat()

        total_count = products_collection.count_documents(query_filter)
        total_pages = (total_count + limit - 1) // limit

        return jsonify({
            'message': 'Products retrieved successfully',
            'products': products,
            'pagination': {
                'currentPage': page,
                'totalPages': total_pages,
                'totalItems': total_count,
                'itemsPerPage': limit,
                'hasNext': page < total_pages,
                'hasPrev': page > 1
            },
            'filters': {
                'keyword': keyword,
                'sort': sort_param
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Get products error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/products', methods=['POST'])
@auth_middleware
def create_product(current_user):
    if not products_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        required_fields = ['title', 'description', 'price']
        errors = {}

        for field in required_fields:
            if not data.get(field):
                errors[field] = f'{field.capitalize()} is required'

        try:
            price = float(data.get('price', 0))
            if price <= 0:
                errors['price'] = 'Price must be a positive number'
        except (ValueError, TypeError):
            errors['price'] = 'Price must be a valid number'

        if errors:
            return jsonify({
                'error': 'Validation failed',
                'errors': errors
            }), 400

        product_data = {
            'id': str(uuid.uuid4()),
            'title': data['title'].strip(),
            'description': data['description'].strip(),
            'price': float(data['price']),
            'image': data.get('image', 'https://via.placeholder.com/300x200'),
            'createdBy': str(current_user['_id']),
            'createdAt': datetime.utcnow()
        }

        result = products_collection.insert_one(product_data)
        product_data['_id'] = str(result.inserted_id)
        product_data['createdAt'] = product_data['createdAt'].isoformat()

        return jsonify({
            'message': 'Product created successfully',
            'product': product_data
        }), 201

    except Exception as e:
        app.logger.error(f"Create product error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/products/<product_id>', methods=['GET'])
@auth_middleware
def get_product(current_user, product_id):
    if not products_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        product = products_collection.find_one({'id': product_id})

        if not product:
            return jsonify({'error': 'Product not found'}), 404

        product['_id'] = str(product['_id'])
        if 'createdAt' in product:
            product['createdAt'] = product['createdAt'].isoformat()

        return jsonify({
            'message': 'Product retrieved successfully',
            'product': product
        }), 200

    except Exception as e:
        app.logger.error(f"Get product error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/products/<product_id>', methods=['PUT'])
@auth_middleware
def update_product(current_user, product_id):
    if not products_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        product = products_collection.find_one({'id': product_id})

        if not product:
            return jsonify({'error': 'Product not found'}), 404

        update_data = {}
        if 'title' in data:
            update_data['title'] = data['title'].strip()
        if 'description' in data:
            update_data['description'] = data['description'].strip()
        if 'price' in data:
            try:
                update_data['price'] = float(data['price'])
                if update_data['price'] <= 0:
                    return jsonify({'error': 'Price must be positive'}), 400
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid price'}), 400
        if 'image' in data:
            update_data['image'] = data['image']

        update_data['updatedAt'] = datetime.utcnow()

        products_collection.update_one({'id': product_id}, {'$set': update_data})

        updated_product = products_collection.find_one({'id': product_id})
        updated_product['_id'] = str(updated_product['_id'])
        if 'createdAt' in updated_product:
            updated_product['createdAt'] = updated_product['createdAt'].isoformat()
        if 'updatedAt' in updated_product:
            updated_product['updatedAt'] = updated_product['updatedAt'].isoformat()

        return jsonify({
            'message': 'Product updated successfully',
            'product': updated_product
        }), 200

    except Exception as e:
        app.logger.error(f"Update product error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/products/<product_id>', methods=['DELETE'])
@auth_middleware
def delete_product(current_user, product_id):
    if not products_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        product = products_collection.find_one({'id': product_id})

        if not product:
            return jsonify({'error': 'Product not found'}), 404

        products_collection.delete_one({'id': product_id})

        return jsonify({
            'message': 'Product deleted successfully',
            'deletedProduct': {
                'id': product['id'],
                'title': product['title']
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Delete product error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/register', methods=['POST'])
def register_user():
    if not users_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        validation_errors = validate_registration_data(data)
        if validation_errors:
            return jsonify({
                'error': 'Validation failed',
                'errors': validation_errors
            }), 400

        existing_user = users_collection.find_one({'email': data['email'].strip().lower()})
        if existing_user:
            return jsonify({
                'error': 'Validation failed',
                'errors': {'email': 'Email already registered'}
            }), 400

        user_data = {
            'fullName': data['fullName'].strip(),
            'email': data['email'].strip().lower(),
            'phone': re.sub(r'\D', '', data['phone'].strip()),
            'password': generate_password_hash(data['password']),
            'createdAt': datetime.utcnow(),
            'isActive': True
        }

        result = users_collection.insert_one(user_data)

        response_data = {
            'id': str(result.inserted_id),
            'fullName': user_data['fullName'],
            'email': user_data['email'],
            'phone': user_data['phone'],
            'createdAt': user_data['createdAt'].isoformat()
        }

        return jsonify({
            'message': 'User registered successfully',
            'user': response_data
        }), 201

    except Exception as e:
        app.logger.error(f"Registration error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/login', methods=['POST'])
def login_user():
    if not users_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        data = request.get_json()

        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400

        user = users_collection.find_one({'email': data['email'].strip().lower()})

        if not user or not check_password_hash(user['password'], data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401

        response_data = {
            'id': str(user['_id']),
            'fullName': user.get('fullName', user.get('name', '')),
            'email': user['email'],
            'phone': user.get('phone', '')
        }

        return jsonify({
            'message': 'Login successful',
            'user': response_data
        }), 200

    except Exception as e:
        app.logger.error(f"Login error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/users', methods=['GET'])
def get_all_users():
    if not users_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        users = list(users_collection.find({}, {'password': 0}))

        for user in users:
            user['_id'] = str(user['_id'])
            if 'createdAt' in user:
                user['createdAt'] = user['createdAt'].isoformat()

        return jsonify({
            'message': 'Users retrieved successfully',
            'users': users,
            'count': len(users)
        }), 200

    except Exception as e:
        app.logger.error(f"Get users error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    if not users_collection:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)}, {'password': 0})

        if not user:
            return jsonify({'error': 'User not found'}), 404

        user['_id'] = str(user['_id'])
        if 'createdAt' in user:
            user['createdAt'] = user['createdAt'].isoformat()

        return jsonify({
            'message': 'User retrieved successfully',
            'user': user
        }), 200

    except Exception as e:
        app.logger.error(f"Get user error: {str(e)[:50]}...")
        return jsonify({
            'error': 'Internal server error',
            'details': 'Please try again' if ENV == 'production' else str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        status = 'healthy'
        db_status = 'connected'
        
        if db:
            db.command('ping')
        else:
            status = 'degraded'
            db_status = 'unavailable'
            
        return jsonify({
            'status': status,
            'message': 'API is running',
            'database': db_status,
            'timestamp': datetime.utcnow().isoformat(),
            'environment': ENV
        }), 200
    except Exception as e:
        app.logger.error(f"Health check error: {str(e)[:50]}...")
        return jsonify({
            'status': 'unhealthy',
            'message': 'Database connection failed',
            'error': 'Connection error',
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'Product Management API',
        'version': '1.0.0',
        'status': 'running',
        'environment': ENV,
        'endpoints': [
            '/api/health',
            '/api/auth/register',
            '/api/auth/login',
            '/api/auth/verify',
            '/api/products',
            '/api/register',
            '/api/login',
            '/api/users'
        ]
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port)
