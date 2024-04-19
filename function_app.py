# import azure.functions as func
# import json
# #from werkzeug.security import generate_password_hash, check_password_hash
# # from sqlalchemy import Column, String, Integer, create_engine
# # from sqlalchemy.ext.declarative import declarative_base
# # from sqlalchemy.orm import sessionmaker
# import uuid
# from functools import wraps
# from azure.functions import HttpRequest, HttpResponse
# from typing import Dict, Any, Union

# app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


# #app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# Base = declarative_base()

# class User(Base):
#     __tablename__ = 'users'
#     id = Column(Integer, primary_key=True)
#     public_id = Column(String(50), unique=True, nullable=False)
#     email = Column(String(50), unique=True, nullable=False)
#     password = Column(String(100), nullable=False)
#     role = Column(String(20), nullable=False)

# engine = create_engine('sqlite:///:memory:', echo=True)
# Base.metadata.create_all(engine)
# Session = sessionmaker(bind=engine)


# # Mock user data
# mock_users = [
#     {"email": "user1@example.com", "password": "password1"},
#     {"email": "user2@example.com", "password": "password2"},
#     {"email": "user3@example.com", "password": "password3"}
# ]

# def fetch_user_data(email):
#     for user in mock_users:
#         if user['email'] == email:
#             return user
#     return None

# def route(route, auth_level):
#     def decorator(func):
#         def wrapper(req: func.HttpRequest):
#             if req.route_params and 'route' in req.route_params and req.route_params['route'] == route:
#                 if auth_level == func.AuthLevel.ANONYMOUS or req.params.get('auth_level') == auth_level:
#                     return func(req)
#                 else:
#                     return func.HttpResponse("Unauthorized", status_code=401)
#             else:
#                 return func.HttpResponse("Not Found", status_code=404)
#         return wrapper
#     return decorator


# def token_required(f):
#     @wraps(f)
#     def decorated_function(req: HttpRequest):
#         token = req.headers.get('Authorization')
#         if not token:
#             return func.HttpResponse("Token is missing", status_code=401)
#         try:
#             token_type, token_value = token.split()
#             if token_type.lower() != 'bearer':
#                 raise ValueError('Invalid token type')
#             data = jwt.decode(token_value, "testing", algorithms=['HS256'])
#             # Assuming you have the logic to retrieve user data from the token
#             current_user = fetch_user_data(data['public_id'])
#         except jwt.ExpiredSignatureError:
#             return func.HttpResponse("Token has expired", status_code=401)
#         except jwt.InvalidTokenError:
#             return func.HttpResponse("Token is invalid", status_code=401)
#         except (ValueError, KeyError):
#             return func.HttpResponse("Invalid token format", status_code=401)
#         return f(req, current_user)  # Assuming you pass current_user here
#     return decorated_function


# @app.route(route="user_registration_func001", auth_level=func.AuthLevel.ANONYMOUS)
# def user_registration_func001(req: func.HttpRequest) -> func.HttpResponse:
#     # Parse request body
#     try:
#         req_body = req.get_json()
#         email = req_body.get('email')
#         password = req_body.get('password')
#     except ValueError:
#         return func.HttpResponse(
#             "Invalid JSON format in request body",
#             status_code=400
#         )
#     # Here, we'll just return a success message with the provided email
#     if email and password:
#         response_data = {
#             "message": f"User registered successfully with email: {email}"
#         }
#         return func.HttpResponse(
#             json.dumps(response_data),
#             status_code=200,
#             mimetype="application/json"
#         )
#     else:
#         return func.HttpResponse(
#             "Email and password are required fields",
#             status_code=400
#         )


# @app.route(route="user_login_func002", auth_level=func.AuthLevel.ANONYMOUS)
# def user_login_func002(req: func.HttpRequest) -> func.HttpResponse:
#     # Parse request body
#     try:
#         req_body = req.get_json()
#         email = req_body.get('email')
#         password = req_body.get('password')
#     except ValueError:
#         return func.HttpResponse(
#             "Invalid JSON format in request body",
#             status_code=400
#         )
#     # Fetch user data dynamically
#     user_data = fetch_user_data(email)
#     if user_data and user_data['password'] == password:
#         response_data = {
#             "message": "User login successful"
#         }
#         return func.HttpResponse(
#             json.dumps(response_data),
#             status_code=200,
#             mimetype="application/json"
#         )
#     else:
#         return func.HttpResponse(
#             "Invalid email or password",
#             status_code=401
#         )

# @app.route(route="testuserfunc003")
# def another_authentication_type(req: func.HttpRequest) -> func.HttpResponse:
#     # Mock implementation of another authentication type
#     return func.HttpResponse("Another authentication type successful", status_code=200)


# @app.route(route="user_profile_func_003", auth_level=func.AuthLevel.ANONYMOUS)
# def user_profile_func_003(req: func.HttpRequest) -> func.HttpResponse:
#     # Mock user profile
#     mock_users = {}
#     user_id = req.params.get('user_id')

#     if not user_id:
#         return func.HttpResponse("User ID is required", status_code=400)

#     # Assuming user data is retrieved from a database based on the user ID
#     user_data = mock_users.get(user_id)

#     if not user_data:
#         return func.HttpResponse("User not found", status_code=404)
#     return func.HttpResponse("User profile retrieved successfully", status_code=200)


# @app.route(route="change_password_func_004", auth_level=func.AuthLevel.ANONYMOUS)
# def change_password_func_004(req: func.HttpRequest) -> func.HttpResponse:
#     # Mock change password
#     try:
#         req_body = req.get_json()
#         email = req_body.get('email')
#         old_password = req_body.get('old_password')
#         new_password = req_body.get('new_password')
#     except ValueError:
#         return func.HttpResponse(
#             "Invalid JSON format in request body",
#             status_code=400
#         )

#     if not email or not old_password or not new_password:
#         return func.HttpResponse(
#             "Email, old password, and new password are required fields",
#             status_code=400
#         )

#     # Fetch user data dynamically
#     user = fetch_user_data(email)
#     if user and check_password_hash(user.password, old_password):
#         # Generate hash for the new password
#         hashed_password = generate_password_hash(new_password)
#         # Update user's password in the database
#         session = Session()
#         user.password = hashed_password
#         session.commit()
#         session.close()
#         return func.HttpResponse(
#             "Password changed successfully",
#             status_code=200
#         )
#     else:
#         return func.HttpResponse(
#             "Invalid email or old password",
#             status_code=401
#         )
#     #return func.HttpResponse("Password changed successfully", status_code=200)


# @app.route(route="refresh_token_func_005", auth_level=func.AuthLevel.ANONYMOUS)
# def refresh_token_func_005(req: func.HttpRequest) -> func.HttpResponse:
#     # Mock token refresh
#     if req.method == 'POST':
#         # Implement token refresh functionality here
#         return func.HttpResponse("Token refresh endpoint", status_code=200)
#     else:
#         return func.HttpResponse("Method not allowed", status_code=405)
#     #return func.HttpResponse("Token refreshed successfully", status_code=200)



# @app.route(route="revoke_token_func_006", auth_level=func.AuthLevel.ANONYMOUS)
# def revoke_token_func_006(req: func.HttpRequest) -> func.HttpResponse:
#     # Mock token revoke
#     # Check if Authorization header is present
#     token_revoked = False
#     if 'Authorization' not in req.headers:
#         return func.HttpResponse("Authorization header is missing", status_code=401)
    
#     # Extract the token from Authorization header
#     auth_header = req.headers['Authorization']
#     token_type, token_value = auth_header.split(' ')
    
#     # Check if the token type is Bearer
#     if token_type.lower() != 'bearer':
#         return func.HttpResponse("Invalid token type", status_code=401)
    
#     # Decode the token
#     try:
#         decoded_token = jwt.decode(token_value, "YOUR_SECRET_KEY", algorithms=['HS256'])
#         # Assuming you have some logic to revoke the token in your system/database
#         # Example: token_revoked = revoke_token(decoded_token['token_id'])
#         # Check if the token is successfully revoked
#         if token_revoked:
#             return func.HttpResponse("Token revoked successfully", status_code=200)
#         else:
#             return func.HttpResponse("Failed to revoke token", status_code=500)
#     except jwt.ExpiredSignatureError:
#         return func.HttpResponse("Token has expired", status_code=401)
#     except jwt.InvalidTokenError:
#         return func.HttpResponse("Invalid token", status_code=401)
#     except Exception as e:
#         return func.HttpResponse(f"Error: {str(e)}", status_code=500)
#     #return func.HttpResponse("Token revoked successfully", status_code=200)

import azure.functions as func
import json

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

def route(route, auth_level):
    def decorator(func):
        def wrapper(req: func.HttpRequest):
            if req.route_params and 'route' in req.route_params and req.route_params['route'] == route:
                if auth_level == func.AuthLevel.ANONYMOUS or req.params.get('auth_level') == auth_level:
                    return func(req)
                else:
                    return func.HttpResponse("Unauthorized", status_code=401)
            else:
                return func.HttpResponse("Not Found", status_code=404)
        return wrapper
    return decorator

@app.route(route="user_registration_func001", auth_level=func.AuthLevel.ANONYMOUS)
def user_registration_func001(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        email = req_body.get('email')
        password = req_body.get('password')
    except ValueError:
        return func.HttpResponse("Invalid JSON format in request body", status_code=400)
    
    if email and password:
        response_data = {
            "message": f"User registered successfully with email: {email}"
        }
        return func.HttpResponse(json.dumps(response_data), status_code=200, mimetype="application/json")
    else:
        return func.HttpResponse("Email and password are required fields", status_code=400)

@app.route(route="user_login_func002", auth_level=func.AuthLevel.ANONYMOUS)
def user_login_func002(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        email = req_body.get('email')
        password = req_body.get('password')
    except ValueError:
        return func.HttpResponse("Invalid JSON format in request body", status_code=400)
    
    if email and password:
        # Mock user data retrieval
        mock_users = {
            "user1@example.com": "password1",
            "user2@example.com": "password2",
            "user3@example.com": "password3"
        }
        if email in mock_users and mock_users[email] == password:
            response_data = {
                "message": "User login successful"
            }
            return func.HttpResponse(json.dumps(response_data), status_code=200, mimetype="application/json")
        else:
            return func.HttpResponse("Invalid email or password", status_code=401)
    else:
        return func.HttpResponse("Email and password are required fields", status_code=400)

@app.route(route="user_profile_func_003", auth_level=func.AuthLevel.ANONYMOUS)
def user_profile_func_003(req: func.HttpRequest) -> func.HttpResponse:
    user_id = req.params.get('user_id')
    if not user_id:
        return func.HttpResponse("User ID is required", status_code=400)
    # Assuming user data is retrieved based on the user ID
    # Mock implementation
    user_data = {
        "user_id": user_id,
        "name": "Jan ALI",
        "email": "john.ali@example.com"
    }
    return func.HttpResponse(json.dumps(user_data), status_code=200, mimetype="application/json")

@app.route(route="change_password_func_004", auth_level=func.AuthLevel.ANONYMOUS)
def change_password_func_004(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        email = req_body.get('email')
        old_password = req_body.get('old_password')
        new_password = req_body.get('new_password')
    except ValueError:
        return func.HttpResponse("Invalid JSON format in request body", status_code=400)

    if not email or not old_password or not new_password:
        return func.HttpResponse("Email, old password, and new password are required fields", status_code=400)

    # Mock user data retrieval
    mock_users = {
        "user1@example.com": "password1",
        "user2@example.com": "password2",
        "user3@example.com": "password3"
    }
    
    if email in mock_users and mock_users[email] == old_password:
        # Mock implementation of password change
        mock_users[email] = new_password
        return func.HttpResponse("Password changed successfully", status_code=200)
    else:
        return func.HttpResponse("Invalid email or old password", status_code=401)

@app.route(route="refresh_token_func_005", auth_level=func.AuthLevel.ANONYMOUS)
def refresh_token_func_005(req: func.HttpRequest) -> func.HttpResponse:
    if req.method == 'POST':
        # Mock implementation of token refresh
        return func.HttpResponse("Token refresh endpoint", status_code=200)
    else:
        return func.HttpResponse("Method not allowed", status_code=405)

@app.route(route="revoke_token_func_006", auth_level=func.AuthLevel.ANONYMOUS)
def revoke_token_func_006(req: func.HttpRequest) -> func.HttpResponse:
    # Mock implementation of token revoke
    # Check if Authorization header is present
    if 'Authorization' not in req.headers:
        return func.HttpResponse("Authorization header is missing", status_code=401)
    
    # Mock implementation
    token_revoked = True
    
    if token_revoked:
        return func.HttpResponse("Token revoked successfully", status_code=200)
    else:
        return func.HttpResponse("Failed to revoke token", status_code=500)


@app.route(route="user_logout_func_fin_009", auth_level=func.AuthLevel.ANONYMOUS)
def user_logout_func_fin_009(req: func.HttpRequest) -> func.HttpResponse:
    # Mock implementation of logout
    # You can clear any session data or invalidate tokens here
    return func.HttpResponse("Logout successful", status_code=200)

    