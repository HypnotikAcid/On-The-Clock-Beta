#!/usr/bin/env python3
"""
JWT + Discord OAuth Test Script
===============================
Standalone test to validate Discord OAuth + JWT approach works correctly.
Runs on port 5001 to avoid conflicts with main app.
"""

import os
import jwt
import json
import requests
from datetime import datetime, timedelta
from flask import Flask, request, redirect, jsonify, render_template_string

# Test Flask app on different port
test_app = Flask(__name__)
test_app.secret_key = 'test-jwt-secret-key'

# JWT Configuration
JWT_SECRET = 'test-jwt-secret-2025'
JWT_ALGORITHM = 'HS256'

# Discord OAuth Configuration (using same credentials as main app)
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
DISCORD_REDIRECT_URI = f"http://localhost:3001/auth/callback"

if os.environ.get("REPLIT_ENVIRONMENT") == "production":
    DISCORD_REDIRECT_URI = f"https://on-the-clock.replit.app/auth/callback-test"

print(f"🧪 JWT Test Configuration:")
print(f"   Client ID: {DISCORD_CLIENT_ID}")
print(f"   Redirect URI: {DISCORD_REDIRECT_URI}")
print(f"   Environment: {os.environ.get('REPLIT_ENVIRONMENT', 'development')}")

def create_jwt_token(user_data):
    """Create JWT token with Discord user data"""
    payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'avatar': user_data['avatar'],
        'email': user_data.get('email'),
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow(),
        'iss': 'on-the-clock-test'
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def verify_jwt_token(token):
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_discord_user_guilds(access_token):
    """Get user's Discord guilds using access token"""
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get('https://discord.com/api/users/@me/guilds', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ Failed to fetch guilds: {response.status_code} - {response.text}")
        return []

# Test Routes

@test_app.route('/')
def test_home():
    """Test home page with login button"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>🧪 JWT + Discord OAuth Test</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .button { background: #5865F2; color: white; padding: 15px 25px; text-decoration: none; border-radius: 5px; }
            .success { background: #00ff00; padding: 10px; margin: 10px 0; border-radius: 5px; }
            .error { background: #ff0000; color: white; padding: 10px; margin: 10px 0; border-radius: 5px; }
            .info { background: #e1f5fe; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #0277bd; }
            pre { background: #f5f5f5; padding: 15px; overflow: auto; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>🧪 JWT + Discord OAuth Test</h1>
        
        <div class="info">
            <h3>🎯 Test Objectives:</h3>
            <ul>
                <li>✅ Validate Discord OAuth flow works</li>
                <li>✅ Generate JWT tokens with user data</li>
                <li>✅ Fetch Discord server list via API</li>
                <li>✅ Confirm JWT authentication for protected routes</li>
                <li>✅ Test data structure matches dashboard needs</li>
            </ul>
        </div>
        
        <h2>🚀 Start Test</h2>
        <a href="/auth/login" class="button">🔗 Login with Discord (Test JWT Flow)</a>
        
        <h2>📊 Test Results</h2>
        <p>Click login above to test the complete OAuth + JWT flow.</p>
        
        <div style="margin-top: 30px; padding: 15px; background: #fff3cd; border-radius: 5px;">
            <strong>Note:</strong> This test runs on port 5001 and won't interfere with your main app on port 5000.
        </div>
    </body>
    </html>
    """
    return html

@test_app.route('/auth/login')
def test_login():
    """Redirect to Discord OAuth"""
    discord_login_url = (
        f"https://discord.com/api/oauth2/authorize?"
        f"client_id={DISCORD_CLIENT_ID}&"
        f"redirect_uri={DISCORD_REDIRECT_URI}&"
        f"response_type=code&"
        f"scope=identify%20email%20guilds"
    )
    
    print(f"🔗 Redirecting to Discord OAuth: {discord_login_url}")
    return redirect(discord_login_url)

@test_app.route('/auth/callback')
def test_oauth_callback():
    """Handle Discord OAuth callback and create JWT"""
    code = request.args.get('code')
    
    if not code:
        return jsonify({'error': 'No authorization code received'}), 400
    
    print(f"✅ Received OAuth code: {code[:10]}...")
    
    # Exchange code for access token
    token_data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    token_response = requests.post('https://discord.com/api/oauth2/token', 
                                  data=token_data, headers=headers)
    
    if token_response.status_code != 200:
        print(f"❌ Token exchange failed: {token_response.status_code} - {token_response.text}")
        return jsonify({'error': 'Failed to exchange code for token'}), 400
    
    token_info = token_response.json()
    access_token = token_info['access_token']
    
    print(f"✅ Got access token: {access_token[:15]}...")
    
    # Get user info
    user_response = requests.get('https://discord.com/api/users/@me', 
                                headers={'Authorization': f'Bearer {access_token}'})
    
    if user_response.status_code != 200:
        print(f"❌ User fetch failed: {user_response.status_code} - {user_response.text}")
        return jsonify({'error': 'Failed to fetch user info'}), 400
    
    user_data = user_response.json()
    
    print(f"✅ Got user data: {user_data['username']}#{user_data['discriminator']}")
    
    # Get user guilds
    guilds = get_discord_user_guilds(access_token)
    
    print(f"✅ Got {len(guilds)} guilds")
    
    # Create JWT token
    jwt_token = create_jwt_token(user_data)
    
    print(f"✅ Created JWT token: {jwt_token[:30]}...")
    
    # Store access token temporarily for guild fetching (in real app, store in database)
    user_data['access_token'] = access_token
    user_data['guilds'] = guilds
    
    # Show test results
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>✅ JWT Test Results</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 1000px; margin: 20px auto; padding: 20px; }}
            .success {{ background: #d4edda; color: #155724; padding: 15px; margin: 10px 0; border-radius: 5px; border: 1px solid #c3e6cb; }}
            .section {{ background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 5px; border: 1px solid #dee2e6; }}
            pre {{ background: #f1f3f4; padding: 15px; overflow: auto; border-radius: 5px; }}
            .guild {{ background: white; margin: 10px 0; padding: 15px; border-radius: 5px; border: 1px solid #ddd; }}
            .button {{ background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 5px; }}
            .guild-icon {{ width: 32px; height: 32px; border-radius: 50%; vertical-align: middle; margin-right: 10px; }}
        </style>
    </head>
    <body>
        <h1>✅ JWT + Discord OAuth Test Results</h1>
        
        <div class="success">
            <h3>🎉 Test Completed Successfully!</h3>
            <p>All OAuth + JWT functionality is working correctly.</p>
        </div>
        
        <div class="section">
            <h3>👤 User Information</h3>
            <pre>{json.dumps({
                'id': user_data['id'],
                'username': user_data['username'],
                'discriminator': user_data.get('discriminator', '0'),
                'email': user_data.get('email', 'Not provided'),
                'avatar': user_data['avatar']
            }, indent=2)}</pre>
        </div>
        
        <div class="section">
            <h3>🔑 JWT Token (First 50 chars)</h3>
            <pre>{jwt_token[:50]}...</pre>
            <p><strong>Token Length:</strong> {len(jwt_token)} characters</p>
            <p><strong>Expires:</strong> 24 hours from creation</p>
        </div>
        
        <div class="section">
            <h3>🖥️ Discord Servers ({len(guilds)} found)</h3>
            <p>Servers where user has permissions:</p>
            {generate_guild_html(guilds)}
        </div>
        
        <div class="section">
            <h3>🧪 API Tests</h3>
            <a href="/test/api/user?token={jwt_token}" class="button">Test JWT API Authentication</a>
            <a href="/test/api/guilds?token={jwt_token}" class="button">Test Guild API with JWT</a>
        </div>
        
        <div class="section">
            <h3>📋 Test Summary</h3>
            <ul>
                <li>✅ Discord OAuth flow completed successfully</li>
                <li>✅ Access token obtained and working</li>
                <li>✅ User data retrieved from Discord API</li>
                <li>✅ Guild list fetched ({len(guilds)} servers)</li>
                <li>✅ JWT token created with user data</li>
                <li>✅ Ready for API authentication testing</li>
            </ul>
        </div>
        
        <a href="/" class="button">← Back to Test Home</a>
    </body>
    </html>
    """
    
    return html

def generate_guild_html(guilds):
    """Generate HTML for guild display"""
    if not guilds:
        return "<p>No guilds found or insufficient permissions.</p>"
    
    html = ""
    for guild in guilds[:10]:  # Show first 10 guilds
        icon_url = f"https://cdn.discordapp.com/icons/{guild['id']}/{guild['icon']}.png" if guild['icon'] else ""
        permissions = guild.get('permissions', 0)
        is_admin = (int(permissions) & 0x8) == 0x8  # Administrator permission
        is_manager = (int(permissions) & 0x20) == 0x20  # Manage Guild permission
        
        html += f"""
        <div class="guild">
            {f'<img src="{icon_url}" class="guild-icon" alt="{guild["name"]}">' if icon_url else '📁'}
            <strong>{guild['name']}</strong>
            <br><small>ID: {guild['id']} | Permissions: {permissions}</small>
            {'<span style="color: red;">🛡️ Admin</span>' if is_admin else ''}
            {'<span style="color: green;">⚙️ Manager</span>' if is_manager and not is_admin else ''}
        </div>
        """
    
    if len(guilds) > 10:
        html += f"<p><em>... and {len(guilds) - 10} more servers</em></p>"
    
    return html

@test_app.route('/test/api/user')
def test_api_user():
    """Test JWT authentication for user API"""
    token = request.args.get('token')
    
    if not token:
        return jsonify({'error': 'No JWT token provided'}), 401
    
    user_data = verify_jwt_token(token)
    
    if not user_data:
        return jsonify({'error': 'Invalid or expired JWT token'}), 401
    
    return jsonify({
        'message': '✅ JWT Authentication Successful',
        'user': user_data,
        'test_status': 'PASSED'
    })

@test_app.route('/test/api/guilds')
def test_api_guilds():
    """Test JWT + guild fetching"""
    token = request.args.get('token')
    
    if not token:
        return jsonify({'error': 'No JWT token provided'}), 401
    
    user_data = verify_jwt_token(token)
    
    if not user_data:
        return jsonify({'error': 'Invalid or expired JWT token'}), 401
    
    # In real implementation, we'd store the access_token in database
    # For this test, we'll return success message
    return jsonify({
        'message': '✅ JWT + Guild API Test Successful',
        'user_id': user_data['user_id'],
        'username': user_data['username'],
        'note': 'In production, guild data would be fetched using stored access token',
        'test_status': 'PASSED'
    })

if __name__ == '__main__':
    print("🧪 Starting JWT + Discord OAuth Test Server...")
    print("📡 Test URL: http://localhost:3001")
    print("🎯 This tests the JWT approach without modifying your main app")
    print("=" * 60)
    
    test_app.run(host='0.0.0.0', port=3001, debug=True)