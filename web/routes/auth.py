import os
import traceback
from urllib.parse import urlencode
from flask import Blueprint, redirect, request, session, current_app

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route("/login")
def auth_login():
    """Redirect user to Discord OAuth"""
    from app import create_oauth_state, get_redirect_uri, DISCORD_CLIENT_ID, DISCORD_OAUTH_SCOPES
    state = create_oauth_state()
    redirect_uri = get_redirect_uri()
    
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': DISCORD_OAUTH_SCOPES,
        'state': state
    }
    
    auth_url = f'https://discord.com/oauth2/authorize?{urlencode(params)}'
    current_app.logger.info(f"OAuth login initiated - Redirect URI: {redirect_uri}")
    return redirect(auth_url)

@auth_bp.route("/callback")
def auth_callback():
    """Handle Discord OAuth callback"""
    try:
        from app import (
            verify_oauth_state, get_redirect_uri, exchange_code_for_token, 
            get_user_info, get_user_guilds, create_user_session
        )
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        current_app.logger.info(f"OAuth callback received - code: {'present' if code else 'missing'}, state: {'present' if state else 'missing'}, error: {error}")
        
        if error:
            current_app.logger.error(f"OAuth error from Discord: {error}")
            return "<h1>Authentication Error</h1><p>Unable to authenticate with Discord. Please try again.</p><a href='/'>Return Home</a>", 400
        
        if not code or not state:
            current_app.logger.error("Missing code or state in OAuth callback")
            return "<h1>Authentication Error</h1><p>Invalid authentication request. Please try again.</p><a href='/'>Return Home</a>", 400
        
        state_valid, state_metadata = verify_oauth_state(state)
        if not state_valid:
            current_app.logger.error(f"Invalid OAuth state: {state[:8]}... (CSRF check failed)")
            return "<h1>Authentication Error</h1><p>Security validation failed. Please try again.</p><a href='/'>Return Home</a>", 400
        
        redirect_uri = get_redirect_uri()
        current_app.logger.info(f"Exchanging code for token with redirect_uri: {redirect_uri}")
        token_data = exchange_code_for_token(code, redirect_uri)
        access_token = token_data['access_token']
        refresh_token = token_data.get('refresh_token')
        
        current_app.logger.info("Fetching user info from Discord")
        user_data = get_user_info(access_token)
        current_app.logger.info(f"User authenticated: {user_data.get('username')}")
        
        current_app.logger.info("Fetching user guilds")
        guilds_data = get_user_guilds(access_token)
        current_app.logger.info(f"Found {len(guilds_data)} guilds")
        
        session_id = create_user_session(user_data, access_token, refresh_token, guilds_data)
        session['session_id'] = session_id
        current_app.logger.info(f"Session created: {session_id[:8]}...")
        
        purchase_intent = (state_metadata or {}).get('purchase_intent') or session.get('purchase_intent')
        if purchase_intent:
            session['purchase_intent'] = purchase_intent
            current_app.logger.info(f"Purchase flow detected via state metadata, redirecting to server selection for: {purchase_intent.get('product_type')}")
            return redirect('/purchase/select_server')
        
        return redirect('/dashboard')
        
    except Exception as e:
        current_app.logger.error(f"OAuth callback error: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return "<h1>Authentication Error</h1><p>An error occurred during authentication. Please try again later.</p><a href='/'>Return Home</a>", 500

@auth_bp.route("/logout")
def auth_logout():
    """Logout user"""
    from app import delete_user_session
    session_id = session.get('session_id')
    if session_id:
        delete_user_session(session_id)
        current_app.logger.info("User session cleared")
    session.clear()
    return redirect('/')
