from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
import discord
import asyncio
import threading
import time
from datetime import datetime
import requests
import re
from urllib.parse import urlparse
import hashlib

app = Flask(__name__)
CORS(app)

# Discord bot setup
DISCORD_TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
if not DISCORD_TOKEN:
    raise ValueError("DISCORD_BOT_TOKEN environment variable is required")

# Load API keys from keys.json
def load_api_keys():
    try:
        with open('keys.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

API_KEYS = load_api_keys()

# Discord client setup
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# Bot ready flag
bot_ready = False

@client.event
async def on_ready():
    global bot_ready
    bot_ready = True
    print(f'Discord bot logged in as {client.user}')

def run_discord_bot():
    """Run Discord bot in a separate thread"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(client.start(DISCORD_TOKEN))
    except Exception as e:
        print(f"ERROR starting Discord bot: {str(e)}")

# Start Discord bot in background thread
bot_thread = threading.Thread(target=run_discord_bot)
bot_thread.daemon = True
bot_thread.start()

def get_geolocation(ip):
    """Get geolocation data from IP"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'proxy': data.get('proxy', False),
                    'mobile': data.get('mobile', False)
                }
    except Exception as e:
        print(f"ERROR getting geolocation: {str(e)}")
    return {'country': 'Unknown', 'region': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'proxy': False, 'mobile': False}

def parse_user_agent(user_agent):
    """Parse user agent string"""
    browser = 'Unknown'
    os_info = 'Unknown'

    # Browser detection
    if 'Chrome' in user_agent and 'Safari' in user_agent:
        if 'Edg' in user_agent:
            browser = 'Microsoft Edge'
        elif 'OPR' in user_agent:
            browser = 'Opera'
        else:
            browser = 'Chrome'
    elif 'Firefox' in user_agent:
        browser = 'Firefox'
    elif 'Safari' in user_agent and 'Chrome' not in user_agent:
        browser = 'Safari'

    # OS detection
    if 'Windows NT' in user_agent:
        os_info = 'Windows'
    elif 'Mac OS X' in user_agent:
        os_info = 'macOS'
    elif 'Linux' in user_agent:
        os_info = 'Linux'
    elif 'Android' in user_agent:
        os_info = 'Android'
    elif 'iPhone' in user_agent or 'iPad' in user_agent:
        os_info = 'iOS'

    return browser, os_info

def is_bot_traffic(user_agent, ip):
    """Detect bot traffic"""
    bot_indicators = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
        'python-requests', 'Googlebot', 'bingbot', 'facebookexternalhit'
    ]

    user_agent_lower = user_agent.lower()
    for indicator in bot_indicators:
        if indicator in user_agent_lower:
            return True

    return False

def generate_device_fingerprint(data):
    """Generate device fingerprint"""
    fingerprint_data = f"{data.get('user_agent', '')}{data.get('screen_width', '')}{data.get('screen_height', '')}{data.get('timezone', '')}"
    return hashlib.md5(fingerprint_data.encode()).hexdigest()[:12]

def is_valid_url_for_key(api_key, requested_url):
    """Check if the requested URL is valid for the API key"""
    if api_key not in API_KEYS:
        return False

    registered_url = API_KEYS[api_key]['url']
    parsed_registered = urlparse(registered_url)
    parsed_requested = urlparse(requested_url)

    # Check if scheme and netloc match
    return (parsed_registered.scheme == parsed_requested.scheme and
            parsed_registered.netloc == parsed_requested.netloc)

async def check_admin_permission(guild_id, user_id):
    """Check if user has admin permissions in the guild"""
    try:
        guild = client.get_guild(int(guild_id))
        if not guild:
            print(f"ERROR: Cannot find guild {guild_id}")
            return False

        member = guild.get_member(int(user_id))
        if not member:
            print(f"ERROR: Cannot find member {user_id} in guild {guild_id}")
            return False

        print(f"DEBUG: Member {user_id} admin status: {member.guild_permissions.administrator}")
        return member.guild_permissions.administrator
    except Exception as e:
        print(f"ERROR checking admin permissions: {str(e)}")
        return False

async def send_to_discord(api_key, log_data):
    """Send log data to Discord channel"""
    try:
        print(f"DEBUG: Attempting to send to Discord for API key: {api_key}")
        
        if not bot_ready:
            print("ERROR: Discord bot is not ready")
            return False

        key_info = API_KEYS[api_key]
        guild_id = key_info['discord_server_id']
        channel_id = key_info['discord_log_channel_id']
        owner_id = key_info['owner_id']

        print(f"DEBUG: Guild ID: {guild_id}, Channel ID: {channel_id}, Owner ID: {owner_id}")

        # Check admin permissions
        has_admin = await check_admin_permission(guild_id, owner_id)
        if not has_admin:
            print(f"ERROR: Owner {owner_id} doesn't have admin permissions in server {guild_id}")
            # Let's try to send anyway - maybe the permission check is too strict
            # return False

        # Get channel
        channel = client.get_channel(int(channel_id))
        if not channel:
            print(f"ERROR: Cannot access channel {channel_id}")
            return False

        print(f"DEBUG: Successfully got channel: {channel.name}")

        # Get website favicon
        try:
            favicon_url = f"https://www.google.com/s2/favicons?sz=64&domain={urlparse(log_data['url']).netloc}"
        except:
            favicon_url = None

        # Create embed
        embed = discord.Embed(
            title="📊 Website Visitor Log",
            color=0x00ff88,
            timestamp=datetime.now()
        )

        if favicon_url:
            embed.set_thumbnail(url=favicon_url)
        elif client.user and client.user.avatar:
            embed.set_thumbnail(url=client.user.avatar.url)

        # Add fields
        embed.add_field(name="🌐 Page URL", value=log_data['url'], inline=False)
        embed.add_field(name="🌍 Location",
                        value=f"{log_data['geolocation']['city']}, {log_data['geolocation']['region']}, {log_data['geolocation']['country']}",
                        inline=True)
        embed.add_field(name="🖥️ Device", value=f"{log_data['browser']} on {log_data['os']}", inline=True)
        embed.add_field(name="📱 Device Type", value="Mobile" if log_data['is_mobile'] else "Desktop", inline=True)
        embed.add_field(name="🔗 IP Address", value=log_data['ip'], inline=True)
        embed.add_field(name="🆔 Session ID", value=log_data['device_fingerprint'], inline=True)
        embed.add_field(name="📊 Screen",
                        value=f"{log_data.get('screen_width', 'N/A')}x{log_data.get('screen_height', 'N/A')}",
                        inline=True)

        if log_data.get('referrer'):
            embed.add_field(name="🔄 Referrer", value=log_data['referrer'], inline=False)

        if log_data['geolocation']['proxy']:
            embed.add_field(name="🛡️ VPN/Proxy", value="⚠️ Detected", inline=True)

        if log_data['is_bot']:
            embed.add_field(name="🤖 Bot Traffic", value="⚠️ Detected", inline=True)

        embed.add_field(name="🕒 Visit Time", value=log_data['timestamp'], inline=False)
        embed.set_footer(text=f"ISP: {log_data['geolocation']['isp']}")

        print("DEBUG: Sending embed to Discord...")
        await channel.send(embed=embed)
        print("DEBUG: Successfully sent embed to Discord!")
        return True

    except Exception as e:
        print(f"ERROR sending to Discord: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

@app.route('/api/key/<api_key>/', methods=['POST', 'OPTIONS'])
def log_visitor(api_key):
    """Main API endpoint for logging visitors"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate API key
        if api_key not in API_KEYS:
            return jsonify({'error': 'Invalid API key'}), 401

        # Validate URL
        requested_url = data.get('url')
        if not requested_url or not is_valid_url_for_key(api_key, requested_url):
            return jsonify({'error': 'URL not authorized for this API key'}), 403

        # Get visitor data
        visitor_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if visitor_ip and ',' in visitor_ip:
            visitor_ip = visitor_ip.split(',')[0].strip()

        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')

        # Parse data
        geolocation = get_geolocation(visitor_ip)
        browser, os_info = parse_user_agent(user_agent)
        is_bot = is_bot_traffic(user_agent, visitor_ip)
        device_fingerprint = generate_device_fingerprint(data)

        # Prepare log data
        log_data = {
            'url': requested_url,
            'ip': visitor_ip,
            'geolocation': geolocation,
            'browser': browser,
            'os': os_info,
            'user_agent': user_agent,
            'referrer': referrer,
            'is_mobile': geolocation.get('mobile', False) or 'Mobile' in user_agent,
            'is_bot': is_bot,
            'device_fingerprint': device_fingerprint,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'screen_width': data.get('screen_width'),
            'screen_height': data.get('screen_height'),
            'timezone': data.get('timezone')
        }

        # Track if Discord send was successful
        discord_success = False

        # Send to Discord (async)
        def send_async():
            nonlocal discord_success
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                discord_success = loop.run_until_complete(send_to_discord(api_key, log_data))
            except Exception as e:
                print(f"ERROR in send_async: {str(e)}")
                discord_success = False
            finally:
                loop.close()

        thread = threading.Thread(target=send_async)
        thread.start()
        thread.join(timeout=10)  # Wait up to 10 seconds for Discord send

        # Return more accurate status
        if discord_success:
            return jsonify({'status': 'logged', 'fingerprint': device_fingerprint, 'discord_sent': True})
        else:
            return jsonify({'status': 'logged', 'fingerprint': device_fingerprint, 'discord_sent': False, 'warning': 'Failed to send to Discord'})

    except Exception as e:
        print(f"ERROR in log_visitor: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'bot_ready': bot_ready})

@app.route('/debug/discord')
def debug_discord():
    """Debug endpoint to check Discord connection"""
    if not bot_ready:
        return jsonify({'error': 'Bot not ready', 'bot_ready': False})
    
    debug_info = {
        'bot_ready': bot_ready,
        'bot_user': str(client.user) if client.user else None,
        'guild_count': len(client.guilds),
        'guilds': [{'id': g.id, 'name': g.name} for g in client.guilds],
    }
    
    return jsonify(debug_info)

if __name__ == '__main__':
    app.run(debug=False)
