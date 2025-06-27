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
from concurrent.futures import ThreadPoolExecutor
import logging

app = Flask(__name__)
CORS(app)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
intents.guilds = True
intents.guild_messages = True
client = discord.Client(intents=intents)

# Global variables
bot_ready = False
discord_loop = None
executor = ThreadPoolExecutor(max_workers=5)

@client.event
async def on_ready():
    global bot_ready
    bot_ready = True
    logger.info(f'Discord bot logged in as {client.user}')
    logger.info(f'Bot is in {len(client.guilds)} guilds')

def run_discord_bot():
    """Run Discord bot in a separate thread with proper event loop"""
    global discord_loop
    discord_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(discord_loop)
    
    try:
        discord_loop.run_until_complete(client.start(DISCORD_TOKEN))
    except Exception as e:
        logger.error(f"Discord bot error: {e}")
    finally:
        discord_loop.close()

# Start Discord bot in background thread
bot_thread = threading.Thread(target=run_discord_bot, daemon=True)
bot_thread.start()

# Wait for bot to be ready
def wait_for_bot_ready(timeout=30):
    """Wait for bot to be ready with timeout"""
    start_time = time.time()
    while not bot_ready and (time.time() - start_time) < timeout:
        time.sleep(0.5)
    return bot_ready

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
        logger.error(f"Geolocation error: {e}")
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

async def send_discord_embed(api_key, log_data):
    """Send log data to Discord channel - improved version"""
    try:
        if not bot_ready:
            logger.warning("Bot not ready yet")
            return False, "Bot not ready"

        key_info = API_KEYS[api_key]
        guild_id = int(key_info['discord_server_id'])
        channel_id = int(key_info['discord_log_channel_id'])

        logger.info(f"Attempting to send to guild: {guild_id}, channel: {channel_id}")

        # Get guild
        guild = client.get_guild(guild_id)
        if not guild:
            error_msg = f"Cannot access guild {guild_id}. Bot may not be in this server."
            logger.error(error_msg)
            return False, error_msg

        # Get channel
        channel = client.get_channel(channel_id)
        if not channel:
            error_msg = f"Cannot access channel {channel_id}. Channel may not exist or bot lacks permissions."
            logger.error(error_msg)
            return False, error_msg

        logger.info(f"Found guild: {guild.name}, channel: {channel.name}")

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

        # Send the embed
        await channel.send(embed=embed)
        logger.info("Successfully sent embed to Discord")
        return True, "Success"

    except discord.Forbidden:
        error_msg = "Bot lacks permissions to send messages in this channel"
        logger.error(error_msg)
        return False, error_msg
    except discord.HTTPException as e:
        error_msg = f"Discord HTTP error: {str(e)}"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error sending to Discord: {str(e)}"
        logger.error(error_msg)
        return False, error_msg

def send_to_discord_sync(api_key, log_data):
    """Synchronous wrapper for Discord sending"""
    if not bot_ready:
        return False, "Bot not ready"
    
    if not discord_loop:
        return False, "Discord event loop not available"
    
    try:
        # Use asyncio.run_coroutine_threadsafe to run coroutine in the Discord event loop
        future = asyncio.run_coroutine_threadsafe(
            send_discord_embed(api_key, log_data), 
            discord_loop
        )
        # Wait for result with timeout
        success, message = future.result(timeout=10)
        return success, message
    except asyncio.TimeoutError:
        return False, "Timeout waiting for Discord response"
    except Exception as e:
        return False, f"Error in sync wrapper: {str(e)}"

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

        # Add user_agent to data for fingerprint generation
        data['user_agent'] = user_agent
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

        logger.info(f"Processing visitor log for API key: {api_key}")
        logger.info(f"Visitor data: IP={visitor_ip}, Browser={browser}, OS={os_info}")

        # Send to Discord synchronously to get immediate result
        discord_success = False
        discord_message = "Not attempted"
        
        if bot_ready:
            try:
                discord_success, discord_message = send_to_discord_sync(api_key, log_data)
                logger.info(f"Discord send result: {discord_success} - {discord_message}")
            except Exception as e:
                discord_message = f"Error: {str(e)}"
                logger.error(f"Discord send error: {e}")
        else:
            discord_message = "Bot not ready"

        return jsonify({
            'status': 'logged',
            'fingerprint': device_fingerprint,
            'bot_ready': bot_ready,
            'discord_sent': discord_success,
            'discord_status': discord_message,
            'processed_data': {
                'ip': visitor_ip,
                'location': f"{geolocation['city']}, {geolocation['country']}",
                'browser': browser,
                'os': os_info
            }
        })

    except Exception as e:
        logger.error(f"ERROR in log_visitor: {str(e)}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'bot_ready': bot_ready,
        'bot_user': str(client.user) if client.user else None,
        'guilds_count': len(client.guilds) if bot_ready else 0,
        'guilds': [{'id': g.id, 'name': g.name} for g in client.guilds] if bot_ready else []
    })

@app.route('/debug/<api_key>')
def debug_info(api_key):
    """Debug endpoint to check API key configuration"""
    if api_key not in API_KEYS:
        return jsonify({'error': 'Invalid API key'}), 401

    key_info = API_KEYS[api_key]
    guild_id = int(key_info['discord_server_id'])
    channel_id = int(key_info['discord_log_channel_id'])

    guild = client.get_guild(guild_id) if bot_ready else None
    channel = client.get_channel(channel_id) if bot_ready else None

    # Test Discord connection
    discord_test_result = "Not tested"
    if bot_ready and guild and channel:
        try:
            # Create a simple test log
            test_log = {
                'url': 'https://test.com',
                'ip': '127.0.0.1',
                'geolocation': {'city': 'Test', 'region': 'Test', 'country': 'Test', 'isp': 'Test', 'proxy': False, 'mobile': False},
                'browser': 'Test Browser',
                'os': 'Test OS',
                'user_agent': 'Test Agent',
                'referrer': '',
                'is_mobile': False,
                'is_bot': False,
                'device_fingerprint': 'test123',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'screen_width': 1920,
                'screen_height': 1080,
                'timezone': 'UTC'
            }
            
            success, message = send_to_discord_sync(api_key, test_log)
            discord_test_result = f"{'Success' if success else 'Failed'}: {message}"
        except Exception as e:
            discord_test_result = f"Test failed: {str(e)}"

    return jsonify({
        'api_key': api_key,
        'bot_ready': bot_ready,
        'bot_user': str(client.user) if client.user else None,
        'guild_found': guild is not None,
        'guild_name': guild.name if guild else None,
        'guild_id': guild_id,
        'channel_found': channel is not None,
        'channel_name': channel.name if channel else None,
        'channel_id': channel_id,
        'registered_url': key_info['url'],
        'bot_permissions': channel.permissions_for(guild.me).send_messages if (guild and channel) else None,
        'discord_test': discord_test_result
    })

if __name__ == '__main__':
    # Wait for bot to be ready before starting Flask
    logger.info("Waiting for Discord bot to be ready...")
    if wait_for_bot_ready(30):
        logger.info("Bot is ready! Starting Flask app...")
    else:
        logger.warning("Bot not ready after 30 seconds, starting Flask anyway...")
    
    app.run(debug=False, host='0.0.0.0', port=5000)
