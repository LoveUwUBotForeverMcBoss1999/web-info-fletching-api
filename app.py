from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
import discord
import asyncio
import threading
import time
from datetime import datetime, timedelta
import requests
import re
from urllib.parse import urlparse
import hashlib
from concurrent.futures import ThreadPoolExecutor
import logging
import signal
import sys

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
app_start_time = datetime.now()
last_activity = datetime.now()
keep_alive_active = True

# Keep-alive configuration
KEEP_ALIVE_INTERVAL = 300  # 5 minutes
SELF_PING_URL = os.environ.get('SELF_PING_URL')  # Set this to your app's URL


def update_last_activity():
    """Update the last activity timestamp"""
    global last_activity
    last_activity = datetime.now()


@client.event
async def on_ready():
    global bot_ready
    bot_ready = True
    logger.info(f'Discord bot logged in as {client.user}')
    logger.info(f'Bot is in {len(client.guilds)} guilds')
    update_last_activity()


@client.event
async def on_disconnect():
    global bot_ready
    bot_ready = False
    logger.warning('Discord bot disconnected')


@client.event
async def on_connect():
    logger.info('Discord bot connected')


@client.event
async def on_resumed():
    global bot_ready
    bot_ready = True
    logger.info('Discord bot resumed connection')
    update_last_activity()


def run_discord_bot():
    """Run Discord bot in a separate thread with proper event loop and reconnection"""
    global discord_loop, bot_ready
    
    while keep_alive_active:  # Allow for reconnection attempts
        try:
            discord_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(discord_loop)
            
            logger.info("Starting Discord bot...")
            discord_loop.run_until_complete(client.start(DISCORD_TOKEN))
            
        except discord.LoginFailure:
            logger.error("Discord login failed - invalid token")
            break
        except Exception as e:
            logger.error(f"Discord bot error: {e}")
            bot_ready = False
            
            if keep_alive_active:
                logger.info("Attempting to reconnect Discord bot in 10 seconds...")
                time.sleep(10)
        finally:
            if discord_loop and not discord_loop.is_closed():
                discord_loop.close()
            discord_loop = None


def keep_alive_worker():
    """Keep-alive worker to prevent the app from sleeping"""
    global keep_alive_active
    
    while keep_alive_active:
        try:
            time.sleep(KEEP_ALIVE_INTERVAL)
            
            if not keep_alive_active:
                break
                
            # Self-ping to keep the app alive
            if SELF_PING_URL:
                try:
                    response = requests.get(f"{SELF_PING_URL}/health", timeout=10)
                    logger.info(f"Keep-alive ping: {response.status_code}")
                except Exception as e:
                    logger.warning(f"Keep-alive ping failed: {e}")
            
            # Check if Discord bot needs reconnection
            if not bot_ready and keep_alive_active:
                logger.warning("Discord bot not ready, may need reconnection")
                
        except Exception as e:
            logger.error(f"Keep-alive worker error: {e}")


# Start Discord bot in background thread
bot_thread = threading.Thread(target=run_discord_bot, daemon=True)
bot_thread.start()

# Start keep-alive worker
if SELF_PING_URL:
    keep_alive_thread = threading.Thread(target=keep_alive_worker, daemon=True)
    keep_alive_thread.start()
    logger.info(f"Keep-alive service started with URL: {SELF_PING_URL}")


def wait_for_bot_ready(timeout=60):
    """Wait for bot to be ready with longer timeout for cold starts"""
    start_time = time.time()
    while not bot_ready and (time.time() - start_time) < timeout:
        time.sleep(1)  # Check every second
        if (time.time() - start_time) % 10 == 0:  # Log every 10 seconds
            logger.info(f"Waiting for Discord bot... ({int(time.time() - start_time)}s)")
    return bot_ready


def graceful_shutdown(signum, frame):
    """Handle graceful shutdown"""
    global keep_alive_active
    logger.info("Received shutdown signal, cleaning up...")
    keep_alive_active = False
    
    if client and not client.is_closed():
        asyncio.run_coroutine_threadsafe(client.close(), discord_loop)
    
    sys.exit(0)


# Register signal handlers
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)


def get_geolocation(ip):
    """Get geolocation data from IP with retry logic"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
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
            logger.warning(f"Geolocation attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
    
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

    return (parsed_registered.scheme == parsed_requested.scheme and
            parsed_registered.netloc == parsed_requested.netloc)


async def send_discord_embed(api_key, log_data):
    """Send log data to Discord channel with retry logic"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            if not bot_ready:
                if attempt == 0:
                    logger.warning("Bot not ready, waiting...")
                    # Give bot more time to initialize on first attempt
                    await asyncio.sleep(5)
                    if not bot_ready:
                        raise Exception("Bot still not ready after waiting")

            key_info = API_KEYS[api_key]
            guild_id = int(key_info['discord_server_id'])
            channel_id = int(key_info['discord_log_channel_id'])

            guild = client.get_guild(guild_id)
            if not guild:
                raise Exception(f"Cannot access guild {guild_id}")

            channel = client.get_channel(channel_id)
            if not channel:
                raise Exception(f"Cannot access channel {channel_id}")

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

            await channel.send(embed=embed)
            logger.info("Successfully sent embed to Discord")
            return True, "Success"

        except discord.Forbidden:
            error_msg = "Bot lacks permissions to send messages in this channel"
            logger.error(error_msg)
            return False, error_msg
        except discord.HTTPException as e:
            if attempt < max_retries - 1:
                logger.warning(f"Discord HTTP error (attempt {attempt + 1}): {str(e)}, retrying...")
                await asyncio.sleep(2 ** attempt)
                continue
            error_msg = f"Discord HTTP error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Discord error (attempt {attempt + 1}): {str(e)}, retrying...")
                await asyncio.sleep(2 ** attempt)
                continue
            error_msg = f"Error sending to Discord: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
            
    return False, "Failed after all retry attempts"


def send_to_discord_sync(api_key, log_data):
    """Synchronous wrapper for Discord sending with better error handling"""
    if not discord_loop:
        return False, "Discord event loop not available"

    try:
        future = asyncio.run_coroutine_threadsafe(
            send_discord_embed(api_key, log_data),
            discord_loop
        )
        success, message = future.result(timeout=30)  # Increased timeout
        return success, message
    except asyncio.TimeoutError:
        return False, "Timeout waiting for Discord response"
    except Exception as e:
        return False, f"Error in sync wrapper: {str(e)}"


@app.before_request
def before_request():
    """Update activity before each request"""
    update_last_activity()


@app.route('/')
def api_status():
    """API Status page with cold start information"""
    try:
        current_time = datetime.now()
        uptime = current_time - app_start_time
        time_since_activity = current_time - last_activity
        
        # Determine if this might be a cold start
        is_cold_start = uptime.total_seconds() < 120  # Less than 2 minutes uptime
        
        total_keys = len(API_KEYS)
        bot_status = "online" if bot_ready else ("starting" if is_cold_start else "offline")
        
        # Check accessible configurations
        accessible_configs = 0
        for api_key, config in API_KEYS.items():
            try:
                guild_id = int(config['discord_server_id'])
                channel_id = int(config['discord_log_channel_id'])
                
                if bot_ready:
                    guild = client.get_guild(guild_id)
                    channel = client.get_channel(channel_id)
                    if guild and channel:
                        accessible_configs += 1
            except:
                continue
        
        # System status with cold start consideration
        if is_cold_start:
            system_status = "starting"
            status_message = "Service is starting up (cold start)"
        elif bot_ready and accessible_configs == total_keys:
            system_status = "operational"
            status_message = "All systems operational"
        elif bot_ready and accessible_configs > 0:
            system_status = "partial_outage"
            status_message = "Some configurations unavailable"
        else:
            system_status = "offline"
            status_message = "Discord service unavailable"
        
        return jsonify({
            "service_name": "Website Analytics API",
            "version": "1.1",
            "status": system_status,
            "message": status_message,
            "timestamp": current_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            "uptime": {
                "seconds": int(uptime.total_seconds()),
                "human_readable": f"{int(uptime.total_seconds() // 3600)}h {int((uptime.total_seconds() % 3600) // 60)}m"
            },
            "cold_start_detected": is_cold_start,
            "last_activity": time_since_activity.total_seconds(),
            "components": {
                "api_server": {
                    "status": "operational",
                    "description": "Main API server"
                },
                "discord_bot": {
                    "status": bot_status,
                    "description": "Discord notification service",
                    "connected_servers": len(client.guilds) if bot_ready else 0
                },
                "geolocation_service": {
                    "status": "operational",
                    "description": "IP geolocation lookup"
                },
                "keep_alive": {
                    "status": "active" if SELF_PING_URL else "disabled",
                    "description": "Anti-sleep mechanism"
                }
            },
            "statistics": {
                "registered_api_keys": total_keys,
                "accessible_configurations": accessible_configs,
                "success_rate": f"{(accessible_configs/total_keys*100):.1f}%" if total_keys > 0 else "0%"
            },
            "performance": {
                "bot_ready": bot_ready,
                "response_time_estimate": "< 1s" if not is_cold_start else "5-15s (cold start)"
            }
        })
        
    except Exception as e:
        logger.error(f"Error in api_status: {str(e)}")
        return jsonify({
            "service_name": "Website Analytics API",
            "status": "error",
            "message": "Unable to determine system status",
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        }), 500


@app.route('/api/key/<api_key>/', methods=['POST', 'OPTIONS'])
def log_visitor(api_key):
    """Main API endpoint with cold start handling"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})

    update_last_activity()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        if api_key not in API_KEYS:
            return jsonify({'error': 'Invalid API key'}), 401

        requested_url = data.get('url')
        if not requested_url or not is_valid_url_for_key(api_key, requested_url):
            return jsonify({'error': 'URL not authorized for this API key'}), 403

        # If bot isn't ready, wait a bit (cold start handling)
        if not bot_ready:
            logger.info("Bot not ready, waiting for initialization...")
            wait_for_bot_ready(30)  # Wait up to 30 seconds

        # Get visitor data
        visitor_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if visitor_ip and ',' in visitor_ip:
            visitor_ip = visitor_ip.split(',')[0].strip()

        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')

        # Parse data with retry logic
        geolocation = get_geolocation(visitor_ip)
        browser, os_info = parse_user_agent(user_agent)
        is_bot = is_bot_traffic(user_agent, visitor_ip)

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

        # Send to Discord with retry logic
        discord_success = False
        discord_message = "Not attempted"

        try:
            discord_success, discord_message = send_to_discord_sync(api_key, log_data)
            logger.info(f"Discord send result: {discord_success} - {discord_message}")
        except Exception as e:
            discord_message = f"Error: {str(e)}"
            logger.error(f"Discord send error: {e}")

        return jsonify({
            'status': 'logged',
            'fingerprint': device_fingerprint,
            'bot_ready': bot_ready,
            'discord_sent': discord_success,
            'discord_status': discord_message,
            'cold_start': (datetime.now() - app_start_time).total_seconds() < 120,
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
    """Enhanced health check endpoint"""
    current_time = datetime.now()
    uptime = current_time - app_start_time
    
    return jsonify({
        'status': 'healthy',
        'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'uptime_seconds': int(uptime.total_seconds()),
        'bot_ready': bot_ready,
        'bot_user': str(client.user) if client.user else None,
        'guilds_count': len(client.guilds) if bot_ready else 0,
        'keep_alive_enabled': SELF_PING_URL is not None,
        'last_activity': (current_time - last_activity).total_seconds()
    })


@app.route('/ping')
def ping():
    """Simple ping endpoint for keep-alive"""
    update_last_activity()
    return jsonify({'pong': True, 'timestamp': datetime.now().isoformat()})


@app.route('/debug/<api_key>')
def debug_info(api_key):
    """Enhanced debug endpoint"""
    if api_key not in API_KEYS:
        return jsonify({'error': 'Invalid API key'}), 401

    current_time = datetime.now()
    uptime = current_time - app_start_time
    
    key_info = API_KEYS[api_key]
    guild_id = int(key_info['discord_server_id'])
    channel_id = int(key_info['discord_log_channel_id'])

    guild = client.get_guild(guild_id) if bot_ready else None
    channel = client.get_channel(channel_id) if bot_ready else None

    return jsonify({
        'api_key': api_key,
        'system_info': {
            'uptime_seconds': int(uptime.total_seconds()),
            'bot_ready': bot_ready,
            'cold_start_window': uptime.total_seconds() < 120
        },
        'discord_info': {
            'bot_user': str(client.user) if client.user else None,
            'guild_found': guild is not None,
            'guild_name': guild.name if guild else None,
            'channel_found': channel is not None,
            'channel_name': channel.name if channel else None,
            'bot_permissions': channel.permissions_for(guild.me).send_messages if (guild and channel) else None
        },
        'configuration': {
            'registered_url': key_info['url'],
            'keep_alive_enabled': SELF_PING_URL is not None
        }
    })


if __name__ == '__main__':
    logger.info("Starting Website Analytics API...")
    logger.info("Waiting for Discord bot to initialize...")
    
    # Don't wait too long on startup to avoid timeout
    if wait_for_bot_ready(45):
        logger.info("Discord bot ready! Starting Flask app...")
    else:
        logger.warning("Starting Flask app without Discord bot ready (will retry in background)")

    app.run(debug=False, host='0.0.0.0', port=5000)
