from flask import Flask, request, jsonify
from flask_cors import CORS
from flask import Flask, request, jsonify, render_template
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
from queue import Queue
import traceback

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

# Discord client setup with better intents
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.guild_messages = True
client = discord.Client(intents=intents)

# Global variables with better initialization
bot_ready = False
discord_loop = None
executor = ThreadPoolExecutor(max_workers=10)  # Increased workers
app_start_time = datetime.now()
last_activity = datetime.now()
keep_alive_active = True
bot_restart_count = 0
last_successful_discord_send = datetime.now()

# Message queue for Discord (fallback mechanism)
discord_message_queue = Queue()
queue_processing_active = True

# Keep-alive configuration
KEEP_ALIVE_INTERVAL = 180  # 3 minutes (reduced from 5)
SELF_PING_URL = os.environ.get('SELF_PING_URL')

# Health check intervals
HEALTH_CHECK_INTERVAL = 30  # 30 seconds
BOT_HEALTH_TIMEOUT = 120  # 2 minutes max for bot recovery

def update_last_activity():
    """Update the last activity timestamp"""
    global last_activity
    last_activity = datetime.now()

@client.event
async def on_ready():
    global bot_ready, last_successful_discord_send
    bot_ready = True
    last_successful_discord_send = datetime.now()
    logger.info(f'Discord bot logged in as {client.user}')
    logger.info(f'Bot is in {len(client.guilds)} guilds')
    update_last_activity()
    
    # Process any queued messages
    await process_queued_messages()

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
    global bot_ready, last_successful_discord_send
    bot_ready = True
    last_successful_discord_send = datetime.now()
    logger.info('Discord bot resumed connection')
    update_last_activity()

async def process_queued_messages():
    """Process any messages that were queued while bot was offline"""
    processed = 0
    while not discord_message_queue.empty() and processed < 10:  # Limit to prevent spam
        try:
            api_key, log_data = discord_message_queue.get_nowait()
            success, message = await send_discord_embed(api_key, log_data)
            if success:
                logger.info(f"Processed queued message: {message}")
            processed += 1
        except Exception as e:
            logger.error(f"Error processing queued message: {e}")
            break

def run_discord_bot():
    """Run Discord bot with improved error handling and faster recovery"""
    global discord_loop, bot_ready, bot_restart_count
    
    max_restarts = 10
    base_wait_time = 5  # Start with 5 seconds
    
    while keep_alive_active and bot_restart_count < max_restarts:
        try:
            discord_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(discord_loop)
            
            logger.info(f"Starting Discord bot (attempt {bot_restart_count + 1})...")
            discord_loop.run_until_complete(client.start(DISCORD_TOKEN))
            
        except discord.LoginFailure:
            logger.error("Discord login failed - invalid token")
            break
        except Exception as e:
            logger.error(f"Discord bot error: {e}")
            bot_ready = False
            bot_restart_count += 1
            
            if keep_alive_active and bot_restart_count < max_restarts:
                wait_time = min(base_wait_time * (1.5 ** bot_restart_count), 30)  # Cap at 30 seconds
                logger.info(f"Attempting to reconnect Discord bot in {wait_time:.1f} seconds...")
                time.sleep(wait_time)
        finally:
            if discord_loop and not discord_loop.is_closed():
                discord_loop.close()
            discord_loop = None

def keep_alive_worker():
    """Improved keep-alive worker with health monitoring"""
    global keep_alive_active, bot_ready, bot_restart_count
    
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
            
            # Check bot health and restart if needed
            if not bot_ready:
                time_since_last_success = (datetime.now() - last_successful_discord_send).total_seconds()
                if time_since_last_success > BOT_HEALTH_TIMEOUT:
                    logger.warning(f"Bot offline for {time_since_last_success:.0f}s, attempting restart...")
                    restart_discord_bot()
                    
        except Exception as e:
            logger.error(f"Keep-alive worker error: {e}")

def restart_discord_bot():
    """Restart Discord bot if it's been offline too long"""
    global bot_restart_count
    
    if bot_restart_count < 5:  # Don't restart too many times
        logger.info("Triggering Discord bot restart...")
        bot_restart_count += 1
        
        # Start new bot thread
        bot_thread = threading.Thread(target=run_discord_bot, daemon=True)
        bot_thread.start()

def health_monitor():
    """Monitor system health and take corrective actions"""
    while keep_alive_active:
        try:
            time.sleep(HEALTH_CHECK_INTERVAL)
            
            current_time = datetime.now()
            
            # Check if bot has been offline too long
            if not bot_ready:
                time_offline = (current_time - last_successful_discord_send).total_seconds()
                if time_offline > BOT_HEALTH_TIMEOUT:
                    logger.warning(f"Bot offline for {time_offline:.0f}s - health monitor triggered restart")
                    restart_discord_bot()
            
            # Reset restart count if bot has been stable
            if bot_ready and bot_restart_count > 0:
                stable_time = (current_time - last_successful_discord_send).total_seconds()
                if stable_time > 300:  # 5 minutes stable
                    bot_restart_count = max(0, bot_restart_count - 1)
                    
        except Exception as e:
            logger.error(f"Health monitor error: {e}")

# Start Discord bot in background thread
bot_thread = threading.Thread(target=run_discord_bot, daemon=True)
bot_thread.start()

# Start keep-alive worker
if SELF_PING_URL:
    keep_alive_thread = threading.Thread(target=keep_alive_worker, daemon=True)
    keep_alive_thread.start()
    logger.info(f"Keep-alive service started with URL: {SELF_PING_URL}")

# Start health monitor
health_thread = threading.Thread(target=health_monitor, daemon=True)
health_thread.start()
logger.info("Health monitor started")

def wait_for_bot_ready(timeout=30):
    """Wait for bot to be ready with shorter timeout"""
    start_time = time.time()
    while not bot_ready and (time.time() - start_time) < timeout:
        time.sleep(0.5)  # Check every 0.5 seconds for faster response
        if int(time.time() - start_time) % 5 == 0:  # Log every 5 seconds
            logger.info(f"Waiting for Discord bot... ({int(time.time() - start_time)}s)")
    return bot_ready

def graceful_shutdown(signum, frame):
    """Handle graceful shutdown"""
    global keep_alive_active, queue_processing_active
    logger.info("Received shutdown signal, cleaning up...")
    keep_alive_active = False
    queue_processing_active = False
    
    if client and not client.is_closed():
        if discord_loop:
            asyncio.run_coroutine_threadsafe(client.close(), discord_loop)
    
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

def get_geolocation(ip):
    """Get geolocation data from IP with improved retry logic"""
    max_retries = 2  # Reduced retries for faster response
    timeout = 5  # Reduced timeout
    
    for attempt in range(max_retries):
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=timeout)
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
                time.sleep(1)  # Shorter wait between retries
    
    # Return default data if all attempts fail
    return {
        'country': 'Unknown', 
        'region': 'Unknown', 
        'city': 'Unknown', 
        'isp': 'Unknown', 
        'proxy': False,
        'mobile': False
    }

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
    """Send log data to Discord channel with improved error handling"""
    max_retries = 2  # Reduced retries for faster response
    
    for attempt in range(max_retries):
        try:
            if not bot_ready:
                raise Exception("Bot not ready")
            
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
            
            global last_successful_discord_send
            last_successful_discord_send = datetime.now()
            
            return True, "Success"
            
        except discord.Forbidden:
            error_msg = "Bot lacks permissions to send messages in this channel"
            logger.error(error_msg)
            return False, error_msg
        except discord.HTTPException as e:
            if attempt < max_retries - 1:
                logger.warning(f"Discord HTTP error (attempt {attempt + 1}): {str(e)}, retrying...")
                await asyncio.sleep(1)  # Shorter retry delay
                continue
            error_msg = f"Discord HTTP error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Discord error (attempt {attempt + 1}): {str(e)}, retrying...")
                await asyncio.sleep(1)  # Shorter retry delay
                continue
            error_msg = f"Error sending to Discord: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    return False, "Failed after all retry attempts"

def send_to_discord_sync(api_key, log_data):
    """Synchronous wrapper for Discord sending with queue fallback"""
    if not discord_loop or not bot_ready:
        # Queue the message for later processing
        if queue_processing_active:
            try:
                discord_message_queue.put((api_key, log_data), timeout=1)
                logger.info("Message queued for Discord (bot not ready)")
                return True, "Queued for later delivery"
            except:
                pass
        return False, "Discord bot not available"
    
    try:
        future = asyncio.run_coroutine_threadsafe(
            send_discord_embed(api_key, log_data),
            discord_loop
        )
        success, message = future.result(timeout=15)  # Reduced timeout
        return success, message
    except asyncio.TimeoutError:
        # Queue message on timeout
        if queue_processing_active:
            try:
                discord_message_queue.put((api_key, log_data), timeout=1)
                return True, "Queued due to timeout"
            except:
                pass
        return False, "Timeout waiting for Discord response"
    except Exception as e:
        logger.error(f"Error in sync wrapper: {str(e)}")
        return False, f"Error in sync wrapper: {str(e)}"

@app.before_request
def before_request():
    """Update activity before each request"""
    update_last_activity()

@app.route('/')
def api_status():
    """API Status page with improved information"""
    try:
        current_time = datetime.now()
        uptime = current_time - app_start_time
        time_since_activity = current_time - last_activity
        
        # Determine system status
        is_cold_start = uptime.total_seconds() < 60  # Less than 1 minute uptime
        
        total_keys = len(API_KEYS)
        
        # Bot status with more granular information
        if bot_ready:
            bot_status = "online"
        elif is_cold_start:
            bot_status = "initializing"
        else:
            bot_status = "reconnecting"
        
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
        
        # System status
        if bot_ready and accessible_configs == total_keys:
            system_status = "operational"
            status_message = "All systems operational"
        elif bot_ready and accessible_configs > 0:
            system_status = "partial_outage"
            status_message = "Some configurations unavailable"
        elif is_cold_start:
            system_status = "starting"
            status_message = "Service initializing"
        else:
            system_status = "degraded"
            status_message = "Discord service reconnecting"
        
        return jsonify({
            "service_name": "Website Analytics API",
            "version": "1.2",
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
                    "connected_servers": len(client.guilds) if bot_ready else 0,
                    "restart_count": bot_restart_count,
                    "queued_messages": discord_message_queue.qsize()
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
                "success_rate": f"{(accessible_configs / total_keys * 100):.1f}%" if total_keys > 0 else "0%"
            },
            "performance": {
                "bot_ready": bot_ready,
                "response_time_estimate": "< 1s" if not is_cold_start else "2-5s (initializing)",
                "queue_size": discord_message_queue.qsize()
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
    """Main API endpoint with guaranteed response"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})
    
    update_last_activity()
    
    try:
        # NEVER return an error - always process the request
        data = request.get_json() or {}
        
        if api_key not in API_KEYS:
            logger.warning(f"Invalid API key attempted: {api_key}")
            # Still return success to prevent client-side errors
            return jsonify({
                'status': 'logged',
                'warning': 'Invalid API key',
                'bot_ready': bot_ready,
                'discord_sent': False,
                'discord_status': 'Invalid API key'
            })
        
        requested_url = data.get('url', 'Unknown')
        if not is_valid_url_for_key(api_key, requested_url):
            logger.warning(f"Unauthorized URL for API key {api_key}: {requested_url}")
            # Still process but mark as unauthorized
            
        # Get visitor data
        visitor_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if visitor_ip and ',' in visitor_ip:
            visitor_ip = visitor_ip.split(',')[0].strip()
        
        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')
        
        # Parse data with fallbacks to prevent delays
        try:
            geolocation = get_geolocation(visitor_ip)
        except Exception as e:
            logger.warning(f"Geolocation failed: {e}")
            geolocation = {'country': 'Unknown', 'region': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'proxy': False, 'mobile': False}
        
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
        
        # Always attempt to send to Discord, but never let it block the response
        discord_success = False
        discord_message = "Not attempted"
        
        try:
            discord_success, discord_message = send_to_discord_sync(api_key, log_data)
        except Exception as e:
            discord_message = f"Error: {str(e)}"
            logger.error(f"Discord send error: {e}")
        
        # ALWAYS return success
        return jsonify({
            'status': 'logged',
            'fingerprint': device_fingerprint,
            'bot_ready': bot_ready,
            'discord_sent': discord_success,
            'discord_status': discord_message,
            'cold_start': (datetime.now() - app_start_time).total_seconds() < 60,
            'processed_data': {
                'ip': visitor_ip,
                'location': f"{geolocation['city']}, {geolocation['country']}",
                'browser': browser,
                'os': os_info
            },
            'queue_size': discord_message_queue.qsize(),
            'uptime': int((datetime.now() - app_start_time).total_seconds())
        })
        
    except Exception as e:
        logger.error(f"ERROR in log_visitor: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Even on error, return success to prevent client issues
        return jsonify({
            'status': 'logged',
            'warning': 'Processing error occurred',
            'bot_ready': bot_ready,
            'discord_sent': False,
            'discord_status': f'Error: {str(e)}',
            'error_details': str(e)
        })

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
        'last_activity': (current_time - last_activity).total_seconds(),
        'restart_count': bot_restart_count,
        'queue_size': discord_message_queue.qsize()
    })

@app.route('/ping')
def ping():
    """Simple ping endpoint for keep-alive"""
    update_last_activity()
    return jsonify({
        'pong': True, 
        'timestamp': datetime.now().isoformat(),
        'bot_ready': bot_ready,
        'uptime': int((datetime.now() - app_start_time).total_seconds())
    })

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
            'cold_start_window': uptime.total_seconds() < 60,
            'restart_count': bot_restart_count,
            'queue_size': discord_message_queue.qsize()
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

@app.route('/api-doc')
def api_documentation():
    """API Documentation Page"""
    try:
        return render_template('doc-api.html')
    except Exception as e:
        logger.error(f"Error loading API documentation: {str(e)}")
        return jsonify({
            "error": f"Error loading documentation: {str(e)}",
            "status": "server_error",
            "message": "API documentation is temporarily unavailable"
        }), 500

@app.route('/force-restart-bot')
def force_restart_bot():
    """Emergency endpoint to force restart Discord bot"""
    global bot_restart_count, bot_ready
    
    logger.info("Force restart requested")
    bot_ready = False
    restart_discord_bot()
    
    return jsonify({
        'status': 'restart_initiated',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'restart_count': bot_restart_count
    })

@app.route('/queue-status')
def queue_status():
    """Check Discord message queue status"""
    return jsonify({
        'queue_size': discord_message_queue.qsize(),
        'bot_ready': bot_ready,
        'queue_processing_active': queue_processing_active,
        'last_successful_send': last_successful_discord_send.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'time_since_last_success': (datetime.now() - last_successful_discord_send).total_seconds()
    })

if __name__ == '__main__':
    logger.info("Starting Website Analytics API v1.2...")
    logger.info("Key improvements: Queue system, faster recovery, guaranteed response")
    
    # Don't wait for bot on startup - let it initialize in background
    logger.info("Starting Flask app immediately (bot will initialize in background)")
    
    app.run(debug=False, host='0.0.0.0', port=5000)
