from flask import Flask, render_template, jsonify, send_file, request, redirect, url_for
import subprocess
import threading
import time
import logging
from datetime import datetime
import signal
import queue
import os
import json
# Cấu hình logging
logging.basicConfig(
    filename='ids_web.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Biến global để theo dõi trạng thái
snort_process = None
is_monitoring = False
output_queue = queue.Queue()
snort_output = []

def read_output(pipe, queue):
    """Đọc output từ pipe và đưa vào queue"""
    try:
        for line in iter(pipe.readline, b''):
            queue.put(line.decode('utf-8').strip())
    finally:
        pipe.close()

def start_snort():
    """Khởi động Snort3 với plugin ml_classifier"""
    try:
        global snort_process
        # Sử dụng sudo với -S để đọc password từ stdin nếu cần
        snort_cmd = [
            "sudo", 
            "snort",
            "-c", "/usr/local/etc/snort/snort.lua",
            "--daq", "afpacket", "--daq-mode", "inline", "-A", "alert_fast", "-k", "none", 
            "--plugin-path", "/usr/local/snort/lib/extra/inspectors/",
            "-i", "ens33",
              # Output to console for capture
        ]
        
        # Tạo process với pipe để capture output
        snort_process = subprocess.Popen(
            snort_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid  # Tạo process group mới
        )

        # Start threads để đọc output
        threading.Thread(target=read_output, 
                       args=(snort_process.stdout, output_queue), 
                       daemon=True).start()
        threading.Thread(target=read_output, 
                       args=(snort_process.stderr, output_queue), 
                       daemon=True).start()

        logger.info("Snort started successfully")
        return True
    except Exception as e:
        logger.error(f"Error starting Snort: {str(e)}")
        return False

def stop_snort():
    """Dừng Snort3 và toàn bộ process group"""
    global snort_process
    if snort_process:
        try:
            # Kill toàn bộ process group
            os.killpg(os.getpgid(snort_process.pid), signal.SIGTERM)
            # Đợi process kết thúc với timeout
            snort_process.wait(timeout=5)
            snort_process = None
            logger.info("Snort stopped successfully")
        except subprocess.TimeoutExpired:
            # Nếu timeout, force kill
            os.killpg(os.getpgid(snort_process.pid), signal.SIGKILL)
            snort_process.wait()
            snort_process = None
            logger.warning("Snort force killed")
        except Exception as e:
            logger.error(f"Error stopping Snort: {str(e)}")

def get_latest_output():
    """Lấy output mới nhất từ queue"""
    latest_output = []
    while not output_queue.empty():
        try:
            line = output_queue.get_nowait()
            latest_output.append(line)
            snort_output.append(line)
            # Giới hạn số lượng line lưu trữ
            if len(snort_output) > 1000:
                snort_output.pop(0)
        except queue.Empty:
            break
    return latest_output

@app.route('/')
def home():
    """Trang chủ với nút Start/Stop"""
    return render_template('index.html', is_monitoring=is_monitoring)

@app.route('/start', methods=['POST'])
def start_monitoring():
    """Bắt đầu monitoring"""
    global is_monitoring
    try:
        if not is_monitoring:
            if start_snort():
                is_monitoring = True
                return jsonify({
                    'status': 'success',
                    'message': 'Monitoring started'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to start Snort'
                })
        return jsonify({
            'status': 'warning',
            'message': 'Already monitoring'
        })
    except Exception as e:
        logger.error(f"Error in start_monitoring: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/stop', methods=['POST'])
def stop_monitoring():
    """Dừng monitoring"""
    global is_monitoring
    try:
        if is_monitoring:
            stop_snort()
            is_monitoring = False
            return jsonify({
                'status': 'success',
                'message': 'Monitoring stopped'
            })
        return jsonify({
            'status': 'warning',
            'message': 'Not monitoring'
        })
    except Exception as e:
        logger.error(f"Error in stop_monitoring: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/notify_attack', methods=['POST'])
def notify_attack():
    """Nhận thông báo từ ids.py khi có tấn công"""
    # Cập nhật trạng thái hoặc lưu trữ thông báo nếu cần
    logger.info("Received attack notification")
    return jsonify({'status': 'success', 'message': 'Notification received'}), 200

@app.route('/status')
def get_status():
    """Trả về trạng thái và output mới nhất"""
    latest_output = get_latest_output()
    return jsonify({
        'is_monitoring': is_monitoring,
        'timestamp': datetime.now().isoformat(),
        'output': latest_output,
        'all_output': snort_output
    })
@app.route('/check_alert')
def check_alert():
    """Check alert status from file"""
    try:
        with open('/home/hieupham/Desktop/FlaskIDS/alert_status.json', 'r') as alert_file:
            alert_status = json.load(alert_file)
            return jsonify(alert_status)
    except FileNotFoundError:
        return jsonify({'alert': False})
    except Exception as e:
        logger.error(f"Error reading alert status: {str(e)}")
        return jsonify({'alert': False})

@app.route('/open_attack_folder', methods=['POST'])
def open_attack_folder():
    """Attempt to open the attack data folder on the server."""
    try:
        folder_path = '/home/hieupham/Desktop/FlaskIDS/predicted_attack'
        # Use a system command to open the folder (this is platform-dependent)
        subprocess.Popen(['xdg-open', folder_path])  # For Linux
        # subprocess.Popen(['open', folder_path])  # For macOS
        # subprocess.Popen(['explorer', folder_path])  # For Windows
        logger.info("Opened folder: " + folder_path)
        return jsonify({'status': 'success', 'message': 'Folder opened'})
    except Exception as e:
        logger.error(f"Error opening folder: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})



@app.route('/reset_alert', methods=['POST'])
def reset_alert():
    """Reset the alert status to False."""
    try:
        alert_status_path = '/home/hieupham/Desktop/FlaskIDS/alert_status.json'
        with open(alert_status_path, 'w') as alert_file:
            json.dump({'alert': False}, alert_file)
        logger.info("Alert status reset to False")
        return jsonify({'status': 'success', 'message': 'Alert status reset'})
    except Exception as e:
        logger.error(f"Error resetting alert status: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/edit_rules', methods=['GET', 'POST'])
def edit_rules():
    rules_file_path = '/usr/local/etc/rules/local.rules'
    if request.method == 'POST':
        # Save the edited rules
        new_rules = request.form['rules']
        with open(rules_file_path, 'w') as rules_file:
            rules_file.write(new_rules)
        return redirect(url_for('edit_rules'))

    # Read the current rules
    if os.path.exists(rules_file_path):
        with open(rules_file_path, 'r') as rules_file:
            current_rules = rules_file.read()
    else:
        current_rules = ""

    return render_template('edit_rules.html', rules=current_rules)

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        logger.critical(f"Failed to start server: {str(e)}")