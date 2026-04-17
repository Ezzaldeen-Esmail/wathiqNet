from app import create_app, socketio, db
import os

app = create_app()

# Initialize capture instances
log_watcher = None
packet_capture = None

def init_monitoring():
    """Initialize log watcher and packet capture"""
    global log_watcher, packet_capture
    
    try:
        from app.utils.log_watcher import init_log_watcher, get_log_watcher
        from app.utils.packet_capture import init_packet_capture, get_packet_capture
        from app.detection.engine import DetectionEngine
        
        # Only initialize once
        if get_log_watcher() is None:
            detection_engine = DetectionEngine()
            
            # Initialize log watcher
            log_watcher = init_log_watcher(app, socketio, detection_engine)
            watch_folder = app.config.get('WATCH_FOLDER')
            if watch_folder:
                log_watcher.start([watch_folder])
                print(f"[LogWatcher] Started monitoring: {watch_folder}")
        
        if get_packet_capture() is None:
            detection_engine = DetectionEngine()
            packet_capture = init_packet_capture(app, socketio, detection_engine)
            print("[PacketCapture] Initialized (use Admin panel to start)")
            
    except Exception as e:
        print(f"[Monitoring] Error during initialization: {e}")

if __name__ == '__main__':
    print("=" * 60)
    print("WathiqNet - Network Intrusion Detection System")
    print("=" * 60)
    print("Starting server...")
    print("Access the application at: http://localhost:5000")
    print("Default admin credentials:")
    print("  Username: admin")
    print("  Password: admin123")
    print("=" * 60)
    
    watch_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'watch')
    print(f"\n[Real-Time Monitoring]")
    print(f"  Log Watcher: Drop files into {watch_folder}")
    print(f"  Packet Capture: Start via Admin → Network Capture")
    print(f"  Supported log formats: .csv, .json, .log")
    print("=" * 60)
    
    # Initialize monitoring on first WebSocket connection
    @socketio.on('connect')
    def handle_connect():
        init_monitoring()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)