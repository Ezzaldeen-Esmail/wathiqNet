from app import create_app, socketio

app = create_app()

if __name__ == '__main__':
    print("=" * 60)
    print("NIDS - Network Intrusion Detection System")
    print("=" * 60)
    print("Starting server...")
    print("Access the application at: http://localhost:5000")
    print("Default admin credentials:")
    print("  Username: admin")
    print("  Password: admin123")
    print("=" * 60)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)


    