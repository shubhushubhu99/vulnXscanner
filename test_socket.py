import socketio
import time

sio = socketio.Client()

@sio.event
def connect():
    print("Connected")
    sio.emit('start_scan', {'target': '127.0.0.1', 'deep_scan': False})

@sio.on('scan_complete')
def on_scan_complete(data):
    print("Scan complete:", data)

@sio.on('cve_results')
def on_cve_results(data):
    print("CVE results:", data)

sio.connect('http://127.0.0.1:5000')
time.sleep(15)
sio.disconnect()
