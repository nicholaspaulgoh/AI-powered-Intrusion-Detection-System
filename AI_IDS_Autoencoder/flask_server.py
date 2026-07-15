import os
os.environ["TF_CPP_MIN_LOG_LEVEL"]="3"
os.environ["TF_ENABLE_ONEDNN_OPTS"]="0"
import joblib
import json
from flask import Flask, request, jsonify, Response, render_template
import queue
import numpy as np
import time


import tensorflow as tf
tf.get_logger().setLevel("ERROR")

#__file__ = flask_server.py
#abspath =C:\Users\Nicholas\AI_IDS\app.py
#dirname = C:\Users\Nicholas\AI_IDS
#prevents breaking if I move the folder or if in different location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH= os.path.join(BASE_DIR, "autoencoder_model.h5")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
THRESH_PATH =os.path.join(BASE_DIR, "threshold.json")

print("[Flask] Loading autoencoder model...")
autoencoder=tf.keras.models.load_model(MODEL_PATH,compile=False)
scaler=joblib.load(SCALER_PATH)

with open(THRESH_PATH, "r") as f:
    THRESHOLD=json.load(f)["threshold"]

print(f"[Flask] Model loaded. Threshold: {THRESHOLD:.6f}")
print("[Flask] Server ready.")

# =============================================================================
# SSE EVENT QUEUE
# Each detection result gets put into this queue.
# The /stream endpoint reads from it and pushes to all connected browsers.
# =============================================================================
event_queue = queue.Queue(maxsize=500)

#stats is global
stats = {
    "total": 0,
    "normal": 0,
    "DoS": 0,
    "Probe": 0,
    "R2L": 0,
    "U2R": 0,
    "unknown": 0,
    "anomalies": 0,
}

#"Create a Flask application using this Python file as the root of my project."
app=Flask(__name__)

# =============================================================================
# POST /detect #POST -> send data
# Java calls this with a JSON body containing 46 features + metadata.
# Returns: verdict, reconstruction error, and updates the SSE stream.
#
# Expected JSON:
# {
#   "features": [f0, f1, ..., f45],   // 46 raw engineered features (not normalised)
#   "srcIp": "192.168.1.1",
#   "dstIp": "8.8.8.8",
#   "service": "http",
#   "flag": "SF",
#   "classification": "normal"         // from Java's Weka CSC-RF
# }
# =============================================================================
#app.route -> routing table
# so now /detect -> detect()
#Basically im writing : detect= app.route("/detect")(detect)
@app.route("/detect", methods=["POST"])
def detect():
    global stats

    data = request.get_json() #"I'll parse that JSON text into a Python dictionary."

    if not data:
        return jsonify({"error":"No JSON body"}),400

    features=data.get("features") #instead of data["features"], .get -> won't crash if doesn't exist

    if not features or len(features) !=46:
        return jsonify({"error": "Expected 46 features, got 44"})

    raw =np.array(features, dtype=np.float64).reshape(1,-1) #tensorflow wants (num_samples, num_features) :2D

    scaled =np.clip(scaler.transform(raw),0.0,1.0)
    recon=autoencoder.predict(scaled,verbose=0)

    error=float(np.mean(np.power(scaled-recon,2)))

    verdict ="anomaly" if error > THRESHOLD else "normal"

    classification=data.get("classification","unknown")

    result={
        "timestamp" : time.strftime("%H:%M:%S"),
        "srcIp": data.get("srcIp", "?"),
        "dstIp": data.get("dstIp", "?"),
        "service":data.get("service", "?"),
        "flag": data.get("flag", "?"),
        "classification" : classification,
        "verdict" : verdict,
        "error" : round(error,6)
    }

    stats["total"] +=1
    if classification in stats:
        stats[classification] +=1
    else:
        stats["unknown"] +=1

    if verdict =="anomaly":
        stats["anomalies"] += 1

    try:
      event_queue.put_nowait(result) #waiting ->large amount -> server crash
    except queue.Full:
        pass # drop if browser not connected

    return jsonify({
        "verdict":verdict,
        "error":error
    })

# =============================================================================
# GET /stream
# Browser connects here and keeps the connection open.
# Flask pushes each detection as an SSE event — browser receives instantly.
# so it becomes a live server
# yield = simply Flask to send pieces of data one without ending the function
# SSE format: "data: {json}\n\n"
# =============================================================================

@app.route("/stream", methods=["GET"])
def stream():
    def event_generator():
        #sends stats before streaming
        yield f"data:{json.dumps({'type':'stats', 'stats':stats})}\n\n" #json.dumps -> string
                                                                        # -> yield 'data: {"type":"stats","stats":{"total":15,"normal":12,"anomaly":3}}\n\n'
                                                                        #data: {"type":"stats","stats":{"total":15,"normal":12,"anomaly":3}}
                                                                         # newline -> this event is complete

        while True:
            try:
             result=event_queue.get(timeout=1.0) #after 1.0 second throw queue.Empty if not store in result
             result["type"]="detection" #adds "type":"detection"

             yield f"data:{json.dumps(result)}\n\n" #browser receives data:{ "srcIp" : "192.168.1.4",...}

             # Also update stats after each detection
             yield f"data:{json.dumps({'type':'stats', 'stats':stats})}\n\n"

            #many browsers, proxies, or network devices might assume the connection has died
            # because no data has been sent for a long time, and they may close it.
            #heartbeat = "I'm still here. Nothing new has happened."
            except queue.Empty:
                yield f"data:{json.dumps({'type':'heartbeat'})}\n\n"

            #mimetype=text/event-stream : "Don't treat this as HTML or JSON. This is an SSE stream."
            #Without this header, the browser wouldn't know to process the response as a stream of server-sent events.
            #aka it will close the connection
            #but streaming only works because a generator object is given : event_generator()
    return Response(event_generator(),
                mimetype="text/event-stream",
                headers={
                         "Cache-Control": "no-cache", #dont save old response -> terrible for live dashboard
                                                      #Always ask for new data from server
                         "X-Accel-Buffering":"no", # disable nginx(web server) buffering if present
                                                    #Ensures every detection reaches the browser immediately
                                                    #instead of in batches.
                      })

"""
HTTP Response

Headers
--------
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no

Body
----
data: {"type":"stats"}

data: {"type":"heartbeat"}
"""

@app.route("/stats") #default methods=["GET"], so dont need to specify
def get_stats():
    return jsonify(stats) #jsonify() actually creates a Response object already so no return Response()
                            #A Response containing JSON (mimetype="application/json")
                            #returns a JSON string

# =============================================================================
# GET /
# Serves the dashboard HTML
# =============================================================================
@app.route("/")
def index():

    # find the html file named "dashboard.html" inside templates
    #render_template() reads the html file and sends it to the browser
    #{{}} -> display {% %} -> logic
    return render_template("dashboard.html",threshold=round(THRESHOLD,6))

# =============================================================================
# GET /health
# Simple liveness check — Java can ping this on startup to confirm Flask is up
# =============================================================================
@app.route("/health") # to check if flask is running and correct threshold loaded
def health():
    return jsonify({"status": "ok",
                    "threshold":THRESHOLD
                    })
if __name__ == "__main__":
    #0.0.0.0 -> listen on all network interfaces (other devices on the same network can connect)
    #127.0.0.1 -> only your own computer running java can connect
    #localhost -> same as 127.0.0.1

    #Common Flask development port -> 5000

    #threaded=True
    #Flask can handle multiple requests concurrently using separate threads.
    #One thread can keep the SSE stream alive while another handles incoming detection requests

    #Debug mode is useful during development
    #because Flask automatically reloads when
    #you change the code and shows detailed error pages if something
    #crashes.
    app.run(host="0.0.0.0", port=5000,threaded=True,debug=False)











