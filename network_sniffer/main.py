from fastapi import FastAPI
from threading import Event, Thread
from utilility import utility as utl

app = FastAPI()


@app.post("/start_capturing/{ip}")
async def start_capturing(ip: str):
    with utl.CAPTURE_LOCK:
        if ip in utl.CAPTURE_THREADS:
            return {"status": "already_running", "ip": ip}
        stop_evt = Event()
        utl.CAPTURE_STOP[ip] = stop_evt
        with utl.STORE_LOCK:
            utl.STORE.setdefault(ip, [])
        t = Thread(target=utl.Capture.capture_loop_5s, args=(ip, stop_evt), daemon=True)
        utl.CAPTURE_THREADS[ip] = t
        t.start()
    return {"status": "started", "ip": ip, "message": "Capturing up to 5×5s windows. Use /stop_capturing/{ip} to stop early."}


@app.post("/stop_capturing/{ip}")
async def stop_capturing(ip: str):
    with utl.CAPTURE_LOCK:
        evt = utl.CAPTURE_STOP.get(ip)
        if not evt:
            raise HTTPException(status_code=404, detail="No active capture for this IP.")
        evt.set()
    return {"status": "stopping", "ip": ip}


@app.get("/packets/{ip}")
async def get_packets(ip: str):
    with utl.STORE_LOCK:
        data = utl.STORE.get(ip, [])
    # Is it still capturing?
    with utl.CAPTURE_LOCK:
        running = ip in utl.CAPTURE_THREADS
    return {"ip": ip, "windows": len(data), "capturing": running, "data": data}
