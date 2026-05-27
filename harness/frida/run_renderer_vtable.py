"""Spawn HP39gII.exe under Frida, load plot_renderer_vtable.js, stream all console.log
output to rvt_out.log, and keep the process alive. Run in background; the user drives
the GUI (define F1(X)=SIN(X), press Plot). Read rvt_out.log for the results."""
import frida, sys, time, os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
EXE = os.path.join(ROOT, "HP39gII.exe")
JS = os.path.join(HERE, "plot_renderer_vtable.js")
LOG = os.path.join(HERE, "rvt_out.log")

logf = open(LOG, "w", encoding="utf-8", buffering=1)


def emit(s):
    logf.write(s + "\n")
    print(s, flush=True)


def on_message(message, data):
    if message.get("type") == "error":
        emit("[JS ERROR] " + str(message.get("stack") or message))
    else:
        emit("[msg] " + str(message))


def on_log(level, text):
    emit(text)


dev = frida.get_local_device()
emit(f"[driver] spawning {EXE} (cwd={ROOT})")
pid = dev.spawn([EXE], cwd=ROOT)
session = dev.attach(pid)
script = session.create_script(open(JS, encoding="utf-8").read())
script.on("message", on_message)
script.set_log_handler(on_log)
script.load()
dev.resume(pid)
emit(f"[driver] resumed pid {pid}. Drive the GUI now; results stream to {LOG}")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    emit("[driver] exiting")
