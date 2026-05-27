"""Attach to the already-running HP39gII.exe and load plot_transform_confirm.js, which
dumps the plot screen-transform coefficients on the next plot/repaint. Streams to
xform_out.log. Run in background; user re-plots; read xform_out.log."""
import frida, sys, time, os

HERE = os.path.dirname(os.path.abspath(__file__))
JS = os.path.join(HERE, "plot_transform_confirm.js")
LOG = os.path.join(HERE, "xform_out.log")
logf = open(LOG, "w", encoding="utf-8", buffering=1)


def emit(s):
    logf.write(s + "\n"); print(s, flush=True)


def on_message(m, d):
    emit("[JS ERROR] " + str(m.get("stack") or m) if m.get("type") == "error" else "[msg] " + str(m))


dev = frida.get_local_device()
emit("[driver] attaching to HP39gII.exe ...")
session = dev.attach("HP39gII.exe")        # attach to the running instance (pid 4856)
script = session.create_script(open(JS, encoding="utf-8").read())
script.on("message", on_message)
script.set_log_handler(lambda lvl, txt: emit(txt))
script.load()
emit(f"[driver] hook loaded. Re-plot now; results stream to {LOG}")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    emit("[driver] exiting")
