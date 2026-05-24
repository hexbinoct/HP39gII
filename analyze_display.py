import sys, re
sys.stdout.reconfigure(errors='replace')

with open('F:/ru/myprojects/april/calc/HP39gII.exe', 'rb') as f:
    data = f.read()

print("=== Skin file analysis ===")
with open('F:/ru/myprojects/april/calc/Large 39gII.skin', 'r') as f:
    skin = f.read()
print(skin)

print()
print("=== Display/Graphics related strings in the EXE ===")
display_kw = ['framebuffer','framebuf','screen buffer','lcd','pixel','blit','bitblt','stretchblt',
              'CreateDIB','DIBSection','SetPixel','GetPixel','CreateBitmap','CreateCompatible',
              'display_buf','screen_buf','grob','GROB','vram','backbuffer','rendertarget',
              'paintscreen','drawscreen','updatescreen','refreshscreen','invalidaterect',
              'WM_PAINT','OnPaint','repaint','redraw']
seen = set()
for match in re.finditer(b'[\x20-\x7e]{5,}', data):
    s = match.group().decode('ascii')
    sl = s.lower()
    for kw in display_kw:
        if kw.lower() in sl and s not in seen:
            seen.add(s)
            print('  %x: %s' % (match.start(), s[:150]))

print()
print("=== C++ class names (RTTI) related to display/screen/graphics ===")
rtti_pattern = re.compile(b'\\.\\?AV[A-Za-z0-9_]+@@')
classes = []
for match in rtti_pattern.finditer(data):
    name = match.group().decode('ascii')
    classes.append((match.start(), name))

# Show all RTTI classes - they reveal the app architecture
print("All RTTI classes found:")
for offset, name in sorted(classes, key=lambda x: x[1]):
    # Clean up: .?AVClassName@Namespace@@ -> Namespace::ClassName
    clean = name[4:-2]  # remove .?AV and @@
    print('  %x: %s' % (offset, clean))

print()
print("=== Hardware abstraction / platform layer strings ===")
hal_kw = ['hal_','platform','abstraction','driver','device','render','surface','context',
          'opengl','directdraw','direct3d','d3d','sdl','allegro','sfml',
          'CreateWindow','RegisterClass','WndProc','DefWindowProc','DispatchMessage',
          'PeekMessage','GetMessage','TranslateMessage','timer','SetTimer','KillTimer',
          'keyboard','keydown','keyup','WM_KEY','WM_CHAR','WM_MOUSE','WM_LBUTTON']
seen2 = set()
for match in re.finditer(b'[\x20-\x7e]{5,}', data):
    s = match.group().decode('ascii')
    sl = s.lower()
    for kw in hal_kw:
        if kw.lower() in sl and s not in seen2 and len(s) < 100:
            seen2.add(s)
            print('  %x: %s' % (match.start(), s[:150]))

print()
print("=== GROB (Graphics Object) related - HP's display primitive ===")
for match in re.finditer(b'[\x20-\x7e]{4,}', data):
    s = match.group().decode('ascii')
    if 'grob' in s.lower() or 'GROB' in s:
        if len(s) < 120:
            print('  %x: %s' % (match.start(), s[:150]))
