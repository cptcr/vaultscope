#!/bin/bash

# VaultScope AppImage Creation Script
# This script creates an AppImage for universal Linux distribution

set -e

BUILD_DIR="$1"
VERSION="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

echo "🚀 Creating VaultScope AppImage v$VERSION"
echo "=========================================="

# Validate inputs
if [[ -z "$BUILD_DIR" || -z "$VERSION" ]]; then
    echo "❌ Usage: $0 <build_dir> <version>"
    exit 1
fi

# Create AppDir structure
APPDIR="$BUILD_DIR/VaultScope.AppDir"
echo "📁 Creating AppDir structure: $APPDIR"
rm -rf "$APPDIR"
mkdir -p "$APPDIR"/{usr/bin,usr/lib,usr/share/{applications,icons/hicolor/256x256/apps}}

# Copy JAR and dependencies
echo "📦 Copying application files..."
cp "$BUILD_DIR/vaultscope-$VERSION.jar" "$APPDIR/usr/lib/"
cp -r "$BUILD_DIR/lib"/* "$APPDIR/usr/lib/" 2>/dev/null || echo "No lib directory found"

# Create launcher script
echo "📝 Creating launcher script..."
cat > "$APPDIR/usr/bin/vaultscope" << 'EOF'
#!/bin/bash
# VaultScope AppImage launcher script

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Set up Java classpath
CLASSPATH="$APP_DIR/usr/lib/vaultscope-VERSION.jar"
for jar in "$APP_DIR/usr/lib"/*.jar; do
    if [[ "$jar" != *"vaultscope-"* ]]; then
        CLASSPATH="$CLASSPATH:$jar"
    fi
done

# Java options for better performance and security
JAVA_OPTS=(
    "-Dfile.encoding=UTF-8"
    "-Djava.awt.headless=false"
    "-Xms256m"
    "-Xmx2g"
    "--add-opens=java.base/java.lang=ALL-UNNAMED"
    "--add-opens=java.base/java.util=ALL-UNNAMED"
    "--add-opens=java.desktop/java.awt=ALL-UNNAMED"
    "--add-opens=javafx.graphics/javafx.scene=ALL-UNNAMED"
    "--add-opens=javafx.controls/javafx.scene.control=ALL-UNNAMED"
)

# Launch VaultScope
exec java "${JAVA_OPTS[@]}" -cp "$CLASSPATH" dev.cptcr.vaultscope.VaultScopeApplication "$@"
EOF

# Replace VERSION placeholder
sed -i "s/VERSION/$VERSION/g" "$APPDIR/usr/bin/vaultscope"
chmod +x "$APPDIR/usr/bin/vaultscope"

# Create desktop file
echo "🖥️  Creating desktop file..."
cat > "$APPDIR/usr/share/applications/vaultscope.desktop" << EOF
[Desktop Entry]
Type=Application
Name=VaultScope
GenericName=API Security Assessment Tool
Comment=Enterprise API Security Assessment Tool
Exec=vaultscope
Icon=vaultscope
Terminal=false
Categories=Development;Security;Network;
Keywords=security;api;testing;vulnerability;assessment;
StartupNotify=true
StartupWMClass=VaultScope
MimeType=application/x-vaultscope-project;
EOF

# Create AppRun script
echo "🔧 Creating AppRun script..."
cat > "$APPDIR/AppRun" << 'EOF'
#!/bin/bash
# VaultScope AppRun script for AppImage

# Get the directory where this AppImage is mounted
APPDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Export environment variables
export PATH="$APPDIR/usr/bin:$PATH"
export LD_LIBRARY_PATH="$APPDIR/usr/lib:$LD_LIBRARY_PATH"

# Set up application-specific environment
export VAULTSCOPE_HOME="$APPDIR"
export VAULTSCOPE_VERSION="VERSION"

# Launch VaultScope
exec "$APPDIR/usr/bin/vaultscope" "$@"
EOF

# Replace VERSION placeholder
sed -i "s/VERSION/$VERSION/g" "$APPDIR/AppRun"
chmod +x "$APPDIR/AppRun"

# Create application icon (placeholder)
echo "🎨 Creating application icon..."
cat > "$APPDIR/usr/share/icons/hicolor/256x256/apps/vaultscope.png" << 'EOF'
# This is a placeholder for the application icon
# In a real implementation, you would copy the actual PNG icon file here
EOF

# Copy icon to AppDir root
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/vaultscope.png" "$APPDIR/vaultscope.png"

# Copy desktop file to AppDir root
cp "$APPDIR/usr/share/applications/vaultscope.desktop" "$APPDIR/vaultscope.desktop"

# Create PKGBUILD for Arch Linux
echo "📋 Creating PKGBUILD for Arch Linux..."
cat > "$BUILD_DIR/PKGBUILD" << EOF
# Maintainer: CPTCR <support@cptcr.dev>
pkgname=vaultscope
pkgver=$VERSION
pkgrel=1
pkgdesc="Enterprise API Security Assessment Tool"
arch=('x86_64')
url="https://github.com/cptcr/vaultscope"
license=('Apache')
depends=('java-runtime>=17')
makedepends=('maven' 'java-environment>=17')
source=("vaultscope-\$pkgver.jar")
noextract=("vaultscope-\$pkgver.jar")
sha256sums=('SKIP')

package() {
    # Install JAR
    install -Dm644 "vaultscope-\$pkgver.jar" "\$pkgdir/usr/share/java/vaultscope/vaultscope.jar"
    
    # Install launcher script
    install -Dm755 /dev/stdin "\$pkgdir/usr/bin/vaultscope" << 'LAUNCHER'
#!/bin/bash
exec java -Dfile.encoding=UTF-8 \\
    -Djava.awt.headless=false \\
    -Xms256m -Xmx2g \\
    --add-opens=java.base/java.lang=ALL-UNNAMED \\
    --add-opens=java.base/java.util=ALL-UNNAMED \\
    --add-opens=java.desktop/java.awt=ALL-UNNAMED \\
    --add-opens=javafx.graphics/javafx.scene=ALL-UNNAMED \\
    --add-opens=javafx.controls/javafx.scene.control=ALL-UNNAMED \\
    -jar /usr/share/java/vaultscope/vaultscope.jar "\$@"
LAUNCHER
    
    # Install desktop file
    install -Dm644 /dev/stdin "\$pkgdir/usr/share/applications/vaultscope.desktop" << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=VaultScope
GenericName=API Security Assessment Tool
Comment=Enterprise API Security Assessment Tool
Exec=vaultscope
Icon=vaultscope
Terminal=false
Categories=Development;Security;Network;
Keywords=security;api;testing;vulnerability;assessment;
StartupNotify=true
StartupWMClass=VaultScope
DESKTOP
}
EOF

# Create AppImage if appimagetool is available
if command -v appimagetool &> /dev/null; then
    echo "📦 Creating AppImage..."
    
    # Set version in AppImage
    echo "VERSION=$VERSION" > "$APPDIR/.version"
    
    # Create AppImage
    appimagetool "$APPDIR" "$BUILD_DIR/dist/VaultScope-$VERSION-x86_64.AppImage"
    
    if [[ -f "$BUILD_DIR/dist/VaultScope-$VERSION-x86_64.AppImage" ]]; then
        echo "✅ AppImage created successfully: VaultScope-$VERSION-x86_64.AppImage"
        
        # Make it executable
        chmod +x "$BUILD_DIR/dist/VaultScope-$VERSION-x86_64.AppImage"
        
        # Create symlink without version for easier distribution
        ln -sf "VaultScope-$VERSION-x86_64.AppImage" "$BUILD_DIR/dist/VaultScope-latest-x86_64.AppImage"
        
        echo "📊 AppImage size: $(du -h "$BUILD_DIR/dist/VaultScope-$VERSION-x86_64.AppImage" | cut -f1)"
    else
        echo "❌ AppImage creation failed"
        exit 1
    fi
else
    echo "⚠️  appimagetool not found, skipping AppImage creation"
    echo "📁 AppDir created at: $APPDIR"
fi

echo ""
echo "🎉 Arch Linux packaging completed!"
echo "=================================="
echo "📁 PKGBUILD: $BUILD_DIR/PKGBUILD"
echo "📁 AppDir: $APPDIR"
if [[ -f "$BUILD_DIR/dist/VaultScope-$VERSION-x86_64.AppImage" ]]; then
    echo "📁 AppImage: $BUILD_DIR/dist/VaultScope-$VERSION-x86_64.AppImage"
fi
echo ""
echo "🚀 Installation instructions:"
echo "   Arch Linux: makepkg -si (from directory containing PKGBUILD)"
echo "   AppImage: chmod +x VaultScope-$VERSION-x86_64.AppImage && ./VaultScope-$VERSION-x86_64.AppImage"