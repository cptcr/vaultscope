#!/bin/bash

echo "===================================================="
echo "Building VaultScope - Enterprise API Security Tool"
echo "Author: CPTCR | https://cptcr.dev"
echo "GitHub: https://github.com/cptcr"
echo "License: Apache License 2.0"
echo "===================================================="
echo

if ! command -v mvn &> /dev/null; then
    echo "[ERROR] Maven is not installed or not in PATH"
    echo "Please install Maven 3.6+ and try again"
    exit 1
fi

if ! command -v java &> /dev/null; then
    echo "[ERROR] Java is not installed or not in PATH"
    echo "Please install Java 17+ and try again"
    exit 1
fi

JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f1)
if [ "$JAVA_VERSION" -lt 17 ]; then
    echo "[ERROR] Java 17 or newer is required. Current version: $JAVA_VERSION"
    exit 1
fi

echo "[INFO] Java version: $(java -version 2>&1 | head -n 1)"
echo "[INFO] Maven detected: $(mvn -version | head -n 1)"
echo

echo "[STEP 1/5] Cleaning previous builds..."
mvn clean
if [ $? -ne 0 ]; then
    echo "[ERROR] Clean failed"
    exit 1
fi

echo
echo "[STEP 2/5] Compiling and packaging application..."
mvn compile package -DskipTests
if [ $? -ne 0 ]; then
    echo "[ERROR] Build failed during compilation/packaging"
    exit 1
fi

echo
echo "[STEP 3/5] Creating module path and runtime image..."
mkdir -p target/modules
cp target/vaultscope-1.0.0.jar target/modules/

if command -v jlink &> /dev/null; then
    jlink --module-path "target/modules:$JAVA_HOME/jmods" \
          --add-modules vaultscope \
          --launcher vaultscope=vaultscope/dev.cptcr.vaultscope.VaultScopeApplication \
          --output target/java-runtime \
          --compress=2 \
          --no-header-files \
          --no-man-pages
    
    if [ $? -ne 0 ]; then
        echo "[WARNING] jlink failed, continuing with standard JAR"
    fi
else
    echo "[WARNING] jlink not available, skipping runtime image creation"
fi

echo
echo "[STEP 4/5] Creating installers..."
mkdir -p target/dist

if command -v jpackage &> /dev/null && [ -d "target/java-runtime" ]; then
    echo "Creating DEB package for Linux..."
    jpackage --input target/modules \
             --name VaultScope \
             --main-jar vaultscope-1.0.0.jar \
             --main-class dev.cptcr.vaultscope.VaultScopeApplication \
             --runtime-image target/java-runtime \
             --dest target/dist \
             --type deb \
             --vendor "CPTCR" \
             --app-version "1.0.0" \
             --description "Enterprise API Security Assessment Tool" \
             --linux-shortcut
    
    if [ $? -eq 0 ]; then
        echo "[SUCCESS] DEB package created"
    else
        echo "[WARNING] DEB package creation failed"
    fi
else
    echo "[WARNING] jpackage not available or runtime image missing, skipping installer creation"
fi

echo
echo "[STEP 5/5] Creating distribution directory..."
cp target/vaultscope-1.0.0.jar target/dist/

echo
echo "===================================================="
echo "BUILD COMPLETED SUCCESSFULLY!"
echo "===================================================="
echo
echo "Artifacts created:"
echo "- JAR: target/vaultscope-1.0.0.jar"
echo "- Shaded JAR: target/dist/vaultscope-1.0.0.jar"
if [ -f "target/dist/vaultscope_1.0.0-1_amd64.deb" ]; then
    echo "- Linux DEB: target/dist/vaultscope_1.0.0-1_amd64.deb"
fi
if [ -d "target/java-runtime" ]; then
    echo "- Runtime: target/java-runtime/"
fi
echo
echo "To run the application:"
echo "  java -jar target/vaultscope-1.0.0.jar"
echo
if [ -d "target/java-runtime" ]; then
    echo "Or use the runtime image:"
    echo "  target/java-runtime/bin/vaultscope"
    echo
fi
echo "Repository: https://github.com/cptcr/vaultscope"
echo "Documentation: https://cptcr.dev"
echo