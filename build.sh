#!/bin/bash

echo "Building VaultScope - Enterprise API Security Assessment Tool"
echo "Author: CPTCR | https://cptcr.dev | https://github.com/cptcr"
echo "License: Apache License 2.0"
echo ""

if ! command -v mvn &> /dev/null; then
    echo "Maven is not installed. Please install Maven first."
    exit 1
fi

if ! command -v java &> /dev/null; then
    echo "Java is not installed. Please install Java 17 or newer."
    exit 1
fi

JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f1)
if [ "$JAVA_VERSION" -lt 17 ]; then
    echo "Java 17 or newer is required. Current version: $JAVA_VERSION"
    exit 1
fi

echo "Step 1: Cleaning previous builds..."
mvn clean

echo "Step 2: Compiling and packaging application..."
mvn compile package

if [ $? -ne 0 ]; then
    echo "Build failed during compilation/packaging phase"
    exit 1
fi

echo "Step 3: Creating runtime image..."
jlink --module-path "target/dependency;target/classes" \
      --add-modules vaultscope \
      --launcher vaultscope=vaultscope/dev.cptcr.vaultscope.VaultScopeApplication \
      --output target/java-runtime \
      --compress=2 \
      --no-header-files \
      --no-man-pages

if [ $? -ne 0 ]; then
    echo "Runtime image creation failed"
    exit 1
fi

echo "Step 4: Creating installers..."
mvn jpackage:jpackage@win
mvn jpackage:jpackage@win-msi
mvn jpackage:jpackage@linux

echo ""
echo "Build completed successfully!"
echo "Executables created in target/dist/"
echo ""
echo "To run the application directly:"
echo "  java --module-path target/classes --module vaultscope/dev.cptcr.vaultscope.VaultScopeApplication"
echo ""
echo "Or use the runtime image:"
echo "  target/java-runtime/bin/vaultscope"