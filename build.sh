#!/bin/bash

# P0rt Build Script for Cross-Platform Releases
# This script builds P0rt binaries for multiple platforms

set -e

VERSION=$(cat VERSION 2>/dev/null || echo "1.0.0")
BUILD_DIR="build"
BINARY_NAME="p0rt"

echo "🚀 Building P0rt v${VERSION} for multiple platforms..."

# Clean build directory
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

# Build information
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Common ldflags
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}"

# Platform targets (OS/ARCH)
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "linux/386"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/386"
    "freebsd/amd64"
)

echo "📦 Building binaries..."

for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS=${PLATFORM%/*}
    GOARCH=${PLATFORM#*/}
    
    OUTPUT_NAME="${BINARY_NAME}-v${VERSION}-${GOOS}-${GOARCH}"
    if [ $GOOS = "windows" ]; then
        OUTPUT_NAME+='.exe'
    fi
    
    echo "   Building ${GOOS}/${GOARCH}..."
    
    env GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build \
        -ldflags="${LDFLAGS}" \
        -o ${BUILD_DIR}/${OUTPUT_NAME} \
        cmd/main/main.go
    
    # Create compressed archive
    if [ $GOOS = "windows" ]; then
        (cd ${BUILD_DIR} && zip -q ${OUTPUT_NAME%.exe}.zip ${OUTPUT_NAME})
        rm ${BUILD_DIR}/${OUTPUT_NAME}
    else
        (cd ${BUILD_DIR} && tar -czf ${OUTPUT_NAME}.tar.gz ${OUTPUT_NAME})
        rm ${BUILD_DIR}/${OUTPUT_NAME}
    fi
done

echo "✅ Build complete! Binaries are in the ${BUILD_DIR}/ directory:"
ls -la ${BUILD_DIR}/

echo ""
echo "📋 Build Summary:"
echo "   Version: ${VERSION}"
echo "   Build Time: ${BUILD_TIME}"
echo "   Git Commit: ${GIT_COMMIT}"
echo "   Platforms: ${#PLATFORMS[@]}"
echo ""
echo "🎉 Ready for release! Upload these files to GitHub Releases."